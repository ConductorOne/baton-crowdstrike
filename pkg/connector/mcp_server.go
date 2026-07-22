package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	fClient "github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"golang.org/x/oauth2/clientcredentials"
)

// mcpRunnerEntitlement is the assignment entitlement on an mcp_server resource held
// by the endpoint user that ran the server.
const mcpRunnerEntitlement = "runner"

// launcherUnknown marks a detection whose command line doesn't name a known launcher.
const launcherUnknown = "unknown"

// mcpServerAlertLimit is how many recent alerts we pull to scan for shadow-MCP activity.
const mcpServerAlertLimit = 1000

// mcpSignature matches the command line of a Model Context Protocol server. MCP
// servers are ordinary npx/uvx/node/python processes whose command line carries a
// recognizable package: @modelcontextprotocol/server-*, mcp-server-*, mcp_server_*.
var mcpSignature = regexp.MustCompile(`(?i)(@modelcontextprotocol/server-[\w.-]+|mcp-server-[\w.-]+|mcp_server_[\w.-]+)`)

// mcpServerResourceType syncs unsanctioned ("shadow") MCP servers observed on
// endpoints via CrowdStrike EDR detections, correlates each to the identity that
// ran it, and emits a queryable resource plus an identity-risk insight.
type mcpServerResourceType struct {
	resourceType *v2.ResourceType
	client       *fClient.CrowdStrikeAPISpecification
	src          *mcpSource
}

func (m *mcpServerResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return m.resourceType
}

// mcpDetection is a single shadow-MCP process-creation detection from the Alerts API.
type mcpDetection struct {
	Hostname    string
	AID         string
	LocalIP     string
	UserName    string
	CommandLine string
	FilePath    string
	Timestamp   time.Time
	CompositeID string
	FalconLink  string
	IOARuleName string
}

// mcpServerInstance is a deduplicated (host, user, server) shadow-MCP server. The
// same logical server surfaces under several command-line spellings across the
// process tree; we collapse them and keep the most informative representation.
type mcpServerInstance struct {
	det         mcpDetection
	serverName  string
	pkg         string
	launcher    string
	transport   string
	bestCmdline string // shortest signature-bearing command line (cleanest sample)
	count       int
}

// resolvedIdentity carries the identity a detection's OS user maps to.
type resolvedIdentity struct {
	email       string
	externalID  string
	displayName string
}

// List scans recent EDR detections for shadow-MCP activity, correlates each to an
// identity, and returns one mcp_server resource per unique server instance.
func (m *mcpServerResourceType) List(ctx context.Context, _ *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	dets, err := m.src.detections(ctx, opts.SyncID)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-crowdstrike: mcp_server list: failed to fetch detections: %w", err)
	}
	if len(dets) == 0 {
		return nil, &rs.SyncOpResults{}, nil
	}

	// Build an identity lookup keyed by lowercased samAccountName and email local-part.
	idIndex, err := m.src.identityIndex(ctx, opts.SyncID)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-crowdstrike: mcp_server list: failed to build identity index: %w", err)
	}

	instances := buildInstances(dets)

	resources := make([]*v2.Resource, 0, len(instances))
	for _, inst := range instances {
		id := resolveIdentity(idIndex, inst.det.UserName)
		res, err := mcpServerResource(inst, id)
		if err != nil {
			return nil, nil, fmt.Errorf("baton-crowdstrike: failed to build mcp_server resource: %w", err)
		}
		resources = append(resources, res)
	}

	return resources, &rs.SyncOpResults{}, nil
}

// Entitlements exposes a single "runner" assignment on each mcp_server resource,
// grantable to the endpoint user that ran the server.
func (m *mcpServerResourceType) Entitlements(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	opts := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeEndpointUser),
		ent.WithDisplayName(fmt.Sprintf("%s runner", resource.DisplayName)),
		ent.WithDescription("Endpoint user that ran this shadow MCP server"),
	}
	return []*v2.Entitlement{ent.NewAssignmentEntitlement(resource, mcpRunnerEntitlement, opts...)}, nil, nil
}

// Grants gives the endpoint-user account the "runner" entitlement on the mcp_server
// resource it ran. The account is synced separately (see endpoint_user) and is
// auto-matched to a c1 identity by email or assigned manually; this grant is what
// surfaces it as the resource's principal.
func (m *mcpServerResourceType) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	dets, err := m.src.detections(ctx, opts.SyncID)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-crowdstrike: mcp_server grants: failed to fetch detections: %w", err)
	}
	for _, inst := range buildInstances(dets) {
		if inst.objectID() != resource.Id.Resource {
			continue
		}
		principal := &v2.ResourceId{ResourceType: resourceTypeEndpointUser.Id, Resource: inst.accountID()}
		return []*v2.Grant{grant.NewGrant(resource, mcpRunnerEntitlement, principal)}, nil, nil
	}
	return nil, nil, nil
}

// mcpServerResource builds an mcp_server resource: an App-trait profile carrying the
// full server + endpoint + identity metadata, plus a security-insight annotation
// that binds a shadow-MCP finding to the resolved identity (when one is found).
func mcpServerResource(inst *mcpServerInstance, id *resolvedIdentity) (*v2.Resource, error) {
	d := inst.det

	displayName := fmt.Sprintf("Shadow MCP: %s @ %s", inst.serverName, d.Hostname)
	if d.UserName != "" {
		displayName = fmt.Sprintf("%s (%s)", displayName, d.UserName)
	}

	profile := map[string]interface{}{
		"server_name":         inst.serverName,
		"package":             inst.pkg,
		"launcher":            inst.launcher,
		"transport":           inst.transport,
		"sanctioned":          false,
		"endpoint_user":       d.UserName,
		"host":                d.Hostname,
		"aid":                 d.AID,
		"local_ip":            d.LocalIP,
		"sample_command_line": inst.bestCmdline,
		"detection_count":     inst.count,
		"ioa_rule":            d.IOARuleName,
		"falcon_link":         d.FalconLink,
	}
	if !d.Timestamp.IsZero() {
		profile["first_seen"] = d.Timestamp.UTC().Format(time.RFC3339)
	}
	if id != nil {
		profile["identity_email"] = id.email
		profile["identity_external_id"] = id.externalID
		profile["identity_display_name"] = id.displayName
	}

	opts := []rs.ResourceOption{
		rs.WithAppTrait(rs.WithAppProfile(profile)),
	}

	// Bind the finding to the identity as a security insight (issue) so it flows into
	// c1 identity risk. Requires a resolved identity with an external ID.
	if id != nil && id.externalID != "" {
		issueVal := fmt.Sprintf("Shadow MCP server '%s' (%s via %s/%s) running on %s as %s",
			inst.serverName, inst.pkg, inst.launcher, inst.transport, d.Hostname, d.UserName)
		insightOpts := []rs.SecurityInsightTraitOption{
			rs.WithIssue(issueVal),
			rs.WithIssueSeverity("High"),
			rs.WithInsightAppUserTarget(id.email, id.externalID),
		}
		if !d.Timestamp.IsZero() {
			insightOpts = append(insightOpts, rs.WithInsightObservedAt(d.Timestamp))
		}
		insight, err := rs.NewSecurityInsightTrait(insightOpts...)
		if err != nil {
			return nil, fmt.Errorf("failed to build security insight trait: %w", err)
		}
		opts = append(opts, rs.WithAnnotation(insight))
	}

	return rs.NewResource(displayName, resourceTypeMCPServer, inst.objectID(), opts...)
}

// buildInstances deduplicates detections into unique server instances, keyed by the
// logical server (host, user, server name) so the different command-line spellings of
// the same server (e.g. "node ... @modelcontextprotocol/server-everything" and
// "sh -c mcp-server-everything") collapse into one resource.
func buildInstances(dets []mcpDetection) map[string]*mcpServerInstance {
	instances := map[string]*mcpServerInstance{}
	for _, d := range dets {
		if d.AID == "" || d.UserName == "" {
			continue // unattributable — avoid collapsing distinct hosts/users into one id
		}
		name, pkg, launcher, transport, ok := parseMCPServer(d.CommandLine)
		if !ok {
			continue
		}
		key := strings.Join([]string{d.AID, strings.ToLower(d.UserName), name}, "|")
		inst, seen := instances[key]
		if !seen {
			instances[key] = &mcpServerInstance{
				det: d, serverName: name, pkg: pkg, launcher: launcher, transport: transport,
				bestCmdline: d.CommandLine, count: 1,
			}
			continue
		}
		inst.count++
		if !d.Timestamp.IsZero() && (inst.det.Timestamp.IsZero() || d.Timestamp.Before(inst.det.Timestamp)) {
			inst.det.Timestamp = d.Timestamp
		}
		if inst.launcher == launcherUnknown && launcher != launcherUnknown {
			inst.launcher = launcher
			inst.transport = transport
		}
		if strings.HasPrefix(pkg, "@modelcontextprotocol/") {
			inst.pkg = pkg
		}
		if len(d.CommandLine) < len(inst.bestCmdline) {
			inst.bestCmdline = d.CommandLine
		}
	}
	return instances
}

// objectID is the stable mcp_server resource ID. It hashes aid|user|serverName — the
// same fields buildInstances dedups on — so the ID is stable across syncs regardless of
// which command-line spelling (mcp-server-x vs @modelcontextprotocol/server-x) happens
// to appear in a given alert window, and always agrees with the dedup key.
func (inst *mcpServerInstance) objectID() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{inst.det.AID, strings.ToLower(inst.det.UserName), inst.serverName}, "|")))
	return "mcp-" + hex.EncodeToString(sum[:])[:24]
}

// accountID is the stable endpoint_user account ID (sha256 of aid|user), shared by
// every server the same user ran on the same host.
func (inst *mcpServerInstance) accountID() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{inst.det.AID, strings.ToLower(inst.det.UserName)}, "|")))
	return "eu-" + hex.EncodeToString(sum[:])[:24]
}

// endpointUserResourceType syncs the endpoint OS users that ran shadow MCP servers as
// app accounts, so they can be assigned to a ConductorOne identity and shown against
// the mcp_server resources they ran.
type endpointUserResourceType struct {
	resourceType *v2.ResourceType
	src          *mcpSource
}

func (e *endpointUserResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return e.resourceType
}

func (e *endpointUserResourceType) List(ctx context.Context, _ *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	dets, err := e.src.detections(ctx, opts.SyncID)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-crowdstrike: endpoint_user list: failed to fetch detections: %w", err)
	}
	if len(dets) == 0 {
		return nil, &rs.SyncOpResults{}, nil
	}
	idIndex, err := e.src.identityIndex(ctx, opts.SyncID)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-crowdstrike: endpoint_user list: failed to build identity index: %w", err)
	}

	seen := map[string]bool{}
	var rv []*v2.Resource
	for _, inst := range buildInstances(dets) {
		acctID := inst.accountID()
		if seen[acctID] {
			continue
		}
		seen[acctID] = true
		res, err := endpointUserResource(inst, resolveIdentity(idIndex, inst.det.UserName))
		if err != nil {
			return nil, nil, fmt.Errorf("baton-crowdstrike: failed to build endpoint_user resource: %w", err)
		}
		rv = append(rv, res)
	}
	return rv, &rs.SyncOpResults{}, nil
}

func (e *endpointUserResourceType) Entitlements(context.Context, *v2.Resource, rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

func (e *endpointUserResourceType) Grants(context.Context, *v2.Resource, rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// endpointUserResource builds a user-trait account for an endpoint OS user. When the
// user resolves to an Identity Protection entity, its email is attached so c1 can
// auto-match; otherwise the account stays unmatched for manual assignment.
func endpointUserResource(inst *mcpServerInstance, id *resolvedIdentity) (*v2.Resource, error) {
	d := inst.det
	profile := map[string]interface{}{
		"endpoint_user": d.UserName,
		"host":          d.Hostname,
		"aid":           d.AID,
		"local_ip":      d.LocalIP,
	}
	displayName := fmt.Sprintf("%s@%s", d.UserName, d.Hostname)
	traitOpts := []rs.UserTraitOption{rs.WithStatus(v2.UserTrait_Status_STATUS_ENABLED)}
	if id != nil {
		if id.displayName != "" {
			displayName = fmt.Sprintf("%s (%s@%s)", id.displayName, d.UserName, d.Hostname)
		}
		profile["resolved_identity"] = id.displayName
		profile["identity_external_id"] = id.externalID
		if id.email != "" {
			traitOpts = append(traitOpts, rs.WithEmail(id.email, true))
		}
	}
	traitOpts = append(traitOpts, rs.WithUserProfile(profile))
	return rs.NewUserResource(displayName, resourceTypeEndpointUser, inst.accountID(), traitOpts)
}

// buildIdentityIndex fetches all Identity Protection entities and indexes them by
// lowercased samAccountName and email local-part for endpoint-user resolution.
//
// Endpoint usernames are ambiguous: two distinct identities can share a samAccountName
// or email local-part. Rather than silently letting the last one win (which would pin a
// shadow-MCP finding on the wrong person), a key that maps to more than one identity is
// marked ambiguous (nil) and resolves to no match.
func buildIdentityIndex(ctx context.Context, ip *IdentityProtectionClient) (map[string]*resolvedIdentity, error) {
	index := map[string]*resolvedIdentity{}
	// insert records key->ri, but collapses to nil (ambiguous) if the key already
	// resolves to a different identity.
	insert := func(key string, ri *resolvedIdentity) {
		key = strings.ToLower(key)
		if key == "" {
			return
		}
		existing, seen := index[key]
		if !seen {
			index[key] = ri
			return
		}
		if existing == nil {
			return // already ambiguous
		}
		if existing.externalID != ri.externalID {
			index[key] = nil // collision between distinct identities
		}
	}
	cursor := ""
	for {
		identities, next, hasNext, _, err := ip.GetIdentityRiskScores(ctx, securityInsightPageSize, cursor)
		if err != nil {
			return nil, err
		}
		for i := range identities {
			id := identities[i]
			email := ""
			if len(id.EmailAddresses) > 0 {
				email = id.EmailAddresses[0]
			} else if validateEmail(id.SecondaryDisplayName) {
				email = id.SecondaryDisplayName
			}
			for _, acct := range id.Accounts {
				if acct.SamAccountName != "" {
					insert(acct.SamAccountName, &resolvedIdentity{email: email, externalID: acct.ExternalID(), displayName: id.PrimaryDisplayName})
				}
			}
			if email != "" {
				if local := strings.SplitN(email, "@", 2)[0]; local != "" {
					insert(local, &resolvedIdentity{email: email, externalID: firstExternalID(id), displayName: id.PrimaryDisplayName})
				}
			}
		}
		if !hasNext || next == "" {
			break
		}
		cursor = next
	}
	return index, nil
}

func firstExternalID(id IdentityRiskData) string {
	for _, acct := range id.Accounts {
		if ext := acct.ExternalID(); ext != "" {
			return ext
		}
	}
	return ""
}

// resolveIdentity maps an endpoint OS username to an identity via samAccountName or email local-part.
func resolveIdentity(index map[string]*resolvedIdentity, userName string) *resolvedIdentity {
	if userName == "" {
		return nil
	}
	if ri, ok := index[strings.ToLower(userName)]; ok {
		return ri
	}
	return nil
}

// parseMCPServer extracts the MCP server identity from a process command line,
// returning (name, package, launcher, transport, matched).
func parseMCPServer(cmdline string) (string, string, string, string, bool) {
	match := mcpSignature.FindString(cmdline)
	if match == "" {
		return "", "", "", "", false
	}
	// A bare .js entrypoint (e.g. mcp-server-fetch.js) and its package name are the same
	// logical server; drop the extension so they don't split into two resources.
	pkg := strings.TrimSuffix(match, ".js")

	// Derive a short logical name from the package suffix.
	var name string
	switch {
	case strings.HasPrefix(pkg, "@modelcontextprotocol/server-"):
		name = strings.TrimPrefix(pkg, "@modelcontextprotocol/server-")
	case strings.HasPrefix(pkg, "mcp-server-"):
		name = strings.TrimPrefix(pkg, "mcp-server-")
	case strings.HasPrefix(pkg, "mcp_server_"):
		name = strings.TrimPrefix(pkg, "mcp_server_")
	default:
		name = pkg
	}

	lc := strings.ToLower(cmdline)
	launcher := launcherUnknown
	switch {
	case strings.Contains(lc, "npx"):
		launcher = "npx"
	case strings.Contains(lc, "uvx"):
		launcher = "uvx"
	case strings.Contains(lc, "python"):
		launcher = "python"
	case strings.Contains(lc, "node"):
		launcher = "node"
	}

	transport := "stdio"
	if strings.Contains(lc, "--sse") || strings.Contains(lc, "transport sse") || strings.Contains(lc, "--port") {
		transport = "sse/http"
	}
	return name, pkg, launcher, transport, true
}

// ---- Alerts API client (shadow-MCP detections) ----

// mcpAlertMaxPages bounds how many pages of epp alerts we scan on very large tenants.
// Each page holds up to mcpServerAlertLimit alerts. Capped at 10 so the largest offset
// stays below CrowdStrike's ~10,000-record deep-pagination limit on the alerts query
// endpoint (a request at offset >= 10000 is rejected).
const mcpAlertMaxPages = 10

type mcpDetectionsClient struct {
	httpClient *http.Client
	host       string
}

func newMCPDetectionsClient(ctx context.Context, clientID, clientSecret, host string) *mcpDetectionsClient {
	config := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     "https://" + host + "/oauth2/token",
	}
	httpClient := config.Client(ctx)
	httpClient.Timeout = 30 * time.Second
	return &mcpDetectionsClient{httpClient: httpClient, host: host}
}

type alertsQueryResp struct {
	Resources []string `json:"resources"`
}

type alertsEntitiesResp struct {
	Resources []struct {
		Product     string `json:"product"`
		UserName    string `json:"user_name"`
		Cmdline     string `json:"cmdline"`
		Filepath    string `json:"filepath"`
		Timestamp   string `json:"timestamp"`
		CompositeID string `json:"composite_id"`
		FalconHost  string `json:"falcon_host_link"`
		PatternName string `json:"name"`
		Device      struct {
			Hostname string `json:"hostname"`
			DeviceID string `json:"device_id"`
			LocalIP  string `json:"local_ip"`
		} `json:"device"`
	} `json:"resources"`
}

// mcpMaxRetries is how many times doJSON retries a rate-limited (429) or transient
// server (5xx) response before giving up.
const mcpMaxRetries = 4

func (c *mcpDetectionsClient) doJSON(ctx context.Context, method, reqURL, body string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= mcpMaxRetries; attempt++ {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, reqURL, rdr)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "baton-crowdstrike")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			// Transient transport error — retry with backoff.
			lastErr = err
			if attempt < mcpMaxRetries && waitBackoff(ctx, attempt, 0) {
				continue
			}
			return nil, err
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return b, nil
		}
		// Retry on rate limiting and transient server errors, honoring Retry-After.
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			lastErr = fmt.Errorf("%s alerts returned %d: %s", method, resp.StatusCode, string(b))
			if attempt < mcpMaxRetries && waitBackoff(ctx, attempt, retryAfterSeconds(resp.Header)) {
				continue
			}
			return nil, lastErr
		}
		return nil, fmt.Errorf("%s alerts returned %d: %s", method, resp.StatusCode, string(b))
	}
	return nil, lastErr
}

// retryAfterSeconds reads a Retry-After header expressed in seconds; 0 if absent/invalid.
func retryAfterSeconds(h http.Header) int {
	if v := h.Get("Retry-After"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
			return n
		}
	}
	return 0
}

// waitBackoff sleeps before a retry — the larger of Retry-After and an exponential
// backoff (1s, 2s, 4s, ... capped at 30s). Returns false if the context is cancelled.
func waitBackoff(ctx context.Context, attempt, retryAfter int) bool {
	backoff := time.Duration(1<<attempt) * time.Second
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	if ra := time.Duration(retryAfter) * time.Second; ra > backoff {
		backoff = ra
	}
	t := time.NewTimer(backoff)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// fetchAll pulls endpoint-protection (epp) alerts, narrowed server-side by an FQL
// product filter, paginating to exhaustion (bounded by mcpAlertMaxPages), then keeps
// the ones whose command line matches the MCP signature. Detections missing an AID or
// user name are dropped — they cannot be attributed to a host or identity.
func (c *mcpDetectionsClient) fetchAll(ctx context.Context) ([]mcpDetection, error) {
	filter := url.QueryEscape("product:'epp'")
	var ids []string
	truncated := false
	for page := 0; ; page++ {
		if page >= mcpAlertMaxPages {
			truncated = true
			break
		}
		qURL := fmt.Sprintf("https://%s/alerts/queries/alerts/v2?filter=%s&limit=%d&offset=%d&sort=timestamp.desc",
			c.host, filter, mcpServerAlertLimit, page*mcpServerAlertLimit)
		b, err := c.doJSON(ctx, http.MethodGet, qURL, "")
		if err != nil {
			return nil, err
		}
		var q alertsQueryResp
		if err := json.Unmarshal(b, &q); err != nil {
			return nil, err
		}
		ids = append(ids, q.Resources...)
		if len(q.Resources) < mcpServerAlertLimit {
			break
		}
	}
	if truncated {
		ctxzap.Extract(ctx).Warn("baton-crowdstrike: mcp detection scan hit page cap; older epp alerts not scanned",
			zap.Int("scanned_alerts", len(ids)), zap.Int("page_cap", mcpAlertMaxPages))
	}
	if len(ids) == 0 {
		return nil, nil
	}

	var out []mcpDetection
	for start := 0; start < len(ids); start += mcpServerAlertLimit {
		end := start + mcpServerAlertLimit
		if end > len(ids) {
			end = len(ids)
		}
		detBody, _ := json.Marshal(map[string]interface{}{"composite_ids": ids[start:end]})
		b, err := c.doJSON(ctx, http.MethodPost, fmt.Sprintf("https://%s/alerts/entities/alerts/v2", c.host), string(detBody))
		if err != nil {
			return nil, err
		}
		var e alertsEntitiesResp
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		for _, a := range e.Resources {
			if a.Product != "epp" || !mcpSignature.MatchString(a.Cmdline) {
				continue
			}
			if a.Device.DeviceID == "" || a.UserName == "" {
				continue // unattributable to a host/identity
			}
			ts, _ := time.Parse(time.RFC3339, a.Timestamp)
			out = append(out, mcpDetection{
				Hostname: a.Device.Hostname, AID: a.Device.DeviceID, LocalIP: a.Device.LocalIP,
				UserName: a.UserName, CommandLine: a.Cmdline, FilePath: a.Filepath, Timestamp: ts,
				CompositeID: a.CompositeID, FalconLink: a.FalconHost, IOARuleName: a.PatternName,
			})
		}
	}
	return out, nil
}

// mcpSource is a per-connector data source shared by the mcp_server and endpoint_user
// syncers. It memoizes the detection snapshot and identity index per sync (keyed by
// SyncID) so every List/Grants call across both resource types sees one consistent
// snapshot — avoiding redundant Alerts / Identity-Protection calls and the grant drift
// that independent re-fetches would cause. Only the current sync's data is retained.
type mcpSource struct {
	// enabled gates shadow-MCP detection. When false (the default), detections and
	// the identity index are no-ops that make no CrowdStrike API calls, so the
	// mcp_server / endpoint_user syncers produce nothing — the capability is opt-in.
	enabled bool

	detClient *mcpDetectionsClient
	ipClient  *IdentityProtectionClient

	mu      sync.Mutex
	detSync string
	detData []mcpDetection
	idxSync string
	idxData map[string]*resolvedIdentity
}

func newMCPSource(ctx context.Context, clientID, clientSecret, host string, enabled bool) *mcpSource {
	return &mcpSource{
		enabled:   enabled,
		detClient: newMCPDetectionsClient(ctx, clientID, clientSecret, host),
		ipClient:  NewIdentityProtectionClient(ctx, clientID, clientSecret, host),
	}
}

func (s *mcpSource) detections(ctx context.Context, syncID string) ([]mcpDetection, error) {
	if !s.enabled {
		return nil, nil
	}
	s.mu.Lock()
	if s.detData != nil && s.detSync == syncID {
		d := s.detData
		s.mu.Unlock()
		return d, nil
	}
	s.mu.Unlock()
	d, err := s.detClient.fetchAll(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.detSync, s.detData = syncID, d
	s.mu.Unlock()
	return d, nil
}

func (s *mcpSource) identityIndex(ctx context.Context, syncID string) (map[string]*resolvedIdentity, error) {
	if !s.enabled {
		return map[string]*resolvedIdentity{}, nil
	}
	s.mu.Lock()
	if s.idxData != nil && s.idxSync == syncID {
		idx := s.idxData
		s.mu.Unlock()
		return idx, nil
	}
	s.mu.Unlock()
	idx, err := buildIdentityIndex(ctx, s.ipClient)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.idxSync, s.idxData = syncID, idx
	s.mu.Unlock()
	return idx, nil
}

func mcpServerBuilder(client *fClient.CrowdStrikeAPISpecification, src *mcpSource) *mcpServerResourceType {
	return &mcpServerResourceType{resourceType: resourceTypeMCPServer, client: client, src: src}
}

func endpointUserBuilder(src *mcpSource) *endpointUserResourceType {
	return &endpointUserResourceType{resourceType: resourceTypeEndpointUser, src: src}
}
