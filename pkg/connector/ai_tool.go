package connector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
)

// AI coding tool ("harness") categories.
const (
	harnessKindCLI     = "cli"     // terminal agent (Claude Code, codex, aider, …)
	harnessKindDesktop = "desktop" // standalone desktop app (Claude Desktop)
	harnessKindIDE     = "ide"     // AI-native editor (Cursor, Windsurf)
)

// harnessEntry describes one recognizable AI coding tool and the command-line pattern
// that identifies it. The pattern is matched against process-creation command lines
// surfaced by the Alerts API (the same shared scan shadow-MCP detection reads).
type harnessEntry struct {
	name    string
	vendor  string
	kind    string
	pattern *regexp.Regexp
}

// harnessCatalog is the ordered list of AI coding tools we recognize. Order matters:
// classifyHarness returns the first match, so more specific tools come before broader
// ones (e.g. Claude Code before Claude Desktop). Patterns are deliberately anchored on
// package names (@vendor/tool) or path-qualified executables rather than bare words, to
// keep common English tokens (e.g. "gemini", "copilot") from matching unrelated
// processes. This is not meant to be exhaustive — it covers the popular harnesses.
var harnessCatalog = []harnessEntry{
	{"Claude Code", "Anthropic", harnessKindCLI, regexp.MustCompile(`(?i)(@anthropic-ai[\\/]claude-code|claude-code)`)},
	{"Claude Desktop", "Anthropic", harnessKindDesktop, regexp.MustCompile(`(?i)(anthropicclaude|[\\/]claude\.exe)`)},
	{"Cursor", "Anysphere", harnessKindIDE, regexp.MustCompile(`(?i)([\\/]cursor\.exe|cursor-agent|[\\/]cursor-tunnel)`)},
	{"Windsurf", "Codeium", harnessKindIDE, regexp.MustCompile(`(?i)([\\/]windsurf\.exe|\bwindsurf\b)`)},
	{"Codex CLI", "OpenAI", harnessKindCLI, regexp.MustCompile(`(?i)(@openai[\\/]codex|codex-cli|[\\/]codex\.(exe|cmd|js))`)},
	{"Gemini CLI", "Google", harnessKindCLI, regexp.MustCompile(`(?i)(@google[\\/]gemini-cli|gemini-cli)`)},
	{"GitHub Copilot CLI", "GitHub", harnessKindCLI, regexp.MustCompile(`(?i)(@github[\\/]copilot|copilot-cli)`)},
	{"opencode", "opencode", harnessKindCLI, regexp.MustCompile(`(?i)\bopencode\b`)},
	{"Aider", "Aider", harnessKindCLI, regexp.MustCompile(`(?i)\baider\b`)},
}

// classifyHarness returns the AI tool a command line belongs to, or nil if none match.
func classifyHarness(cmdline string) *harnessEntry {
	for i := range harnessCatalog {
		if harnessCatalog[i].pattern.MatchString(cmdline) {
			return &harnessCatalog[i]
		}
	}
	return nil
}

// matchesHarness reports whether a command line names a known AI coding tool. It is used
// by the shared Alerts scan to keep harness detections alongside shadow-MCP ones.
func matchesHarness(cmdline string) bool {
	return classifyHarness(cmdline) != nil
}

// aiToolInstance is a deduplicated (host, user, tool) AI-tool observation. A tool
// surfaces under many command-line spellings across the process tree; we collapse them
// per logical tool and keep the earliest sighting plus the cleanest sample command line.
type aiToolInstance struct {
	det         mcpDetection
	entry       *harnessEntry
	bestCmdline string
	count       int
}

// objectID is the stable ai_tool resource ID: sha256(aid|user|tool) — the same fields
// buildAIToolInstances dedups on — so it is stable across syncs and command-line
// spellings.
func (inst *aiToolInstance) objectID() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{inst.det.AID, strings.ToLower(inst.det.UserName), inst.entry.name}, "|")))
	return "ai-" + hex.EncodeToString(sum[:])[:24]
}

// buildAIToolInstances deduplicates harness detections into unique (host, user, tool)
// instances, keeping the earliest timestamp and shortest sample command line.
func buildAIToolInstances(dets []mcpDetection) map[string]*aiToolInstance {
	instances := map[string]*aiToolInstance{}
	for _, d := range dets {
		if d.AID == "" || d.UserName == "" {
			continue // unattributable — avoid collapsing distinct hosts/users into one id
		}
		entry := classifyHarness(d.CommandLine)
		if entry == nil {
			continue
		}
		key := strings.Join([]string{d.AID, strings.ToLower(d.UserName), entry.name}, "|")
		inst, seen := instances[key]
		if !seen {
			instances[key] = &aiToolInstance{det: d, entry: entry, bestCmdline: d.CommandLine, count: 1}
			continue
		}
		inst.count++
		if !d.Timestamp.IsZero() && (inst.det.Timestamp.IsZero() || d.Timestamp.Before(inst.det.Timestamp)) {
			inst.det.Timestamp = d.Timestamp
		}
		if len(d.CommandLine) < len(inst.bestCmdline) {
			inst.bestCmdline = d.CommandLine
		}
	}
	return instances
}

// aiToolResourceType syncs AI coding tools ("harnesses" — Claude Code, Cursor, codex,
// etc.) observed running on endpoints via CrowdStrike EDR detections, correlating each
// to the identity that ran it. It is an inventory/governance signal (which identities
// use which AI tools on which hosts), distinct from the shadow-MCP finding.
type aiToolResourceType struct {
	resourceType *v2.ResourceType
	src          *mcpSource
	// enabled gates AI-tool inventory. The shared source may still scan for shadow-MCP;
	// this flag decides whether ai_tool resources are emitted.
	enabled bool
}

func (a *aiToolResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return a.resourceType
}

// List scans the shared EDR detection snapshot for AI-tool activity, correlates each to
// an identity, and returns one ai_tool resource per unique (host, user, tool).
func (a *aiToolResourceType) List(ctx context.Context, _ *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	if !a.enabled {
		return nil, &rs.SyncOpResults{}, nil
	}
	dets, err := a.src.detections(ctx, opts.SyncID)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-crowdstrike: ai_tool list: failed to fetch detections: %w", err)
	}
	if len(dets) == 0 {
		return nil, &rs.SyncOpResults{}, nil
	}
	idIndex, err := a.src.identityIndex(ctx, opts.SyncID)
	if err != nil {
		return nil, nil, fmt.Errorf("baton-crowdstrike: ai_tool list: failed to build identity index: %w", err)
	}

	instances := buildAIToolInstances(dets)
	resources := make([]*v2.Resource, 0, len(instances))
	for _, inst := range instances {
		res, err := aiToolResource(inst, resolveIdentity(idIndex, inst.det.UserName))
		if err != nil {
			return nil, nil, fmt.Errorf("baton-crowdstrike: failed to build ai_tool resource: %w", err)
		}
		resources = append(resources, res)
	}
	return resources, &rs.SyncOpResults{}, nil
}

func (a *aiToolResourceType) Entitlements(context.Context, *v2.Resource, rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

func (a *aiToolResourceType) Grants(context.Context, *v2.Resource, rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// aiToolResource builds an ai_tool resource: an App-trait profile carrying the tool +
// endpoint + resolved-identity metadata, plus a low-severity security-insight annotation
// binding the observation to the identity (when one resolves) so it surfaces in c1's
// identity view as governance visibility rather than a high-severity finding.
func aiToolResource(inst *aiToolInstance, id *resolvedIdentity) (*v2.Resource, error) {
	d := inst.det
	e := inst.entry

	displayName := fmt.Sprintf("AI Tool: %s @ %s", e.name, d.Hostname)
	if d.UserName != "" {
		displayName = fmt.Sprintf("%s (%s)", displayName, d.UserName)
	}

	profile := map[string]interface{}{
		"tool":                e.name,
		"vendor":              e.vendor,
		"kind":                e.kind,
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

	// Bind the observation to the identity as a low-severity insight so it associates
	// in c1's identity view. This is inventory/visibility, not a threat — hence "Low".
	if id != nil && id.externalID != "" {
		issueVal := fmt.Sprintf("AI coding tool '%s' (%s, %s) in use on %s by %s",
			e.name, e.vendor, e.kind, d.Hostname, d.UserName)
		insightOpts := []rs.SecurityInsightTraitOption{
			rs.WithIssue(issueVal),
			rs.WithIssueSeverity("Low"),
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

	return rs.NewResource(displayName, resourceTypeAITool, inst.objectID(), opts...)
}

func aiToolBuilder(src *mcpSource, enabled bool) *aiToolResourceType {
	return &aiToolResourceType{resourceType: resourceTypeAITool, src: src, enabled: enabled}
}
