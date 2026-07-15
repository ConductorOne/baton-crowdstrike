package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2/clientcredentials"
)

// AccountData represents an external account descriptor associated with an identity entity.
type AccountData struct {
	TypeName string `json:"__typename"`

	// Active Directory fields
	ObjectSid      string `json:"objectSid,omitempty"`
	SamAccountName string `json:"samAccountName,omitempty"`
	Domain         string `json:"domain,omitempty"`
	ObjectGUID     string `json:"objectGuid,omitempty"`

	// Azure AD / AWS IC SSO / Generic SSO fields
	DataSourceParticipantIdentifier string `json:"dataSourceParticipantIdentifier,omitempty"`
}

// ExternalID returns the best external identifier for this account based on its type.
//
// Mapping by account type:
//   - ActiveDirectoryAccountDescriptor → objectGuid (formatted as hyphen-free hex)
//   - AzureSsoUserAccountDescriptor    → dataSourceParticipantIdentifier (Azure AD object ID)
//   - AwsIcSsoUserAccountDescriptorImpl → dataSourceParticipantIdentifier (AWS IC user ID)
//   - SsoUserAccountDescriptorImpl      → dataSourceParticipantIdentifier (generic SSO ID)
//
// Non-user account types (groups, roles, endpoints, cloud services) return "".
func (a AccountData) ExternalID() string {
	switch a.TypeName {
	case "ActiveDirectoryAccountDescriptor":
		if a.ObjectGUID != "" {
			return formatADGuid(a.ObjectGUID)
		}
		if a.ObjectSid != "" {
			return a.ObjectSid
		}
		return ""

	case "AzureSsoUserAccountDescriptor",
		"AwsIcSsoUserAccountDescriptorImpl",
		"SsoUserAccountDescriptorImpl":
		return a.DataSourceParticipantIdentifier

	default:
		// Non-user types (groups, roles, endpoints, cloud services) — no external ID
		return ""
	}
}

// IdentityRiskData represents the risk data for a single identity from CrowdStrike.
type IdentityRiskData struct {
	PrimaryDisplayName   string        `json:"primaryDisplayName"`
	SecondaryDisplayName string        `json:"secondaryDisplayName"`
	EmailAddresses       []string      `json:"emailAddresses"`
	RiskScore            float64       `json:"riskScore"`
	RiskScoreSeverity    string        `json:"riskScoreSeverity"`
	RiskFactors          []RiskFactor  `json:"riskFactors"`
	Accounts             []AccountData `json:"accounts"`
}

// RiskFactor represents a single factor contributing to an identity's risk score.
type RiskFactor struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
}

// graphQLRequest represents a GraphQL request body.
type graphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// graphQLResponse represents the GraphQL response for entities query.
type graphQLResponse struct {
	Data   *graphQLData   `json:"data"`
	Errors []graphQLError `json:"errors,omitempty"`
}

type graphQLData struct {
	Entities *entitiesResult `json:"entities"`
}

type entitiesResult struct {
	PageInfo *pageInfo        `json:"pageInfo"`
	Nodes    []identityEntity `json:"nodes"`
}

type pageInfo struct {
	HasNextPage bool   `json:"hasNextPage"`
	EndCursor   string `json:"endCursor"`
}

type identityEntity struct {
	PrimaryDisplayName   string              `json:"primaryDisplayName"`
	SecondaryDisplayName string              `json:"secondaryDisplayName"`
	EmailAddresses       []string            `json:"emailAddresses"`
	RiskScore            float64             `json:"riskScore"`
	RiskScoreSeverity    string              `json:"riskScoreSeverity"`
	RiskFactors          []riskFactor        `json:"riskFactors"`
	Accounts             []accountDescriptor `json:"accounts"`
}

// accountDescriptor is the internal JSON deserialization type that mirrors AccountData.
// It is intentionally identical so we can use a direct type conversion.
type accountDescriptor = AccountData

type riskFactor struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
}

type graphQLError struct {
	Message string `json:"message"`
}

const identityRiskQuery = `
query GetIdentityRiskScores($first: Int, $after: Cursor) {
  entities(types: [USER], sortKey: PRIMARY_DISPLAY_NAME, first: $first, after: $after) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      primaryDisplayName
      secondaryDisplayName
      riskScore
      riskScoreSeverity
      riskFactors {
        type
        severity
      }
      accounts {
        __typename
        ... on ActiveDirectoryAccountDescriptor {
          objectSid
          samAccountName
          domain
          objectGuid
        }
        ... on AzureSsoUserAccountDescriptor {
          dataSourceParticipantIdentifier
        }
        ... on AwsIcSsoUserAccountDescriptorImpl {
          dataSourceParticipantIdentifier
        }
        ... on SsoUserAccountDescriptorImpl {
          dataSourceParticipantIdentifier
        }
      }
      ... on UserEntity {
        emailAddresses
      }
    }
  }
}
`

// IdentityProtectionClient provides methods to interact with CrowdStrike's Identity Protection API.
type IdentityProtectionClient struct {
	httpClient *http.Client
	endpoint   string
}

// NewIdentityProtectionClient creates a new Identity Protection client with OAuth2 authentication.
func NewIdentityProtectionClient(ctx context.Context, clientID, clientSecret, host string) *IdentityProtectionClient {
	// Create OAuth2 client credentials config
	config := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     "https://" + host + "/oauth2/token",
	}

	// Create the OAuth2 HTTP client
	httpClient := config.Client(ctx)
	httpClient.Timeout = 30 * time.Second

	// Wrap the transport to add user-agent header
	httpClient.Transport = &identityProtectionTransport{
		base: httpClient.Transport,
	}

	return &IdentityProtectionClient{
		httpClient: httpClient,
		endpoint:   "https://" + host + "/identity-protection/combined/graphql/v1",
	}
}

// identityProtectionTransport adds custom headers to requests.
type identityProtectionTransport struct {
	base http.RoundTripper
}

func (t *identityProtectionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", "baton-crowdstrike")
	if t.base == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return t.base.RoundTrip(req)
}

// RefreshContext updates the OAuth2 context used for token refresh.
// This should be called before making requests to ensure the token can be refreshed.
func (c *IdentityProtectionClient) RefreshContext(ctx context.Context, clientID, clientSecret, host string) {
	config := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     "https://" + host + "/oauth2/token",
	}
	httpClient := config.Client(ctx)
	httpClient.Timeout = 30 * time.Second
	httpClient.Transport = &identityProtectionTransport{
		base: httpClient.Transport,
	}
	c.httpClient = httpClient
}

// GetIdentityRiskScores fetches identity risk scores from CrowdStrike Identity Protection.
// It uses the GraphQL API to retrieve risk data for all users.
func (c *IdentityProtectionClient) GetIdentityRiskScores(ctx context.Context, pageSize int, cursor string) ([]IdentityRiskData, string, bool, RateLimitInfo, error) {
	// Build variables for pagination
	variables := map[string]interface{}{
		"first": pageSize,
	}
	if cursor != "" {
		variables["after"] = cursor
	}

	reqBody := graphQLRequest{
		Query:     identityRiskQuery,
		Variables: variables,
	}

	// Create the request body
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", false, RateLimitInfo{}, fmt.Errorf("baton-crowdstrike: failed to marshal GraphQL request: %w", err)
	}

	// Create the HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "", false, RateLimitInfo{}, fmt.Errorf("baton-crowdstrike: failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	//nolint:gosec // endpoint host derives from the configured CrowdStrike region, not user input
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", false, RateLimitInfo{}, fmt.Errorf("baton-crowdstrike: failed to execute identity protection request: %w", err)
	}
	defer resp.Body.Close()

	// Extract rate limit info from response headers
	rateLimitInfo := extractRateLimitInfo(resp)

	// Check for error status codes
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, "", false, rateLimitInfo, fmt.Errorf("baton-crowdstrike: identity protection API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", false, rateLimitInfo, fmt.Errorf("baton-crowdstrike: failed to read response body: %w", err)
	}

	var graphQLResp graphQLResponse
	if err := json.Unmarshal(respBody, &graphQLResp); err != nil {
		return nil, "", false, rateLimitInfo, fmt.Errorf("baton-crowdstrike: failed to parse GraphQL response: %w", err)
	}

	// Check for GraphQL errors
	if len(graphQLResp.Errors) > 0 {
		return nil, "", false, rateLimitInfo, fmt.Errorf("baton-crowdstrike: GraphQL error: %s", graphQLResp.Errors[0].Message)
	}

	// Check if we have data
	if graphQLResp.Data == nil || graphQLResp.Data.Entities == nil {
		return nil, "", false, rateLimitInfo, nil
	}

	// Convert to IdentityRiskData
	results := make([]IdentityRiskData, 0, len(graphQLResp.Data.Entities.Nodes))
	for _, entity := range graphQLResp.Data.Entities.Nodes {
		riskFactors := make([]RiskFactor, 0, len(entity.RiskFactors))
		for _, rf := range entity.RiskFactors {
			riskFactors = append(riskFactors, RiskFactor(rf))
		}

		accounts := make([]AccountData, len(entity.Accounts))
		copy(accounts, entity.Accounts)

		results = append(results, IdentityRiskData{
			PrimaryDisplayName:   entity.PrimaryDisplayName,
			SecondaryDisplayName: entity.SecondaryDisplayName,
			EmailAddresses:       entity.EmailAddresses,
			RiskScore:            entity.RiskScore,
			RiskScoreSeverity:    entity.RiskScoreSeverity,
			RiskFactors:          riskFactors,
			Accounts:             accounts,
		})
	}

	// Get pagination info
	nextCursor := ""
	hasNextPage := false
	if graphQLResp.Data.Entities.PageInfo != nil {
		hasNextPage = graphQLResp.Data.Entities.PageInfo.HasNextPage
		nextCursor = graphQLResp.Data.Entities.PageInfo.EndCursor
	}

	return results, nextCursor, hasNextPage, rateLimitInfo, nil
}

// ValidateAccess checks if the connector has access to the Identity Protection API.
func (c *IdentityProtectionClient) ValidateAccess(ctx context.Context) error {
	// Try to fetch a single entity to validate access
	_, _, _, _, err := c.GetIdentityRiskScores(ctx, 1, "")
	if err != nil {
		return fmt.Errorf("baton-crowdstrike: identity protection API access validation failed: %w", err)
	}
	return nil
}

// extractRateLimitInfo extracts rate limit information from HTTP response headers.
func extractRateLimitInfo(resp *http.Response) RateLimitInfo {
	var limit, remaining int64

	if limitStr := resp.Header.Get("X-RateLimit-Limit"); limitStr != "" {
		_, _ = fmt.Sscanf(limitStr, "%d", &limit)
	}
	if remainingStr := resp.Header.Get("X-RateLimit-Remaining"); remainingStr != "" {
		_, _ = fmt.Sscanf(remainingStr, "%d", &remaining)
	}

	return NewRateLimitInfo(limit, remaining)
}

// formatADGuid converts an Active Directory objectGuid from the standard UUID/RFC format
// returned by CrowdStrike (big-endian) to the mixed-endian hex format that Active Directory
// and baton-active-directory use.
//
// Microsoft GUIDs use mixed-endian encoding:
//   - Data1 (4 bytes): little-endian  → bytes reversed
//   - Data2 (2 bytes): little-endian  → bytes reversed
//   - Data3 (2 bytes): little-endian  → bytes reversed
//   - Data4 (8 bytes): big-endian     → unchanged
//
// Example:
//
//	CrowdStrike: "682cf9db-abba-432f-b682-5a7fea80a00a"
//	AD format:   "dbf92c68baab2f43b6825a7fea80a00a"
func formatADGuid(guid string) string {
	guid = strings.TrimPrefix(guid, "{")
	guid = strings.TrimSuffix(guid, "}")
	guid = strings.ReplaceAll(guid, "-", "")
	guid = strings.ToLower(guid)

	// Need exactly 32 hex chars (16 bytes) to do the endian conversion
	if len(guid) != 32 {
		return guid
	}

	// Reverse byte pairs for Data1 (bytes 0-3), Data2 (bytes 4-5), Data3 (bytes 6-7).
	// Each byte is 2 hex chars.
	// Data1: positions 0-7 (4 bytes = 8 hex chars) → reverse byte order
	// Data2: positions 8-11 (2 bytes = 4 hex chars) → reverse byte order
	// Data3: positions 12-15 (2 bytes = 4 hex chars) → reverse byte order
	// Data4: positions 16-31 (8 bytes = 16 hex chars) → unchanged
	data1 := guid[0:8]
	data2 := guid[8:12]
	data3 := guid[12:16]
	data4 := guid[16:32]

	return reverseByteHex(data1) + reverseByteHex(data2) + reverseByteHex(data3) + data4
}

// reverseByteHex reverses the byte order of a hex string.
// e.g. "682cf9db" → "dbf92c68" (swaps pairs: 68,2c,f9,db → db,f9,2c,68).
func reverseByteHex(hex string) string {
	n := len(hex)
	result := make([]byte, n)
	for i := 0; i < n; i += 2 {
		result[n-i-2] = hex[i]
		result[n-i-1] = hex[i+1]
	}
	return string(result)
}
