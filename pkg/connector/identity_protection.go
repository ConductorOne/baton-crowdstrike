package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2/clientcredentials"
)

// IdentityRiskData represents the risk data for a single identity from CrowdStrike.
type IdentityRiskData struct {
	PrimaryDisplayName   string       `json:"primaryDisplayName"`
	SecondaryDisplayName string       `json:"secondaryDisplayName"`
	EmailAddresses       []string     `json:"emailAddresses"`
	RiskScore            float64      `json:"riskScore"`
	RiskScoreSeverity    string       `json:"riskScoreSeverity"`
	RiskFactors          []RiskFactor `json:"riskFactors"`
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
	PrimaryDisplayName   string       `json:"primaryDisplayName"`
	SecondaryDisplayName string       `json:"secondaryDisplayName"`
	EmailAddresses       []string     `json:"emailAddresses"`
	RiskScore            float64      `json:"riskScore"`
	RiskScoreSeverity    string       `json:"riskScoreSeverity"`
	RiskFactors          []riskFactor `json:"riskFactors"`
}

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
		return nil, "", false, RateLimitInfo{}, fmt.Errorf("failed to marshal GraphQL request: %w", err)
	}

	// Create the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "", false, RateLimitInfo{}, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Make the HTTP request using the authenticated client
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", false, RateLimitInfo{}, fmt.Errorf("failed to execute identity protection request: %w", err)
	}
	defer resp.Body.Close()

	// Extract rate limit info from response headers
	rateLimitInfo := extractRateLimitInfo(resp)

	// Check for error status codes
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, "", false, rateLimitInfo, fmt.Errorf("identity protection API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", false, rateLimitInfo, fmt.Errorf("failed to read response body: %w", err)
	}

	var graphQLResp graphQLResponse
	if err := json.Unmarshal(respBody, &graphQLResp); err != nil {
		return nil, "", false, rateLimitInfo, fmt.Errorf("failed to parse GraphQL response: %w", err)
	}

	// Check for GraphQL errors
	if len(graphQLResp.Errors) > 0 {
		return nil, "", false, rateLimitInfo, fmt.Errorf("GraphQL error: %s", graphQLResp.Errors[0].Message)
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
			riskFactors = append(riskFactors, RiskFactor{
				Type:     rf.Type,
				Severity: rf.Severity,
			})
		}

		results = append(results, IdentityRiskData{
			PrimaryDisplayName:   entity.PrimaryDisplayName,
			SecondaryDisplayName: entity.SecondaryDisplayName,
			EmailAddresses:       entity.EmailAddresses,
			RiskScore:            entity.RiskScore,
			RiskScoreSeverity:    entity.RiskScoreSeverity,
			RiskFactors:          riskFactors,
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
		return fmt.Errorf("identity protection API access validation failed: %w", err)
	}
	return nil
}

// extractRateLimitInfo extracts rate limit information from HTTP response headers.
func extractRateLimitInfo(resp *http.Response) RateLimitInfo {
	var limit, remaining int64

	if limitStr := resp.Header.Get("X-RateLimit-Limit"); limitStr != "" {
		fmt.Sscanf(limitStr, "%d", &limit)
	}
	if remainingStr := resp.Header.Get("X-RateLimit-Remaining"); remainingStr != "" {
		fmt.Sscanf(remainingStr, "%d", &remaining)
	}

	return NewRateLimitInfo(limit, remaining)
}
