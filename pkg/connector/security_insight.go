package connector

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	fClient "github.com/crowdstrike/gofalcon/falcon/client"
)

const (
	// securityInsightPageSize is the number of identity risk scores to fetch per page.
	securityInsightPageSize = 100
)

type securityInsightResourceType struct {
	resourceType *v2.ResourceType
	client       *fClient.CrowdStrikeAPISpecification
	ipClient     *IdentityProtectionClient
	// enabled gates risk-score ingestion (on by default). When false, List is a
	// no-op that makes no Identity Protection API call.
	enabled bool
}

func (s *securityInsightResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return s.resourceType
}

// securityInsightResource creates a new security insight resource for a single account
// on an identity entity. Each account produces its own insight with the account's
// external ID set as an AppUser target. Returns nil (without error) if the account
// does not have an external ID.
func securityInsightResource(identity IdentityRiskData, account AccountData) (*v2.Resource, error) {
	externalID := account.ExternalID()

	// We only create insights for accounts that have an external ID
	if externalID == "" {
		return nil, nil
	}

	// Get the email if available — not required, but helpful for resolution
	var email string
	if len(identity.EmailAddresses) > 0 {
		email = identity.EmailAddresses[0]
	} else if validateEmail(identity.SecondaryDisplayName) {
		email = identity.SecondaryDisplayName
	}

	// Use the external ID as the resource ID for uniqueness
	resourceID := externalID

	// Build the display name for the resource
	displayName := fmt.Sprintf("Risk Score: %s", identity.PrimaryDisplayName)
	if identity.PrimaryDisplayName == "" {
		displayName = fmt.Sprintf("Risk Score: %s", resourceID)
	}
	// Append account type for clarity when an entity has multiple accounts
	if account.TypeName != "" {
		displayName = fmt.Sprintf("%s (%s)", displayName, account.TypeName)
	}

	// Normalize 0-1 score to 0-100 percentage; preserve the original as the source score.
	// Clamp to [0,1] to guard against unexpected values from the API.
	clamped := math.Max(0, math.Min(1, identity.RiskScore))
	if math.IsNaN(identity.RiskScore) || math.IsInf(identity.RiskScore, 0) {
		clamped = 0
	}
	normalizedScore := uint32(math.Round(clamped * 100))
	sourceScore := strconv.FormatFloat(identity.RiskScore, 'f', -1, 64)

	traitOpts := []rs.SecurityInsightTraitOption{
		rs.WithNormalizedRiskScore(normalizedScore, sourceScore),
	}

	// Add structured risk factors if present
	if len(identity.RiskFactors) > 0 {
		factors := make([]*v2.RiskFactor, 0, len(identity.RiskFactors))
		for _, rf := range identity.RiskFactors {
			factors = append(factors, rs.NewRiskFactor(rf.Type, mapRiskFactorSeverity(rf.Severity)))
		}
		traitOpts = append(traitOpts, rs.WithRiskFactors(factors...))
	}

	// Always use AppUser target with email + external ID
	traitOpts = append(traitOpts, rs.WithInsightAppUserTarget(email, externalID))

	// Create the security insight resource
	resource, err := rs.NewSecurityInsightResource(
		displayName,
		resourceTypeSecurityInsight,
		resourceID,
		traitOpts...,
	)
	if err != nil {
		return nil, fmt.Errorf("baton-crowdstrike: failed to create security insight resource: %w", err)
	}

	return resource, nil
}

func (s *securityInsightResourceType) List(ctx context.Context, _ *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	// When risk-score ingestion is disabled, sync nothing and make no Identity
	// Protection API call.
	if !s.enabled {
		return nil, &rs.SyncOpResults{}, nil
	}

	// Parse the page token to get the cursor
	cursor := opts.PageToken.Token

	// Fetch identity risk scores from CrowdStrike
	identities, nextCursor, hasNextPage, rateLimitInfo, err := s.ipClient.GetIdentityRiskScores(ctx, securityInsightPageSize, cursor)
	if err != nil {
		return nil, nil, wrapCrowdStrikeError(err, "security insight list: failed to fetch identity risk scores")
	}

	// Build rate limit annotations
	annos := WithRateLimitAnnotations(rateLimitInfo)

	// If no identities found, return empty result
	if len(identities) == 0 {
		return nil, &rs.SyncOpResults{Annotations: annos}, nil
	}

	// Convert identities to resources — one insight per account on each entity.
	// Only accounts with an external ID produce insights.
	var resources []*v2.Resource
	for _, identity := range identities {
		if len(identity.Accounts) == 0 {
			// No accounts — skip this entity entirely
			continue
		}

		for _, account := range identity.Accounts {
			resource, err := securityInsightResource(identity, account)
			if err != nil {
				return nil, nil, fmt.Errorf("baton-crowdstrike: failed to create security insight resource for %s (account %s): %w",
					identity.PrimaryDisplayName, account.TypeName, err)
			}
			// securityInsightResource returns nil when it can't build an AppUser target
			if resource == nil {
				continue
			}
			resources = append(resources, resource)
		}
	}

	// Determine the next page token
	nextPageToken := ""
	if hasNextPage && nextCursor != "" {
		nextPageToken = nextCursor
	}

	return resources, &rs.SyncOpResults{NextPageToken: nextPageToken, Annotations: annos}, nil
}

func (s *securityInsightResourceType) Entitlements(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	// Security insights do not have entitlements
	return nil, nil, nil
}

func (s *securityInsightResourceType) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	// Security insights do not have grants
	return nil, nil, nil
}

// mapRiskFactorSeverity maps CrowdStrike's ScoreSeverity enum (NORMAL, MEDIUM, HIGH)
// to the SDK's RiskFactor_Severity enum.
func mapRiskFactorSeverity(severity string) v2.RiskFactor_Severity {
	switch strings.ToUpper(severity) {
	case "NORMAL":
		return v2.RiskFactor_SEVERITY_LOW
	case "MEDIUM":
		return v2.RiskFactor_SEVERITY_MEDIUM
	case "HIGH":
		return v2.RiskFactor_SEVERITY_HIGH
	default:
		return v2.RiskFactor_SEVERITY_UNSPECIFIED
	}
}

func securityInsightBuilder(client *fClient.CrowdStrikeAPISpecification, httpClient *uhttp.BaseHttpClient, host string, enabled bool) *securityInsightResourceType {
	return &securityInsightResourceType{
		resourceType: resourceTypeSecurityInsight,
		client:       client,
		ipClient:     NewIdentityProtectionClient(httpClient, host),
		enabled:      enabled,
	}
}
