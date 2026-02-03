package connector

import (
	"context"
	"fmt"
	"strconv"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
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
}

func (s *securityInsightResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return s.resourceType
}

// securityInsightResource creates a new security insight resource for an identity risk score.
func securityInsightResource(identity IdentityRiskData) (*v2.Resource, error) {
	// Determine the unique identifier for this security insight
	// Use secondaryDisplayName (often the UPN/email) as the primary identifier
	var resourceID string
	var email string

	if identity.SecondaryDisplayName != "" {
		resourceID = identity.SecondaryDisplayName
	} else if len(identity.EmailAddresses) > 0 {
		resourceID = identity.EmailAddresses[0]
	} else {
		resourceID = identity.PrimaryDisplayName
	}

	// Get the primary email for targeting
	if len(identity.EmailAddresses) > 0 {
		email = identity.EmailAddresses[0]
	} else if validateEmail(identity.SecondaryDisplayName) {
		email = identity.SecondaryDisplayName
	}

	// Build the display name for the resource
	displayName := fmt.Sprintf("Risk Score: %s", identity.PrimaryDisplayName)
	if identity.PrimaryDisplayName == "" {
		displayName = fmt.Sprintf("Risk Score: %s", resourceID)
	}

	// Convert risk score to string (format as percentage)
	riskScoreStr := strconv.FormatFloat(identity.RiskScore, 'f', 2, 64)

	// Build trait options
	traitOpts := []rs.SecurityInsightTraitOption{
		rs.WithRiskScore(riskScoreStr),
	}

	// Add target - prefer AppUserTarget since we have both email and external ID
	if email != "" {
		traitOpts = append(traitOpts, rs.WithInsightAppUserTarget(email, resourceID))
	} else {
		// Fall back to external resource target if no email available
		traitOpts = append(traitOpts, rs.WithInsightExternalResourceTarget(resourceID, "crowdstrike"))
	}

	// Create the security insight resource
	resource, err := rs.NewSecurityInsightResource(
		displayName,
		resourceTypeSecurityInsight,
		resourceID,
		traitOpts...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create security insight resource: %w", err)
	}

	return resource, nil
}

func (s *securityInsightResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	// Parse the page token to get the cursor
	cursor := pt.Token

	// Fetch identity risk scores from CrowdStrike
	identities, nextCursor, hasNextPage, rateLimitInfo, err := s.ipClient.GetIdentityRiskScores(ctx, securityInsightPageSize, cursor)
	if err != nil {
		return nil, "", nil, wrapCrowdStrikeError(err, "security insight list: failed to fetch identity risk scores")
	}

	// Build rate limit annotations
	annos := WithRateLimitAnnotations(rateLimitInfo)

	// If no identities found, return empty result
	if len(identities) == 0 {
		return nil, "", annos, nil
	}

	// Convert identities to resources
	resources := make([]*v2.Resource, 0, len(identities))
	for _, identity := range identities {
		// Skip identities without a risk score (value of 0 means no assessment yet)
		// We still include them but they will have a risk score of "0"

		resource, err := securityInsightResource(identity)
		if err != nil {
			// Log the error but continue processing other identities
			continue
		}
		resources = append(resources, resource)
	}

	// Determine the next page token
	nextPageToken := ""
	if hasNextPage && nextCursor != "" {
		nextPageToken = nextCursor
	}

	return resources, nextPageToken, annos, nil
}

func (s *securityInsightResourceType) Entitlements(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	// Security insights do not have entitlements
	return nil, "", nil, nil
}

func (s *securityInsightResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	// Security insights do not have grants
	return nil, "", nil, nil
}

func securityInsightBuilder(ctx context.Context, client *fClient.CrowdStrikeAPISpecification, clientID, clientSecret, host string) *securityInsightResourceType {
	return &securityInsightResourceType{
		resourceType: resourceTypeSecurityInsight,
		client:       client,
		ipClient:     NewIdentityProtectionClient(ctx, clientID, clientSecret, host),
	}
}
