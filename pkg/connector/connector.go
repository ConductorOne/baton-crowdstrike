package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/crowdstrike/gofalcon/falcon"
	fClient "github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"google.golang.org/grpc/codes"
)

type Connector struct {
	client       *fClient.CrowdStrikeAPISpecification
	clientId     string
	clientSecret string
	host         string
}

func (o *Connector) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		userBuilder(o.client),
		roleBuilder(o.client),
		securityInsightBuilder(ctx, o.client, o.clientId, o.clientSecret, o.host),
	}
}

func (o *Connector) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "CrowdStrike",
		Description: "Connector syncing CrowdStrike users, roles, and identity risk scores to Baton.",
	}, nil
}

// Validates that the user has access to all relevant endpoints.
func (o *Connector) Validate(ctx context.Context) (annotations.Annotations, error) {
	var limit int64 = 1

	// get user ids
	_, err := o.client.UserManagement.QueryUserV1(
		&user_management.QueryUserV1Params{
			Limit:   &limit,
			Context: ctx,
		},
	)
	if err != nil {
		return nil, wrapCrowdStrikeError(err, "validate: unable to query user ids")
	}

	// get role ids
	roleIDs, err := o.client.UserManagement.QueriesRolesV1(
		&user_management.QueriesRolesV1Params{
			Context: ctx,
		},
	)
	if err != nil {
		return nil, wrapCrowdStrikeError(err, "validate: unable to query role ids")
	}

	// get role details
	_, err = o.client.UserManagement.EntitiesRolesV1(
		&user_management.EntitiesRolesV1Params{
			Ids:     roleIDs.Payload.Resources,
			Context: ctx,
		},
	)
	if err != nil {
		return nil, wrapCrowdStrikeError(err, "validate: unable to retrieve role details")
	}

	return nil, nil
}

// New returns the CrowdStrike connector.
func New(ctx context.Context, clientId, clientSecret string, region string) (*Connector, error) {
	var cloudRegion falcon.CloudType
	switch region {
	case "us-1":
		cloudRegion = falcon.CloudUs1
	case "us-2":
		cloudRegion = falcon.CloudUs2
	case "eu-1":
		cloudRegion = falcon.CloudEu1
	case "us-gov-1":
		cloudRegion = falcon.CloudUsGov1
	default:
		return nil, uhttp.WrapErrors(codes.InvalidArgument, fmt.Sprintf("invalid region: %s", region))
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:          clientId,
		ClientSecret:      clientSecret,
		Cloud:             cloudRegion,
		Context:           ctx,
		UserAgentOverride: "conductorone-crowdstrike",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize SDK client: %w", err)
	}

	return &Connector{
		client:       client,
		clientId:     clientId,
		clientSecret: clientSecret,
		host:         cloudRegion.Host(),
	}, nil
}
