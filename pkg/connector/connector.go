package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/crowdstrike/gofalcon/falcon"
	fClient "github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
)

var (
	resourceTypeUser = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: annotationsForUserResourceType(),
	}
	resourceTypeRole = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_ROLE,
		},
	}
)

type CrowdStrike struct {
	client *fClient.CrowdStrikeAPISpecification
}

func (o *CrowdStrike) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		userBuilder(o.client),
		roleBuilder(o.client),
	}
}

func (o *CrowdStrike) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "CrowdStrike",
		Description: "Connector syncing CrowdStrike users and their roles to Baton.",
	}, nil
}

// Validates that the user has access to all relevant endpoints.
func (o *CrowdStrike) Validate(ctx context.Context) (annotations.Annotations, error) {
	var limit int64 = 1

	// get user ids
	_, err := o.client.UserManagement.QueryUserV1(
		&user_management.QueryUserV1Params{
			Limit:   &limit,
			Context: ctx,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("crowdstrike-connector: current user is not able to query user ids: %w", err)
	}

	// get role ids
	roleIDs, err := o.client.UserManagement.QueriesRolesV1(
		&user_management.QueriesRolesV1Params{
			Context: ctx,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("crowdstrike-connector: current user is not able to query role ids: %w", err)
	}

	// get role details
	_, err = o.client.UserManagement.EntitiesRolesV1(
		&user_management.EntitiesRolesV1Params{
			Ids:     roleIDs.Payload.Resources,
			Context: ctx,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("crowdstrike-connector: current user is not able to retrieve role details: %w", err)
	}

	return nil, nil
}

// New returns the CrowdStrike connector.
func New(ctx context.Context, clientId, clientSecret string, region string) (*CrowdStrike, error) {
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
		return nil, fmt.Errorf("crowdstrike-connector: invalid region: %s", region)
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Cloud:        cloudRegion,
		Context:      ctx,
	})
	if err != nil {
		return nil, err
	}

	return &CrowdStrike{
		client: client,
	}, nil
}
