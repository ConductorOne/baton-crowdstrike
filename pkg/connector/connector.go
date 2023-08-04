package connector

import (
	"context"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/crowdstrike/gofalcon/falcon"
	fClient "github.com/crowdstrike/gofalcon/falcon/client"
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

// Validates that the user has read access to all relevant tables (more information in the readme).
func (o *CrowdStrike) Validate(ctx context.Context) (annotations.Annotations, error) {
	return nil, nil
}

// New returns the CrowdStrike connector.
func New(ctx context.Context, clientId, clientSecret string) (*CrowdStrike, error) {
	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     clientId,
		ClientSecret: clientSecret,
		Context:      ctx,
	})
	if err != nil {
		return nil, err
	}

	return &CrowdStrike{
		client: client,
	}, nil
}
