package connector

import (
	"context"
	"fmt"

	cfg "github.com/conductorone/baton-crowdstrike/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
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

func (o *Connector) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncerV2 {
	// One shared MCP data source so the mcp_server and endpoint_user syncers operate on
	// a single per-sync detection snapshot + identity index (consistent grants, no
	// redundant Alerts / Identity-Protection calls).
	mcpSrc := newMCPSource(ctx, o.clientId, o.clientSecret, o.host)
	return []connectorbuilder.ResourceSyncerV2{
		userBuilder(o.client),
		roleBuilder(o.client),
		securityInsightBuilder(ctx, o.client, o.clientId, o.clientSecret, o.host),
		mcpServerBuilder(o.client, mcpSrc),
		endpointUserBuilder(mcpSrc),
	}
}

func (o *Connector) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "CrowdStrike",
		Description: "Connector syncing CrowdStrike users, roles, and identity risk scores to Baton.",
		AccountCreationSchema: &v2.ConnectorAccountCreationSchema{
			FieldMap: map[string]*v2.ConnectorAccountCreationSchema_Field{
				"email": {
					DisplayName: "Email",
					Required:    true,
					Description: "Email address for the new user. Used as both the login (uid) and the email.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "jane.doe@example.com",
					Order:       1,
				},
				profileFieldFirstName: {
					DisplayName: "First Name",
					Required:    false,
					Description: "Given name of the user.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Jane",
					Order:       2,
				},
				profileFieldLastName: {
					DisplayName: "Last Name",
					Required:    false,
					Description: "Family name of the user.",
					Field: &v2.ConnectorAccountCreationSchema_Field_StringField{
						StringField: &v2.ConnectorAccountCreationSchema_StringField{},
					},
					Placeholder: "Doe",
					Order:       3,
				},
			},
		},
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
func New(ctx context.Context, cc *cfg.Crowdstrike, opts *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	var cloudRegion falcon.CloudType
	switch cc.Region {
	case "us-1":
		cloudRegion = falcon.CloudUs1
	case "us-2":
		cloudRegion = falcon.CloudUs2
	case "eu-1":
		cloudRegion = falcon.CloudEu1
	case "us-gov-1":
		cloudRegion = falcon.CloudUsGov1
	default:
		return nil, nil, uhttp.WrapErrors(codes.InvalidArgument, fmt.Sprintf("invalid region: %s", cc.Region))
	}

	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     cc.CrowdstrikeClientId,
		ClientSecret: cc.CrowdstrikeClientSecret,
		Cloud:        cloudRegion,
		HostOverride: cc.BaseUrl,
		Context:      ctx,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize SDK client: %w", err)
	}

	// Mirror gofalcon's HostOverride so the Identity Protection client can be
	// pointed at a test server too; falls back to the region host in production.
	host := cloudRegion.Host()
	if cc.BaseUrl != "" {
		host = cc.BaseUrl
	}

	return &Connector{
		client:       client,
		clientId:     cc.CrowdstrikeClientId,
		clientSecret: cc.CrowdstrikeClientSecret,
		host:         host,
	}, nil, nil
}
