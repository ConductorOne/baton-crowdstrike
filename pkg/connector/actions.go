package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	config "github.com/conductorone/baton-sdk/pb/c1/config/v1"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/actions"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	profileFieldUserProfile = "user_profile"
	displayNameUser         = "User"
)

var (
	_ connectorbuilder.GlobalActionProvider   = (*Connector)(nil)
	_ connectorbuilder.ResourceActionProvider = (*userResourceType)(nil)
)

// --- Global account-level action (consumed by C1 push rules) ---

var globalUpdateUserActionSchema = &v2.BatonActionSchema{
	Name:        actionUpdateUser,
	DisplayName: "Update User",
	Description: "Updates a CrowdStrike user's first and/or last name from a user profile JSON object.",
	Arguments: []*config.Field{
		{
			Name:        argUserID,
			DisplayName: displayNameUser,
			Description: "The user to update.",
			IsRequired:  true,
			Field: &config.Field_ResourceIdField{
				ResourceIdField: &config.ResourceIdField{
					Rules: &config.ResourceIDRules{
						AllowedResourceTypeIds: []string{resourceTypeUser.Id},
					},
				},
			},
		},
		{
			Name:        profileFieldUserProfile,
			DisplayName: "User Profile Data",
			Description: "A JSON object containing first_name and/or last_name.",
			IsRequired:  true,
			Field:       &config.Field_StringField{},
		},
	},
	ReturnTypes: []*config.Field{
		{Name: returnFieldSuccess, DisplayName: "Success", Field: &config.Field_BoolField{}},
		{Name: "updated_fields", DisplayName: "Updated Fields", Field: &config.Field_StringField{}},
	},
	ActionType: []v2.ActionType{
		v2.ActionType_ACTION_TYPE_ACCOUNT,
		v2.ActionType_ACTION_TYPE_ACCOUNT_UPDATE_PROFILE,
	},
}

// GlobalActions registers account-level actions used by C1 automations such as push rules.
func (o *Connector) GlobalActions(ctx context.Context, registry actions.ActionRegistry) error {
	if err := registry.Register(ctx, globalUpdateUserActionSchema, o.updateUserActionHandler); err != nil {
		return fmt.Errorf("baton-crowdstrike: register update_user action: %w", err)
	}

	return nil
}

func (o *Connector) updateUserActionHandler(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	userResourceID, ok := actions.GetResourceIDArg(args, argUserID)
	if !ok || userResourceID.GetResource() == "" {
		return nil, nil, uhttp.WrapErrors(codes.InvalidArgument, "baton-crowdstrike: update_user: user_id is required")
	}
	userID := userResourceID.GetResource()

	profileJSON, err := actions.RequireStringArg(args, profileFieldUserProfile)
	if err != nil {
		return nil, nil, uhttp.WrapErrors(codes.InvalidArgument, fmt.Sprintf("baton-crowdstrike: update_user: %v", err))
	}

	var profile map[string]any
	if err := json.Unmarshal([]byte(profileJSON), &profile); err != nil {
		return nil, nil, uhttp.WrapErrors(codes.InvalidArgument, fmt.Sprintf("baton-crowdstrike: update_user: invalid user_profile JSON: %v", err))
	}

	firstName := stringProfileValue(profile, profileFieldFirstName, "firstName")
	lastName := stringProfileValue(profile, profileFieldLastName, "lastName")

	annos, updatedFields, err := updateUserProfile(ctx, o.client, userID, firstName, lastName)
	if err != nil {
		return nil, nil, err
	}

	result, err := structpb.NewStruct(map[string]any{
		returnFieldSuccess: true,
		"updated_fields":   strings.Join(updatedFields, ", "),
	})
	if err != nil {
		return nil, annos, uhttp.WrapErrors(codes.Internal, "baton-crowdstrike: update_user: failed to build result")
	}

	return result, annos, nil
}

func stringProfileValue(profile map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := profile[key].(string); ok {
			return value
		}
	}

	return ""
}

// --- Resource-scoped action (manual invocation on a user resource) ---

var updateUserActionSchema = &v2.BatonActionSchema{
	Name:        actionUpdateProfile,
	DisplayName: "Update User Profile",
	Description: "Updates a CrowdStrike user's first and/or last name.",
	Arguments: []*config.Field{
		{
			Name:        argUserID,
			DisplayName: displayNameUser,
			Description: "The user to update.",
			IsRequired:  true,
			Field: &config.Field_ResourceIdField{
				ResourceIdField: &config.ResourceIdField{
					Rules: &config.ResourceIDRules{
						AllowedResourceTypeIds: []string{resourceTypeUser.Id},
					},
				},
			},
		},
		{Name: profileFieldFirstName, DisplayName: "First Name", Description: "New first name for the user.", Field: &config.Field_StringField{}},
		{Name: profileFieldLastName, DisplayName: "Last Name", Description: "New last name for the user.", Field: &config.Field_StringField{}},
	},
	ReturnTypes: []*config.Field{
		{Name: returnFieldSuccess, DisplayName: "Success", Field: &config.Field_BoolField{}},
	},
	ActionType:     []v2.ActionType{v2.ActionType_ACTION_TYPE_ACCOUNT_UPDATE_PROFILE},
	ResourceTypeId: resourceTypeUser.Id,
}

// ResourceActions registers the CrowdStrike user profile update action.
func (u *userResourceType) ResourceActions(ctx context.Context, registry actions.ActionRegistry) error {
	if err := registry.Register(ctx, updateUserActionSchema, u.updateUserHandler); err != nil {
		return fmt.Errorf("baton-crowdstrike: register update_profile action: %w", err)
	}

	return nil
}

// updateUserHandler updates first and/or last name, backfilling the omitted
// name so a partial update never clears the other field.
func (u *userResourceType) updateUserHandler(ctx context.Context, args *structpb.Struct) (*structpb.Struct, annotations.Annotations, error) {
	userResourceID, ok := actions.GetResourceIDArg(args, argUserID)
	if !ok || userResourceID.GetResource() == "" {
		return nil, nil, uhttp.WrapErrors(codes.InvalidArgument, "baton-crowdstrike: update_profile: user_id is required")
	}
	userID := userResourceID.GetResource()

	firstName, _ := actions.GetStringArg(args, profileFieldFirstName)
	lastName, _ := actions.GetStringArg(args, profileFieldLastName)

	annos, _, err := updateUserProfile(ctx, u.client, userID, firstName, lastName)
	if err != nil {
		return nil, nil, err
	}

	result, err := structpb.NewStruct(map[string]any{returnFieldSuccess: true})
	if err != nil {
		return nil, annos, uhttp.WrapErrors(codes.Internal, "baton-crowdstrike: update_profile: failed to build result")
	}

	return result, annos, nil
}
