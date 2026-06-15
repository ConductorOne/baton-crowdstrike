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

const profileFieldUserProfile = "user_profile"

var _ connectorbuilder.GlobalActionProvider = (*Connector)(nil)

var globalUpdateUserActionSchema = &v2.BatonActionSchema{
	Name:        actionUpdateUser,
	DisplayName: "Update User",
	Description: "Updates a CrowdStrike user's first and/or last name from a user profile JSON object.",
	Arguments: []*config.Field{
		{
			Name:        argUserID,
			DisplayName: "User Resource ID",
			Description: "The ID of the user to update.",
			IsRequired:  true,
			Field:       &config.Field_StringField{},
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
	userID, err := actions.RequireStringArg(args, argUserID)
	if err != nil {
		return nil, nil, uhttp.WrapErrors(codes.InvalidArgument, fmt.Sprintf("baton-crowdstrike: update_user: %v", err))
	}

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
		return nil, annos, fmt.Errorf("baton-crowdstrike: update_user: failed to build result: %w", err)
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
