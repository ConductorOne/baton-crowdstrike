package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	fClient "github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

const (
	roleMembership = "member"
)

type roleResourceType struct {
	resourceType *v2.ResourceType
	client       *fClient.CrowdStrikeAPISpecification
}

func (r *roleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return r.resourceType
}

// Create a new connector resource for an CrowdStrike Role.
func roleResource(ctx context.Context, role *models.DomainUserRole) (*v2.Resource, error) {
	id, displayName, description := *role.ID, *role.DisplayName, *role.Description

	profile := map[string]interface{}{
		"role_id":     id,
		"role_name":   displayName,
		"description": description,
	}

	roleTraitOptions := []rs.RoleTraitOption{
		rs.WithRoleProfile(profile),
	}

	resource, err := rs.NewRoleResource(
		displayName,
		resourceTypeRole,
		id,
		roleTraitOptions,
	)

	if err != nil {
		return nil, err
	}

	return resource, nil
}

func (r *roleResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	roleIds, err := r.client.UserManagement.QueriesRolesV1(
		&user_management.QueriesRolesV1Params{
			Context: ctx,
		},
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("crowdstrike-connector: failed to list roles: %w", err)
	}

	// get details for roles under fetched ids
	roleDetails, err := r.client.UserManagement.EntitiesRolesV1(
		&user_management.EntitiesRolesV1Params{
			Ids:     roleIds.Payload.Resources,
			Context: ctx,
		},
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("crowdstrike-connector: failed to get role details: %w", err)
	}

	var rv []*v2.Resource
	for _, role := range roleDetails.Payload.Resources {
		roleCopy := role
		ur, err := roleResource(ctx, roleCopy)

		if err != nil {
			return nil, "", nil, err
		}

		rv = append(rv, ur)
	}

	return rv, "", nil, nil
}

func (r *roleResourceType) Entitlements(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(resourceTypeUser),
		ent.WithDisplayName(fmt.Sprintf("%s Role %s", resource.DisplayName, roleMembership)),
		ent.WithDescription(fmt.Sprintf("Access to %s role in CrowdStrike", resource.DisplayName)),
	}

	rv = append(rv, ent.NewAssignmentEntitlement(
		resource,
		roleMembership,
		assignmentOptions...,
	))

	return rv, "", nil, nil
}

func (r *roleResourceType) FindUsersWithRole(ctx context.Context, userIds []string, roleId string) ([]string, error) {
	var users []string

	for _, userId := range userIds {
		userRoles, err := r.client.UserManagement.CombinedUserRolesV1(
			&user_management.CombinedUserRolesV1Params{
				UserUUID: userId,
				Context:  ctx,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("crowdstrike-connector: failed to get user roles: %w", err)
		}

		// check if user has role
		for _, role := range userRoles.Payload.Resources {
			if *role.RoleID == roleId {
				users = append(users, userId)
			}
		}
	}

	return users, nil
}

func (r *roleResourceType) Grants(ctx context.Context, resource *v2.Resource, pt *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	bag, offset, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, err
	}

	// 1. get all users
	userIds, err := r.client.UserManagement.QueryUserV1(
		&user_management.QueryUserV1Params{
			Limit:   &ResourcesPageSize,
			Offset:  &offset,
			Context: ctx,
		},
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("crowdstrike-connector: failed to list users: %w", err)
	}

	nextPage, err := handleNextPage(bag, offset+ResourcesPageSize)
	if err != nil {
		return nil, "", nil, err
	}

	isLastPage, err := userIds.Payload.Meta.Pagination.LastPage()
	if err != nil {
		return nil, "", nil, err
	}

	if isLastPage {
		nextPage = ""
	}

	// 2. find users that have this role
	targetUserIds, err := r.FindUsersWithRole(ctx, userIds.Payload.Resources, resource.Id.Resource)
	if err != nil {
		return nil, "", nil, err
	}

	if len(targetUserIds) == 0 {
		return nil, nextPage, nil, nil
	}

	// 3. get details for users under fetched ids
	users, err := r.client.UserManagement.RetrieveUsersGETV1(
		&user_management.RetrieveUsersGETV1Params{
			Body: &models.MsaIdsRequest{
				Ids: targetUserIds,
			},
			Context: ctx,
		},
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("crowdstrike-connector: failed to get user details: %w", err)
	}

	// 4. create grants for users
	var rv []*v2.Grant
	for _, user := range users.Payload.Resources {
		userCopy := user

		ur, err := userResource(ctx, userCopy)
		if err != nil {
			return nil, "", nil, err
		}

		rv = append(
			rv,
			grant.NewGrant(
				resource,
				roleMembership,
				ur.Id,
			),
		)
	}

	return rv, nextPage, nil, nil
}

func roleBuilder(client *fClient.CrowdStrikeAPISpecification) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		client:       client,
	}
}
