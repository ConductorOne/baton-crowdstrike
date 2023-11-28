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
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
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
func roleResource(ctx context.Context, role *models.DomainRole) (*v2.Resource, error) {
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

	// annotations for rate limits
	annos := WithRateLimitAnnotations(
		NewRateLimitInfo(
			roleIds.XRateLimitLimit,
			roleIds.XRateLimitRemaining,
		),
		NewRateLimitInfo(
			roleDetails.XRateLimitLimit,
			roleDetails.XRateLimitRemaining,
		),
	)

	return rv, "", annos, nil
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

func (r *roleResourceType) FindUsersWithRole(ctx context.Context, userIds []string, roleId string) ([]string, []RateLimitInfo, error) {
	rateLimitInfo := make([]RateLimitInfo, len(userIds))

	var users []string
	for _, userId := range userIds {
		userRoles, err := r.client.UserManagement.CombinedUserRolesV1(
			&user_management.CombinedUserRolesV1Params{
				UserUUID: userId,
				Context:  ctx,
			},
		)
		if err != nil {
			return nil, nil, fmt.Errorf("crowdstrike-connector: failed to get user roles: %w", err)
		}

		rateLimitInfo = append(
			rateLimitInfo,
			NewRateLimitInfo(
				userRoles.XRateLimitLimit,
				userRoles.XRateLimitRemaining,
			),
		)

		// check if user has role
		for _, role := range userRoles.Payload.Resources {
			if *role.RoleID == roleId {
				users = append(users, userId)
			}
		}
	}

	return users, rateLimitInfo, nil
}

func (r *roleResourceType) Grants(ctx context.Context, resource *v2.Resource, pt *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	rateLimitInfo := make([]RateLimitInfo, 0)
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

	// add rate limit info from listing users
	rateLimitInfo = append(
		rateLimitInfo,
		NewRateLimitInfo(
			userIds.XRateLimitLimit,
			userIds.XRateLimitRemaining,
		),
	)

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
	targetUserIds, rlInfo, err := r.FindUsersWithRole(ctx, userIds.Payload.Resources, resource.Id.Resource)
	if err != nil {
		return nil, "", nil, err
	}

	// add rate limit info from listing user roles
	rateLimitInfo = append(rateLimitInfo, rlInfo...)

	if len(targetUserIds) == 0 {
		annos := WithRateLimitAnnotations(rateLimitInfo...)

		return nil, nextPage, annos, nil
	}

	// 3. get details for users under fetched ids
	users, err := r.client.UserManagement.RetrieveUsersGETV1(
		&user_management.RetrieveUsersGETV1Params{
			Body: &models.MsaspecIdsRequest{
				Ids: targetUserIds,
			},
			Context: ctx,
		},
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("crowdstrike-connector: failed to get user details: %w", err)
	}

	// add rate limit info from listing user details
	rateLimitInfo = append(
		rateLimitInfo,
		NewRateLimitInfo(
			users.XRateLimitLimit,
			users.XRateLimitRemaining,
		),
	)

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

	// annotations for rate limits
	annos := WithRateLimitAnnotations(rateLimitInfo...)

	return rv, nextPage, annos, nil
}

func (r *roleResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"crowdstrike-connector: only users can be granted role membership",
			zap.String("principal_id", principal.Id.Resource),
			zap.String("principal_type", principal.Id.ResourceType),
		)

		return nil, fmt.Errorf("crowdstrike-connector: only users can be granted role membership")
	}

	roleId := entitlement.Resource.Id.Resource

	// grant role membership
	grantResponse, err := r.client.UserManagement.GrantUserRoleIds(
		&user_management.GrantUserRoleIdsParams{
			UserUUID: principal.Id.Resource,
			Body: &models.DomainRoleIDs{
				RoleIds: []string{roleId},
			},
			Context: ctx,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("crowdstrike-connector: failed to grant role membership: %w", err)
	}

	// annotations for rate limits
	annos := WithRateLimitAnnotations(
		NewRateLimitInfo(
			grantResponse.XRateLimitLimit,
			grantResponse.XRateLimitRemaining,
		),
	)

	return annos, nil
}

func (r *roleResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	entitlement := grant.Entitlement
	principal := grant.Principal

	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"crowdstrike-connector: only users can have role membership revoked",
			zap.String("principal_id", principal.Id.Resource),
			zap.String("principal_type", principal.Id.ResourceType),
		)

		return nil, fmt.Errorf("crowdstrike-connector: only users can have role membership revoked")
	}

	roleId := entitlement.Resource.Id.Resource

	// revoke role membership
	revokeResponse, err := r.client.UserManagement.RevokeUserRoleIds(
		&user_management.RevokeUserRoleIdsParams{
			UserUUID: principal.Id.Resource,
			Ids:      []string{roleId},
			Context:  ctx,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("crowdstrike-connector: failed to revoke role membership: %w", err)
	}

	// annotations for rate limits
	annos := WithRateLimitAnnotations(
		NewRateLimitInfo(
			revokeResponse.XRateLimitLimit,
			revokeResponse.XRateLimitRemaining,
		),
	)

	return annos, nil
}

func roleBuilder(client *fClient.CrowdStrikeAPISpecification) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		client:       client,
	}
}
