package connector

import (
	"context"
	"fmt"
	"sync"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	fClient "github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
)

const (
	roleMembership = "member"
)

type roleResourceType struct {
	resourceType *v2.ResourceType
	client       *fClient.CrowdStrikeAPISpecification

	// userRolesCache maps userID -> []roleID. Populated lazily on first
	// FindUsersWithRole call so that all 8 role queries share one cache
	// instead of each making per-user API calls independently.
	userRolesCache map[string][]string
	userRolesMu    sync.Mutex
}

func (r *roleResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return r.resourceType
}

// Create a new connector resource for an CrowdStrike Role.
func roleResource(role *models.DomainRole) (*v2.Resource, error) {
	id, displayName, description := *role.ID, *role.DisplayName, *role.Description

	profile := map[string]any{
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

func (r *roleResourceType) List(ctx context.Context, _ *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	roleIDs, err := r.client.UserManagement.QueriesRolesV1(
		&user_management.QueriesRolesV1Params{
			Context: ctx,
		},
	)
	if err != nil {
		return nil, nil, wrapCrowdStrikeError(err, "role list: failed to query role ids")
	}

	// get details for roles under fetched ids
	roleDetails, err := r.client.UserManagement.EntitiesRolesV1(
		&user_management.EntitiesRolesV1Params{
			Ids:     roleIDs.Payload.Resources,
			Context: ctx,
		},
	)
	if err != nil {
		return nil, nil, wrapCrowdStrikeError(err, "role list: failed to retrieve role details")
	}

	var rv []*v2.Resource
	for _, role := range roleDetails.Payload.Resources {
		ur, err := roleResource(role)

		if err != nil {
			return nil, nil, fmt.Errorf("failed to create role resource: %w", err)
		}

		rv = append(rv, ur)
	}

	// annotations for rate limits
	annos := WithRateLimitAnnotations(
		NewRateLimitInfo(
			roleIDs.XRateLimitLimit,
			roleIDs.XRateLimitRemaining,
		),
		NewRateLimitInfo(
			roleDetails.XRateLimitLimit,
			roleDetails.XRateLimitRemaining,
		),
	)

	return rv, &rs.SyncOpResults{Annotations: annos}, nil
}

func (r *roleResourceType) Entitlements(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
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

	return rv, nil, nil
}

// ensureUserRolesCached fetches roles for the given user IDs and caches them.
// Already-cached users are skipped. This is called per-page of users, and the
// cache persists across all role queries within the same sync.
func (r *roleResourceType) ensureUserRolesCached(ctx context.Context, userIDs []string) ([]RateLimitInfo, error) {
	r.userRolesMu.Lock()
	defer r.userRolesMu.Unlock()

	if r.userRolesCache == nil {
		r.userRolesCache = make(map[string][]string)
	}

	var rateLimitInfo []RateLimitInfo
	for _, userID := range userIDs {
		if _, ok := r.userRolesCache[userID]; ok {
			continue // already cached from a previous role's Grants() call
		}

		userRoles, err := r.client.UserManagement.CombinedUserRolesV1(
			&user_management.CombinedUserRolesV1Params{
				UserUUID: userID,
				Context:  ctx,
			},
		)
		if err != nil {
			return nil, wrapCrowdStrikeError(err, "find users with role: failed to get user roles")
		}

		rateLimitInfo = append(rateLimitInfo, NewRateLimitInfo(
			userRoles.XRateLimitLimit,
			userRoles.XRateLimitRemaining,
		))

		var roleIDs []string
		for _, role := range userRoles.Payload.Resources {
			roleIDs = append(roleIDs, *role.RoleID)
		}
		r.userRolesCache[userID] = roleIDs
	}

	return rateLimitInfo, nil
}

func (r *roleResourceType) FindUsersWithRole(ctx context.Context, userIDs []string, roleId string) ([]string, []RateLimitInfo, error) {
	rlInfo, err := r.ensureUserRolesCached(ctx, userIDs)
	if err != nil {
		return nil, nil, err
	}

	var users []string
	r.userRolesMu.Lock()
	defer r.userRolesMu.Unlock()
	for _, userID := range userIDs {
		for _, cachedRole := range r.userRolesCache[userID] {
			if cachedRole == roleId {
				users = append(users, userID)
				break
			}
		}
	}

	return users, rlInfo, nil
}

func (r *roleResourceType) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	rateLimitInfo := make([]RateLimitInfo, 0)
	bag, offset, err := parsePageToken(opts.PageToken.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, nil, err
	}

	// 1. get all user ids
	userIDs, err := r.client.UserManagement.QueryUserV1(
		&user_management.QueryUserV1Params{
			Limit:   &ResourcesPageSize,
			Offset:  &offset,
			Context: ctx,
		},
	)
	if err != nil {
		return nil, nil, wrapCrowdStrikeError(err, "role grants: failed to query user ids")
	}

	// add rate limit info from listing user ids
	rateLimitInfo = append(
		rateLimitInfo,
		NewRateLimitInfo(
			userIDs.XRateLimitLimit,
			userIDs.XRateLimitRemaining,
		),
	)

	// continue syncing if no users are found
	if len(userIDs.Payload.Resources) == 0 {
		annos := WithRateLimitAnnotations(rateLimitInfo...)

		return nil, &rs.SyncOpResults{Annotations: annos}, nil
	}

	nextPage, err := handleNextPage(bag, offset+ResourcesPageSize)
	if err != nil {
		return nil, nil, err
	}

	isLastPage, err := userIDs.Payload.Meta.Pagination.LastPage()
	if err != nil {
		return nil, nil, err
	}

	if isLastPage {
		nextPage = ""
	}

	// 2. find users that have this role
	targetUserIDs, rlInfo, err := r.FindUsersWithRole(ctx, userIDs.Payload.Resources, resource.Id.Resource)
	if err != nil {
		return nil, nil, err
	}

	// add rate limit info from listing user roles
	rateLimitInfo = append(rateLimitInfo, rlInfo...)

	if len(targetUserIDs) == 0 {
		annos := WithRateLimitAnnotations(rateLimitInfo...)

		return nil, &rs.SyncOpResults{NextPageToken: nextPage, Annotations: annos}, nil
	}

	// 3. get details for users under fetched ids
	users, err := r.client.UserManagement.RetrieveUsersGETV1(
		&user_management.RetrieveUsersGETV1Params{
			Body: &models.MsaspecIdsRequest{
				Ids: targetUserIDs,
			},
			Context: ctx,
		},
	)
	if err != nil {
		return nil, nil, wrapCrowdStrikeError(err, "role grants: failed to retrieve user details")
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
		uID, err := rs.NewResourceID(resourceTypeUser, user.UUID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create user resource id: %w", err)
		}

		rv = append(
			rv,
			grant.NewGrant(
				resource,
				roleMembership,
				uID,
			),
		)
	}

	// annotations for rate limits
	annos := WithRateLimitAnnotations(rateLimitInfo...)

	return rv, &rs.SyncOpResults{NextPageToken: nextPage, Annotations: annos}, nil
}

func (r *roleResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"crowdstrike-connector grant: only users can be granted role membership",
			zap.String("principal_id", principal.Id.Resource),
			zap.String("principal_type", principal.Id.ResourceType),
		)

		return nil, uhttp.WrapErrors(codes.InvalidArgument, "only users can be granted role membership")
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
		// Check if grant already exists (409 Conflict)
		if isConflictError(err) {
			annos := annotations.Annotations{}
			annos.Update(&v2.GrantAlreadyExists{})
			return annos, nil
		}
		return nil, wrapCrowdStrikeError(err, "grant: failed to assign role membership")
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
			"crowdstrike-connector revoke: only users can have role membership revoked",
			zap.String("principal_id", principal.Id.Resource),
			zap.String("principal_type", principal.Id.ResourceType),
		)

		return nil, uhttp.WrapErrors(codes.InvalidArgument, "only users can have role membership revoked")
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
		// Check if grant was already revoked (409 Conflict)
		if isConflictError(err) {
			annos := annotations.Annotations{}
			annos.Update(&v2.GrantAlreadyRevoked{})
			return annos, nil
		}
		return nil, wrapCrowdStrikeError(err, "revoke: failed to remove role membership")
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
