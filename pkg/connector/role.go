package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
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

func (r *roleResourceType) Grants(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

func (r *roleResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Debug(
			"crowdstrike-connector grant: only users can be granted role membership",
			zap.String("principal_id", principal.Id.Resource),
			zap.String("principal_type", principal.Id.ResourceType),
		)

		return nil, uhttp.WrapErrors(codes.InvalidArgument, "only users can be granted role membership")
	}

	userID := principal.Id.Resource
	roleID := entitlement.Resource.Id.Resource

	cid, err := r.userCID(ctx, userID)
	if err != nil {
		return nil, wrapCrowdStrikeError(err, "crowdstrike-connector grant: failed to resolve customer id")
	}

	// The user-role-actions endpoint is idempotent: granting an already-held
	// role returns 200, so no "already exists" special-casing is needed.
	response, err := r.client.UserManagement.UserRolesActionV1(
		&user_management.UserRolesActionV1Params{
			Body: &models.DomainActionUserRolesRequest{
				Action:  "grant",
				Cid:     cid,
				UUID:    userID,
				RoleIds: []string{roleID},
			},
			Context: ctx,
		},
	)
	if err != nil {
		return nil, wrapCrowdStrikeError(err, "crowdstrike-connector grant: failed to assign role membership")
	}

	annos := WithRateLimitAnnotations(
		NewRateLimitInfo(
			response.XRateLimitLimit,
			response.XRateLimitRemaining,
		),
	)

	return annos, nil
}

func (r *roleResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	entitlement := grant.Entitlement
	principal := grant.Principal

	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Debug(
			"crowdstrike-connector revoke: only users can have role membership revoked",
			zap.String("principal_id", principal.Id.Resource),
			zap.String("principal_type", principal.Id.ResourceType),
		)

		return nil, uhttp.WrapErrors(codes.InvalidArgument, "only users can have role membership revoked")
	}

	userID := principal.Id.Resource
	roleID := entitlement.Resource.Id.Resource

	cid, err := r.userCID(ctx, userID)
	if err != nil {
		return nil, wrapCrowdStrikeError(err, "crowdstrike-connector revoke: failed to resolve customer id")
	}

	// The user-role-actions endpoint is idempotent: revoking a role the user
	// does not hold returns 200, so no "already revoked" special-casing is needed.
	response, err := r.client.UserManagement.UserRolesActionV1(
		&user_management.UserRolesActionV1Params{
			Body: &models.DomainActionUserRolesRequest{
				Action:  "revoke",
				Cid:     cid,
				UUID:    userID,
				RoleIds: []string{roleID},
			},
			Context: ctx,
		},
	)
	if err != nil {
		return nil, wrapCrowdStrikeError(err, "crowdstrike-connector revoke: failed to remove role membership")
	}

	// annotations for rate limits
	annos := WithRateLimitAnnotations(
		NewRateLimitInfo(
			response.XRateLimitLimit,
			response.XRateLimitRemaining,
		),
	)

	return annos, nil
}

// userCID resolves the CrowdStrike customer ID (CID) for a user. The
// user-role-actions endpoint requires the CID alongside the user UUID to
// scope the grant/revoke, and CrowdStrike rejects the request without it.
func (r *roleResourceType) userCID(ctx context.Context, userUUID string) (string, error) {
	user, err := getUserByUUID(ctx, r.client, userUUID)
	if err != nil {
		return "", err
	}
	if user.Cid == "" {
		return "", uhttp.WrapErrors(codes.FailedPrecondition, fmt.Sprintf("user %s has no customer id", userUUID))
	}

	return user.Cid, nil
}

func roleBuilder(client *fClient.CrowdStrikeAPISpecification) *roleResourceType {
	return &roleResourceType{
		resourceType: resourceTypeRole,
		client:       client,
	}
}
