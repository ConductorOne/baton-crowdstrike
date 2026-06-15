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
		l.Debug(
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
