package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	fClient "github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

type userResourceType struct {
	resourceType *v2.ResourceType
	client       *fClient.CrowdStrikeAPISpecification
}

func (u *userResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return u.resourceType
}

// Create a new connector resource for an CrowdStrike User.
func userResource(ctx context.Context, user *models.DomainUser) (*v2.Resource, error) {
	// user `uid` is represented as a username which can also be an email address
	// unique identifier for the user is under `uuid`
	profile := map[string]interface{}{
		"cid":        user.Cid,
		"user_id":    user.UUID,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
	}

	userTraitOptions := []rs.UserTraitOption{
		rs.WithUserProfile(profile),
		rs.WithStatus(v2.UserTrait_Status_STATUS_ENABLED),
	}

	// check if `uid` is an email address
	if validateEmail(user.Email) {
		userTraitOptions = append(userTraitOptions, rs.WithEmail(user.Email, true))
	}

	resource, err := rs.NewUserResource(
		user.Email,
		resourceTypeUser,
		user.UUID,
		userTraitOptions,
	)

	if err != nil {
		return nil, err
	}

	return resource, nil
}

func (u *userResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag, offset, err := parsePageToken(pt.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, "", nil, err
	}

	userIds, err := u.client.UserManagement.QueryUserV1(
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

	// get details for users under fetched ids
	userDetails, err := u.client.UserManagement.RetrieveUsersGETV1(
		&user_management.RetrieveUsersGETV1Params{
			Body: &models.MsaspecIdsRequest{
				Ids: userIds.Payload.Resources,
			},
			Context: ctx,
		},
	)
	if err != nil {
		return nil, "", nil, fmt.Errorf("crowdstrike-connector: failed to get user details: %w", err)
	}

	var rv []*v2.Resource
	for _, user := range userDetails.Payload.Resources {
		userCopy := user
		ur, err := userResource(ctx, userCopy)

		if err != nil {
			return nil, "", nil, err
		}

		rv = append(rv, ur)
	}

	isLastPage, err := userIds.Payload.Meta.Pagination.LastPage()
	if err != nil {
		return nil, "", nil, err
	}

	// annotations for rate limits
	annos := WithRateLimitAnnotations(
		NewRateLimitInfo(
			userIds.XRateLimitLimit,
			userIds.XRateLimitRemaining,
		),
		NewRateLimitInfo(
			userDetails.XRateLimitLimit,
			userDetails.XRateLimitRemaining,
		),
	)

	if isLastPage {
		return rv, "", annos, nil
	}

	return rv, nextPage, annos, nil
}

func (u *userResourceType) Entitlements(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (u *userResourceType) Grants(ctx context.Context, resource *v2.Resource, token *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func userBuilder(client *fClient.CrowdStrikeAPISpecification) *userResourceType {
	return &userResourceType{
		resourceType: resourceTypeUser,
		client:       client,
	}
}
