package connector

import (
	"context"
	"fmt"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	fClient "github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"google.golang.org/grpc/codes"
)

var userGrantsPageSize int64 = 500

const (
	actionUpdateUser    = "update_user"
	actionUpdateProfile = "update_profile"

	profileFieldFirstName = "first_name"
	profileFieldLastName  = "last_name"

	argUserID          = "user_id"
	returnFieldSuccess = "success"
)

var (
	_ connectorbuilder.AccountManagerV2       = (*userResourceType)(nil)
	_ connectorbuilder.ResourceDeleterLimited = (*userResourceType)(nil)
)

type userResourceType struct {
	resourceType *v2.ResourceType
	client       *fClient.CrowdStrikeAPISpecification
}

func (u *userResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return u.resourceType
}

// userResource converts a CrowdStrike user into a Baton user resource. CrowdStrike
// uses uid as the login/email and uuid as the stable resource ID.
func userResource(user *models.DomainUser) (*v2.Resource, error) {
	profile := map[string]any{
		"cid":                 user.Cid,
		"login":               user.UID,
		argUserID:             user.UUID,
		profileFieldFirstName: user.FirstName,
		profileFieldLastName:  user.LastName,
	}

	var status v2.Status_ResourceStatus
	switch user.Status {
	case "active":
		status = v2.Status_RESOURCE_STATUS_ENABLED
	case "inactive":
		status = v2.Status_RESOURCE_STATUS_DISABLED
	default:
		status = v2.Status_RESOURCE_STATUS_UNSPECIFIED
	}

	var userTraitOptions []rs.UserTraitOption
	resourceOpts := []rs.ResourceOption{
		rs.WithResourceProfile(profile),
		rs.WithResourceStatus(status, ""),
	}

	if !user.LastLoginAt.IsZero() {
		userTraitOptions = append(userTraitOptions, rs.WithLastLogin(time.Time(user.LastLoginAt)))
	}

	if validateEmail(user.UID) {
		userTraitOptions = append(userTraitOptions, rs.WithEmail(user.UID, true))
	}

	resource, err := rs.NewUserResource(
		user.UID,
		resourceTypeUser,
		user.UUID,
		userTraitOptions,
		resourceOpts...,
	)

	if err != nil {
		return nil, err
	}

	return resource, nil
}

// List returns CrowdStrike users by first querying UUIDs and then fetching full
// user details for the current page.
func (u *userResourceType) List(ctx context.Context, _ *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	bag, offset, err := parsePageToken(opts.PageToken.Token, &v2.ResourceId{ResourceType: resourceTypeUser.Id})
	if err != nil {
		return nil, nil, err
	}

	userIDs, err := u.client.UserManagement.QueryUserV1(
		&user_management.QueryUserV1Params{
			Limit:   &ResourcesPageSize,
			Offset:  &offset,
			Context: ctx,
		},
	)
	if err != nil {
		return nil, nil, wrapCrowdStrikeError(err, "user list: failed to query user ids")
	}

	var rateLimitInfo []RateLimitInfo

	rateLimitInfo = append(
		rateLimitInfo,
		NewRateLimitInfo(
			userIDs.XRateLimitLimit,
			userIDs.XRateLimitRemaining,
		),
	)

	if len(userIDs.Payload.Resources) == 0 {
		annos := WithRateLimitAnnotations(rateLimitInfo...)

		return nil, &rs.SyncOpResults{Annotations: annos}, nil
	}

	nextPage, err := handleNextPage(bag, offset+ResourcesPageSize)
	if err != nil {
		return nil, nil, err
	}

	userDetails, err := u.client.UserManagement.RetrieveUsersGETV1(
		&user_management.RetrieveUsersGETV1Params{
			Body: &models.MsaspecIdsRequest{
				Ids: userIDs.Payload.Resources,
			},
			Context: ctx,
		},
	)
	if err != nil {
		return nil, nil, wrapCrowdStrikeError(err, "user list: failed to retrieve user details")
	}

	var rv []*v2.Resource
	for _, user := range userDetails.Payload.Resources {
		ur, err := userResource(user)

		if err != nil {
			return nil, nil, err
		}

		rv = append(rv, ur)
	}

	if userIDs.Payload.Meta.Pagination == nil {
		annos := WithRateLimitAnnotations(rateLimitInfo...)
		return rv, &rs.SyncOpResults{Annotations: annos}, nil
	}

	isLastPage, err := userIDs.Payload.Meta.Pagination.LastPage()
	if err != nil {
		return nil, nil, err
	}

	rateLimitInfo = append(
		rateLimitInfo,
		NewRateLimitInfo(
			userDetails.XRateLimitLimit,
			userDetails.XRateLimitRemaining,
		),
	)

	annos := WithRateLimitAnnotations(rateLimitInfo...)

	if isLastPage {
		return rv, &rs.SyncOpResults{Annotations: annos}, nil
	}

	return rv, &rs.SyncOpResults{NextPageToken: nextPage, Annotations: annos}, nil
}

// Entitlements returns no user-level entitlements; roles own grantable permissions.
func (u *userResourceType) Entitlements(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants emits role memberships assigned to the CrowdStrike user.
func (u *userResourceType) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	userID := resource.Id.Resource

	bag, offset, err := parsePageToken(opts.PageToken.Token, resource.Id)
	if err != nil {
		return nil, nil, err
	}

	resp, err := u.client.UserManagement.CombinedUserRolesV1(
		&user_management.CombinedUserRolesV1Params{
			UserUUID: userID,
			Limit:    &userGrantsPageSize,
			Offset:   &offset,
			Context:  ctx,
		},
	)
	if err != nil {
		return nil, nil, wrapCrowdStrikeError(err, "user grants: failed to query user roles")
	}

	var rv []*v2.Grant
	for _, roleGrant := range resp.Payload.Resources {
		roleResID, err := rs.NewResourceID(resourceTypeRole, *roleGrant.RoleID)
		if err != nil {
			return nil, nil, fmt.Errorf("user grants: failed to create role resource id: %w", err)
		}

		roleRes := v2.Resource_builder{Id: roleResID}.Build()
		rv = append(rv, grant.NewGrant(roleRes, roleMembership, resource))
	}

	annos := WithRateLimitAnnotations(NewRateLimitInfo(resp.XRateLimitLimit, resp.XRateLimitRemaining))

	if resp.Payload.Meta.Pagination == nil {
		return rv, &rs.SyncOpResults{Annotations: annos}, nil
	}

	isLastPage, err := resp.Payload.Meta.Pagination.LastPage()
	if err != nil {
		return nil, nil, err
	}

	if isLastPage {
		return rv, &rs.SyncOpResults{Annotations: annos}, nil
	}

	nextPage, err := handleNextPage(bag, offset+userGrantsPageSize)
	if err != nil {
		return nil, nil, err
	}

	return rv, &rs.SyncOpResults{NextPageToken: nextPage, Annotations: annos}, nil
}

// findUserByEmail resolves a CrowdStrike user by uid/email. CreateAccount uses
// this when CrowdStrike reports a duplicate or returns an incomplete create body.
func (u *userResourceType) findUserByEmail(ctx context.Context, email string) (*models.DomainUser, error) {
	filter := fmt.Sprintf("uid:'%s'", email)
	var limit int64 = 1

	ids, err := u.client.UserManagement.QueryUserV1(
		&user_management.QueryUserV1Params{
			Filter:  &filter,
			Limit:   &limit,
			Context: ctx,
		},
	)
	if err != nil {
		return nil, err
	}
	if ids.Payload == nil || len(ids.Payload.Resources) == 0 {
		return nil, uhttp.WrapErrors(codes.NotFound, fmt.Sprintf("user with email %s not found", email))
	}

	return u.getUserByUUID(ctx, ids.Payload.Resources[0])
}

// getUserByUUID retrieves a single CrowdStrike user's full details by UUID.
func (u *userResourceType) getUserByUUID(ctx context.Context, uuid string) (*models.DomainUser, error) {
	return getUserByUUID(ctx, u.client, uuid)
}

func getUserByUUID(ctx context.Context, client *fClient.CrowdStrikeAPISpecification, uuid string) (*models.DomainUser, error) {
	details, err := client.UserManagement.RetrieveUsersGETV1(
		&user_management.RetrieveUsersGETV1Params{
			Body: &models.MsaspecIdsRequest{
				Ids: []string{uuid},
			},
			Context: ctx,
		},
	)
	if err != nil {
		return nil, err
	}
	if details.Payload == nil || len(details.Payload.Resources) == 0 {
		return nil, uhttp.WrapErrors(codes.NotFound, fmt.Sprintf("user %s not found", uuid))
	}

	return details.Payload.Resources[0], nil
}

// updateUserProfile updates first and/or last name, backfilling the omitted
// name so a partial update never clears the other field.
func updateUserProfile(ctx context.Context, client *fClient.CrowdStrikeAPISpecification, userID, firstName, lastName string) (annotations.Annotations, []string, error) {
	if firstName == "" && lastName == "" {
		return nil, nil, uhttp.WrapErrors(codes.InvalidArgument, "baton-crowdstrike: update profile: at least one of first_name or last_name is required")
	}

	updatedFields := make([]string, 0, 2)
	if firstName != "" {
		updatedFields = append(updatedFields, profileFieldFirstName)
	}
	if lastName != "" {
		updatedFields = append(updatedFields, profileFieldLastName)
	}

	// Only fetch the current user when a name is omitted: CrowdStrike replaces
	// both fields on update, so we backfill the missing one to avoid clearing it.
	if firstName == "" || lastName == "" {
		current, err := getUserByUUID(ctx, client, userID)
		if err != nil {
			return nil, nil, wrapCrowdStrikeError(err, fmt.Sprintf("baton-crowdstrike: update profile: failed to fetch user %s", userID))
		}
		if firstName == "" {
			firstName = current.FirstName
		}
		if lastName == "" {
			lastName = current.LastName
		}
	}

	resp, err := client.UserManagement.UpdateUserV1(
		&user_management.UpdateUserV1Params{
			UserUUID: userID,
			Body: &models.DomainUpdateUserRequest{
				FirstName: firstName,
				LastName:  lastName,
			},
			Context: ctx,
		},
	)
	if err != nil {
		return nil, nil, wrapCrowdStrikeError(err, fmt.Sprintf("baton-crowdstrike: update profile: failed to update user %s", userID))
	}

	annos := WithRateLimitAnnotations(NewRateLimitInfo(resp.XRateLimitLimit, resp.XRateLimitRemaining))

	return annos, updatedFields, nil
}

// CreateAccountCapabilityDetails advertises passwordless account creation. The
// CrowdStrike API recommends omitting passwords and sends an activation email.
func (u *userResourceType) CreateAccountCapabilityDetails(_ context.Context) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	return &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
	}, nil, nil
}

// CreateAccount provisions a CrowdStrike user and returns AlreadyExistsResult
// when uid/email already exists, matching C1 account-provisioning idempotency.
func (u *userResourceType) CreateAccount(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	_ *v2.LocalCredentialOptions,
) (connectorbuilder.CreateAccountResponse, []*v2.PlaintextData, annotations.Annotations, error) {
	profile := accountInfo.GetProfile().AsMap()

	email, _ := profile["email"].(string)
	if !validateEmail(email) {
		if login := accountInfo.GetLogin(); validateEmail(login) {
			email = login
		}
	}
	if !validateEmail(email) {
		return nil, nil, nil, uhttp.WrapErrors(codes.InvalidArgument, "create account: a valid email address is required for the CrowdStrike uid")
	}

	firstName, _ := profile[profileFieldFirstName].(string)
	lastName, _ := profile[profileFieldLastName].(string)

	created, err := u.client.UserManagement.CreateUserV1(
		&user_management.CreateUserV1Params{
			Body: &models.DomainCreateUserRequest{
				UID:       email,
				FirstName: firstName,
				LastName:  lastName,
			},
			Context: ctx,
		},
	)

	alreadyExists := err != nil && isConflictError(err)
	if err != nil && !alreadyExists {
		return nil, nil, nil, wrapCrowdStrikeError(err, fmt.Sprintf("create account: failed to create user %s", email))
	}

	var domainUser *models.DomainUser
	if !alreadyExists && created != nil && created.Payload != nil && len(created.Payload.Resources) > 0 {
		domainUser = created.Payload.Resources[0]
	}
	if domainUser == nil || domainUser.UUID == "" {
		domainUser, err = u.findUserByEmail(ctx, email)
		if err != nil {
			return nil, nil, nil, wrapCrowdStrikeError(err, fmt.Sprintf("create account: failed to fetch user %s", email))
		}
	}

	resource, err := userResource(domainUser)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("baton-crowdstrike: create account: failed to build resource: %w", err)
	}

	if alreadyExists {
		return &v2.CreateAccountResponse_AlreadyExistsResult{Resource: resource}, nil, nil, nil
	}

	return &v2.CreateAccountResponse_SuccessResult{Resource: resource}, nil, nil, nil
}

// Delete permanently removes a CrowdStrike user. CrowdStrike's REST API has no
// disable/deactivate flag, so not-found is treated as an already-deleted success.
func (u *userResourceType) Delete(ctx context.Context, resourceId *v2.ResourceId) (annotations.Annotations, error) {
	resp, err := u.client.UserManagement.DeleteUserV1(
		&user_management.DeleteUserV1Params{
			UserUUID: resourceId.Resource,
			Context:  ctx,
		},
	)
	if err != nil {
		if isNotFoundError(err) {
			return nil, nil
		}
		return nil, wrapCrowdStrikeError(err, fmt.Sprintf("delete: failed to delete user %s", resourceId.Resource))
	}

	annos := WithRateLimitAnnotations(NewRateLimitInfo(resp.XRateLimitLimit, resp.XRateLimitRemaining))

	return annos, nil
}

func userBuilder(client *fClient.CrowdStrikeAPISpecification) *userResourceType {
	return &userResourceType{
		resourceType: resourceTypeUser,
		client:       client,
	}
}
