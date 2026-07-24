package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"google.golang.org/protobuf/proto"
)

func capabilityPermissions(perms ...string) *v2.CapabilityPermissions {
	cp := &v2.CapabilityPermissions{}
	for _, p := range perms {
		cp.Permissions = append(cp.Permissions, &v2.CapabilityPermission{Permission: p})
	}
	return cp
}

// userResourceTypeDef builds the user resource type, varying its
// skip-sync annotation based on whether the role resource type will be
// synced. The user builder emits role-membership grants as a cross-type
// optimization (see Grants() in user.go); when role sync is disabled it has
// no entitlements AND no grants of its own to report, so it can skip both
// rather than just entitlements.
func userResourceTypeDef(syncRoles bool) *v2.ResourceType {
	var skipAnno proto.Message
	if syncRoles {
		skipAnno = &v2.SkipEntitlements{}
	} else {
		skipAnno = &v2.SkipEntitlementsAndGrants{}
	}

	return &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: annotations.New(
			skipAnno,
			capabilityPermissions(
				"User Management: Read",
				"User Management: Write",
			),
		),
	}
}

var (
	resourceTypeUser = userResourceTypeDef(true)
	resourceTypeRole = &v2.ResourceType{
		Id:          "role",
		DisplayName: "Role",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_ROLE,
		},
		Annotations: annotations.New(
			&v2.SkipGrants{},
			capabilityPermissions(
				"User Management: Read",
				"User Management: Write",
			),
		),
	}
	resourceTypeSecurityInsight = &v2.ResourceType{
		Id:          "security_insight",
		DisplayName: "Identity Risk Score",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_SECURITY_INSIGHT,
		},
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			&v2.OptInRequired{},
			capabilityPermissions(
				"Identity Protection Entities: Read",
				"Identity Protection GraphQL: Write",
			),
		),
	}
)
