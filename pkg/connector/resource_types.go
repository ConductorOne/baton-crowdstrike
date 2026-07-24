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

// userResourceTypeBase carries the fields and annotations common to every
// user resourceType, minus the skip-sync annotation that varies with
// syncRoles -- see userResourceTypeDef.
var userResourceTypeBase = &v2.ResourceType{
	Id:          "user",
	DisplayName: "User",
	Traits: []v2.ResourceType_Trait{
		v2.ResourceType_TRAIT_USER,
	},
	Annotations: annotations.New(
		capabilityPermissions(
			"User Management: Read",
			"User Management: Write",
		),
	),
}

// userResourceTypeDef clones userResourceTypeBase and prepends a skip-sync
// annotation based on whether the role resource type will be synced. The
// user builder emits role-membership grants as a cross-type optimization
// (see Grants() in user.go); when role sync is disabled it has no
// entitlements AND no grants of its own to report, so the sync engine can
// skip calling Entitlements()/Grants() for user resources entirely
// (SkipEntitlementsAndGrants) rather than just Entitlements()
// (SkipEntitlements). Cloning -- rather than mutating userResourceTypeBase
// in place -- keeps every other resourceType consumer (and the package-level
// resourceTypeUser default below) unaffected.
func userResourceTypeDef(syncRoles bool) *v2.ResourceType {
	rt, ok := proto.Clone(userResourceTypeBase).(*v2.ResourceType)
	if !ok {
		panic("baton-crowdstrike: proto.Clone returned unexpected type for *v2.ResourceType")
	}

	var skipAnno proto.Message
	if syncRoles {
		skipAnno = &v2.SkipEntitlements{}
	} else {
		skipAnno = &v2.SkipEntitlementsAndGrants{}
	}

	// Prepend (not append) so the skip annotation leads, matching the
	// ordering every other resourceType in this file uses.
	rt.Annotations = append(annotations.New(skipAnno), rt.GetAnnotations()...)

	return rt
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
