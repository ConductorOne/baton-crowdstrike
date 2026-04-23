package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

func capabilityPermissions(perms ...string) *v2.CapabilityPermissions {
	cp := &v2.CapabilityPermissions{}
	for _, p := range perms {
		cp.Permissions = append(cp.Permissions, &v2.CapabilityPermission{Permission: p})
	}
	return cp
}

var (
	resourceTypeUser = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: annotations.New(
			&v2.SkipEntitlements{},
			capabilityPermissions(
				"User Management: Read",
				"User Management: Write",
			),
		),
	}
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
