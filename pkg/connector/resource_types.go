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
	// resourceTypeMCPServer models an unsanctioned ("shadow") Model Context Protocol
	// server observed running on an endpoint via CrowdStrike EDR detections. It carries
	// a full App-trait profile (server, endpoint, and resolved-identity metadata) and a
	// security-insight annotation binding the finding to the identity's c1 risk.
	resourceTypeMCPServer = &v2.ResourceType{
		Id:          "mcp_server",
		DisplayName: "Shadow MCP Server",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_APP,
			v2.ResourceType_TRAIT_SECURITY_INSIGHT,
		},
		Annotations: annotations.New(
			capabilityPermissions(
				"Alerts: Read",
				"Identity Protection Entities: Read",
				"Identity Protection GraphQL: Write",
			),
		),
	}
	// resourceTypeEndpointUser is the endpoint OS user that ran a shadow MCP server,
	// modeled as an app account so it can be assigned to a ConductorOne identity and
	// shown against the mcp_server resources it ran (grant principal only).
	resourceTypeEndpointUser = &v2.ResourceType{
		Id:          "endpoint_user",
		DisplayName: "Endpoint User",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_USER,
		},
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			capabilityPermissions(
				"Alerts: Read",
				"Identity Protection Entities: Read",
			),
		),
	}
	// resourceTypeAITool models an AI coding tool ("harness" — Claude Code, Cursor,
	// codex, etc.) observed running on an endpoint via CrowdStrike EDR detections. It
	// carries an App-trait inventory profile (tool, endpoint, and resolved-identity
	// metadata) and a low-severity security-insight annotation associating the tool with
	// the identity that ran it. This is governance visibility, not a threat finding.
	resourceTypeAITool = &v2.ResourceType{
		Id:          "ai_tool",
		DisplayName: "AI Coding Tool",
		Traits: []v2.ResourceType_Trait{
			v2.ResourceType_TRAIT_APP,
			v2.ResourceType_TRAIT_SECURITY_INSIGHT,
		},
		Annotations: annotations.New(
			&v2.SkipEntitlementsAndGrants{},
			capabilityPermissions(
				"Alerts: Read",
				"Identity Protection Entities: Read",
				"Identity Protection GraphQL: Write",
			),
		),
	}
)
