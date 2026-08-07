package connector

import (
	"context"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"google.golang.org/protobuf/proto"
)

func hasGuardAnno(rt *v2.ResourceType, msg proto.Message) bool {
	for _, a := range rt.GetAnnotations() {
		if a.MessageIs(msg) {
			return true
		}
	}
	return false
}

// The user type's only grants are cross-type role grants, so when role is
// excluded the whole grants pass is skipped.
func TestUserResourceType_SkipAnnotation(t *testing.T) {
	inScope := userBuilder(nil, false).ResourceType(context.Background())
	if !hasGuardAnno(inScope, &v2.SkipEntitlements{}) || hasGuardAnno(inScope, &v2.SkipEntitlementsAndGrants{}) {
		t.Fatalf("role in scope: want SkipEntitlements only, got %v", inScope.GetAnnotations())
	}

	filtered := userBuilder(nil, true).ResourceType(context.Background())
	if !hasGuardAnno(filtered, &v2.SkipEntitlementsAndGrants{}) {
		t.Fatalf("role filtered: want SkipEntitlementsAndGrants, got %v", filtered.GetAnnotations())
	}

	if hasGuardAnno(resourceTypeUser, &v2.SkipEntitlementsAndGrants{}) {
		t.Fatal("package-level resourceTypeUser was mutated")
	}
}

// main.go registers a zero-value Connector{} as the capabilities factory, which
// bypasses New; it must report the unfiltered capability set.
func TestZeroValueConnector_DoesNotSkipGrants(t *testing.T) {
	for _, s := range (&Connector{}).ResourceSyncers(context.Background()) {
		rt := s.ResourceType(context.Background())
		if rt.GetId() != resourceTypeUser.GetId() {
			continue
		}
		if hasGuardAnno(rt, &v2.SkipEntitlementsAndGrants{}) {
			t.Fatal("zero-value Connector advertised SkipEntitlementsAndGrants")
		}
	}
}
