package connector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

// hasAnnotationType reports whether annos contains a message of the given
// fully-qualified protobuf type URL (e.g.
// "type.googleapis.com/c1.connector.v2.SkipEntitlements").
func hasAnnotationType(annos []*anypb.Any, typeURL string) bool {
	for _, a := range annos {
		if a.GetTypeUrl() == typeURL {
			return true
		}
	}
	return false
}

const (
	skipEntitlementsTypeURL          = "type.googleapis.com/c1.connector.v2.SkipEntitlements"
	skipEntitlementsAndGrantsTypeURL = "type.googleapis.com/c1.connector.v2.SkipEntitlementsAndGrants"
)

// TestUserResourceTypeDef_SyncRolesTrue asserts that when role sync is
// enabled, the user resource type carries SkipEntitlements only -- the sync
// engine will still call Grants() so it can emit role-membership grants (see
// user.go's Grants(), which is unconditional), but Entitlements() is
// correctly skipped since user has no entitlements of its own.
func TestUserResourceTypeDef_SyncRolesTrue(t *testing.T) {
	rt := userBuilder(nil, true).ResourceType(context.Background())

	annos := rt.GetAnnotations()
	require.True(t, hasAnnotationType(annos, skipEntitlementsTypeURL))
	require.False(t, hasAnnotationType(annos, skipEntitlementsAndGrantsTypeURL))
}

// TestUserResourceTypeDef_SyncRolesFalse asserts that when the role resource
// type is excluded from the sync (e.g. via --sync-resource-types user), the
// user resource type carries SkipEntitlementsAndGrants -- the sync engine's
// syncer (pkg/sync/syncer.go's shouldSkipGrants/shouldSkipEntitlementsAndGrants)
// reads this resource-type-level annotation and skips scheduling the
// SyncGrantsOp/SyncEntitlementsOp actions for user resources entirely, so
// Grants() is never even called (see user.go's Grants(), which has no
// in-method guard -- the sync engine is the sole enforcement point).
func TestUserResourceTypeDef_SyncRolesFalse(t *testing.T) {
	rt := userBuilder(nil, false).ResourceType(context.Background())

	annos := rt.GetAnnotations()
	require.True(t, hasAnnotationType(annos, skipEntitlementsAndGrantsTypeURL))
	require.False(t, hasAnnotationType(annos, skipEntitlementsTypeURL))
}

// TestConnector_ZeroValueDefaultsToSyncingRoles guards against a zero-value
// footgun found while wiring this gate: cmd/baton-crowdstrike/main.go's
// WithDefaultCapabilitiesConnectorBuilderV2(&connector.Connector{}) probes
// resource-type capabilities using a bare, never-through-New() zero-value
// Connector. A naively-named `syncRoles bool` field defaults to false on
// that zero value, silently flipping the generated user resource type's
// annotation to SkipEntitlementsAndGrants and desyncing
// baton_capabilities.json from the real default (no --sync-resource-types
// filter => sync everything). The Connector struct instead stores the
// negated `skipRoleGrants`, whose zero value (false) is already correct.
// This test locks that in.
func TestConnector_ZeroValueDefaultsToSyncingRoles(t *testing.T) {
	c := &Connector{}

	var userRT *v2.ResourceType
	for _, syncer := range c.ResourceSyncers(context.Background()) {
		rt := syncer.ResourceType(context.Background())
		if rt.GetId() == resourceTypeUser.GetId() {
			userRT = rt
		}
	}
	require.NotNil(t, userRT, "expected a user resource syncer")

	annos := userRT.GetAnnotations()
	require.True(t, hasAnnotationType(annos, skipEntitlementsTypeURL),
		"expected the default (role-syncing) SkipEntitlements annotation")
	require.False(t, hasAnnotationType(annos, skipEntitlementsAndGrantsTypeURL),
		"zero-value Connector produced SkipEntitlementsAndGrants; role sync must default to enabled")
}

// combinedUserRolesTestServer stands up a minimal HTTPS mock of the two
// gofalcon endpoints Grants() needs: OAuth token issuance and the
// combined-user-roles listing. Response shapes mirror
// test-server/main.go's handleToken and handleCombinedUserRoles (that
// package is `main` and can't be imported directly).
func combinedUserRolesTestServer(t *testing.T, userUUID, roleID string) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "bearer",
			"expires_in":   1799,
		})
	})
	mux.HandleFunc("/user-management/combined/user-roles/v1", func(w http.ResponseWriter, r *http.Request) {
		uuid := r.URL.Query().Get("user_uuid")
		var resources []map[string]any
		if uuid == userUUID {
			resources = append(resources, map[string]any{
				"cid":     "test-cid",
				"uuid":    userUUID,
				"role_id": roleID,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-RateLimit-Limit", "6000")
		w.Header().Set("X-RateLimit-Remaining", "5999")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"meta": map[string]any{
				"pagination": map[string]any{
					"limit":  500,
					"offset": 0,
					"total":  len(resources),
				},
			},
			"resources": resources,
		})
	})

	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{}
	server.StartTLS()
	t.Cleanup(server.Close)

	// gofalcon hardcodes HTTPS for both the token and API requests, so trust
	// the server's self-signed certificate via SSL_CERT_FILE, which Go's
	// crypto/x509 reads when building the system cert pool on unix.
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	certPath := filepath.Join(t.TempDir(), "test-server-cert.pem")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	t.Setenv("SSL_CERT_FILE", certPath)

	return server
}

// TestUserResourceType_Grants_SyncRolesTrue asserts that Grants() returns the
// role-membership grant reported by the combined-user-roles API. Grants()
// has no sync-state guard of its own (see TestUserResourceTypeDef_* above for
// where that's actually enforced), so this exercises its unconditional body.
func TestUserResourceType_Grants_SyncRolesTrue(t *testing.T) {
	const (
		userUUID = "11111111-1111-1111-1111-111111111111"
		roleID   = "falcon_read_only"
	)

	server := combinedUserRolesTestServer(t, userUUID, roleID)
	host := strings.TrimPrefix(server.URL, "https://")

	ctx := context.Background()
	client, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     "test",
		ClientSecret: "test",
		HostOverride: host,
		Context:      ctx,
	})
	require.NoError(t, err)

	u := userBuilder(client, true)

	resourceID, err := rs.NewResourceID(resourceTypeUser, userUUID)
	require.NoError(t, err)
	resource := v2.Resource_builder{Id: resourceID}.Build()

	grants, results, err := u.Grants(ctx, resource, rs.SyncOpAttrs{})
	require.NoError(t, err)
	require.NotNil(t, results)
	require.Len(t, grants, 1)

	// The entitlement name (roleMembership, "member") isn't a standalone
	// field on the built entitlement -- NewGrant folds it into the
	// entitlement ID as "<resource type>:<resource id>:<entitlement name>".
	wantEntitlementID := fmt.Sprintf("%s:%s:%s", resourceTypeRole.GetId(), roleID, roleMembership)
	require.Equal(t, wantEntitlementID, grants[0].GetEntitlement().GetId())
	require.Equal(t, roleID, grants[0].GetEntitlement().GetResource().GetId().GetResource())
	require.Equal(t, resourceTypeRole.GetId(), grants[0].GetEntitlement().GetResource().GetId().GetResourceType())
	require.Equal(t, userUUID, grants[0].GetPrincipal().GetId().GetResource())
}
