// Command test-server is an in-process mock of the CrowdStrike Falcon
// user-management API. It lets the baton-crowdstrike connector run its full
// sync and provisioning lifecycle (create / update / delete users, grant /
// revoke roles) without a real Falcon tenant.
//
// The gofalcon SDK hardcodes HTTPS for both the OAuth token request and all API
// calls, so the server speaks TLS with an in-memory self-signed certificate
// written to test-server-cert.pem on startup. Point SSL_CERT_FILE at that cert
// so the connector trusts it, then run the connector against the server with:
//
//	SSL_CERT_FILE=./test-server-cert.pem ./baton-crowdstrike \
//	  --crowdstrike-client-id test --crowdstrike-client-secret test \
//	  --base-url 127.0.0.1:8443
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	statusActive = "active"
	aliceEmail   = "alice@example.com"
)

type user struct {
	CID       string
	UID       string
	UUID      string
	FirstName string
	LastName  string
	Status    string
	Roles     []string
}

type role struct {
	ID          string
	DisplayName string
	Description string
}

type store struct {
	mu    sync.Mutex
	cid   string
	users map[string]*user // keyed by UUID
	roles map[string]*role // keyed by ID
	seq   int
}

func newStore() *store {
	s := &store{
		cid:   "abcdef1234567890abcdef1234567890",
		users: make(map[string]*user),
		roles: make(map[string]*role),
	}

	s.roles["falcon_administrator"] = &role{ID: "falcon_administrator", DisplayName: "Falcon Administrator", Description: "Full administrative access."}
	s.roles["falcon_analyst"] = &role{ID: "falcon_analyst", DisplayName: "Falcon Analyst", Description: "Read and investigate detections."}
	s.roles["falcon_read_only"] = &role{ID: "falcon_read_only", DisplayName: "Falcon Read Only", Description: "Read-only access."}

	s.users["11111111-1111-1111-1111-111111111111"] = &user{
		CID: s.cid, UID: aliceEmail, UUID: "11111111-1111-1111-1111-111111111111",
		FirstName: "Alice", LastName: "Anderson", Status: statusActive,
		Roles: []string{"falcon_administrator"},
	}
	s.users["22222222-2222-2222-2222-222222222222"] = &user{
		CID: s.cid, UID: "bob@example.com", UUID: "22222222-2222-2222-2222-222222222222",
		FirstName: "Bob", LastName: "Brown", Status: statusActive,
		Roles: []string{"falcon_analyst", "falcon_read_only"},
	}

	return s
}

// --- response models (subset of the Falcon API shapes the SDK parses) ---

type meta struct {
	Pagination *paging `json:"pagination,omitempty"`
}

type paging struct {
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
	Total  int64 `json:"total"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type queryResponse struct {
	Meta      meta       `json:"meta"`
	Resources []string   `json:"resources"`
	Errors    []apiError `json:"errors"`
}

type domainUser struct {
	Cid       string `json:"cid,omitempty"`
	UID       string `json:"uid,omitempty"`
	UUID      string `json:"uuid,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Status    string `json:"status,omitempty"`
}

type userResponse struct {
	Meta      meta         `json:"meta"`
	Resources []domainUser `json:"resources"`
	Errors    []apiError   `json:"errors"`
}

type domainRole struct {
	Cid         string  `json:"cid,omitempty"`
	ID          *string `json:"id"`
	DisplayName *string `json:"display_name"`
	Description *string `json:"description"`
	IsGlobal    *bool   `json:"is_global"`
}

type rolesResponse struct {
	Meta      meta         `json:"meta"`
	Resources []domainRole `json:"resources"`
	Errors    []apiError   `json:"errors"`
}

type domainUserGrant struct {
	Cid    string  `json:"cid,omitempty"`
	UUID   string  `json:"uuid,omitempty"`
	RoleID *string `json:"role_id"`
}

type userGrantResponse struct {
	Meta      meta              `json:"meta"`
	Resources []domainUserGrant `json:"resources"`
	Errors    []apiError        `json:"errors"`
}

type idsResponse struct {
	Meta      meta       `json:"meta"`
	Resources []string   `json:"resources"`
	Errors    []apiError `json:"errors"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-RateLimit-Limit", "6000")
	w.Header().Set("X-RateLimit-Remaining", "5999")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"meta":   meta{},
		"errors": []apiError{{Code: status, Message: message}},
	})
}

func (s *store) handleToken(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusCreated, map[string]any{
		"access_token": "test-access-token",
		"token_type":   "bearer",
		"expires_in":   1799,
	})
}

func (s *store) handleQueryUsers(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	filter := r.URL.Query().Get("filter")
	var ids []string
	for _, u := range s.users {
		if filter != "" && !matchUIDFilter(filter, u.UID) {
			continue
		}
		ids = append(ids, u.UUID)
	}

	writeJSON(w, http.StatusOK, queryResponse{
		Meta:      meta{Pagination: &paging{Limit: 500, Offset: 0, Total: int64(len(ids))}},
		Resources: ids,
	})
}

// matchUIDFilter handles the FQL filter "uid:'value'" used by findUserByEmail.
func matchUIDFilter(filter, uid string) bool {
	const prefix = "uid:"
	if !strings.HasPrefix(filter, prefix) {
		return true
	}
	want := strings.Trim(strings.TrimPrefix(filter, prefix), "'\"")
	return strings.EqualFold(want, uid)
}

func (s *store) handleRetrieveUsers(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var resources []domainUser
	for _, id := range req.IDs {
		if u, ok := s.users[id]; ok {
			resources = append(resources, toDomainUser(u))
		}
	}

	writeJSON(w, http.StatusOK, userResponse{
		Meta:      meta{Pagination: &paging{Limit: 500, Offset: 0, Total: int64(len(resources))}},
		Resources: resources,
	})
}

func (s *store) handleUsersEntity(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleCreateUser(w, r)
	case http.MethodPatch:
		s.handleUpdateUser(w, r)
	case http.MethodDelete:
		s.handleDeleteUser(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *store) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UID       string `json:"uid"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.UID == "" {
		writeError(w, http.StatusBadRequest, "uid is required")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if strings.EqualFold(u.UID, req.UID) {
			writeError(w, http.StatusConflict, "user already exists")
			return
		}
	}

	s.seq++
	u := &user{
		CID:       s.cid,
		UID:       req.UID,
		UUID:      newUUID(s.seq),
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Status:    statusActive,
	}
	s.users[u.UUID] = u

	writeJSON(w, http.StatusCreated, userResponse{
		Meta:      meta{},
		Resources: []domainUser{toDomainUser(u)},
	})
}

func (s *store) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	uuid := r.URL.Query().Get("user_uuid")

	var req struct {
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[uuid]
	if !ok {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	u.FirstName = req.FirstName
	u.LastName = req.LastName

	writeJSON(w, http.StatusOK, userResponse{
		Meta:      meta{},
		Resources: []domainUser{toDomainUser(u)},
	})
}

func (s *store) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	uuid := r.URL.Query().Get("user_uuid")

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[uuid]; !ok {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	delete(s.users, uuid)

	writeJSON(w, http.StatusOK, map[string]any{"meta": meta{}})
}

func (s *store) handleQueryRoles(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var ids []string
	for id := range s.roles {
		ids = append(ids, id)
	}

	writeJSON(w, http.StatusOK, queryResponse{
		Meta:      meta{Pagination: &paging{Limit: 500, Offset: 0, Total: int64(len(ids))}},
		Resources: ids,
	})
}

func (s *store) handleEntitiesRoles(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var resources []domainRole
	for _, id := range r.URL.Query()["ids"] {
		if rl, ok := s.roles[id]; ok {
			resources = append(resources, toDomainRole(rl))
		}
	}

	writeJSON(w, http.StatusOK, rolesResponse{
		Meta:      meta{},
		Resources: resources,
	})
}

func (s *store) handleCombinedUserRoles(w http.ResponseWriter, r *http.Request) {
	uuid := r.URL.Query().Get("user_uuid")

	s.mu.Lock()
	defer s.mu.Unlock()

	var resources []domainUserGrant
	if u, ok := s.users[uuid]; ok {
		for _, roleID := range u.Roles {
			rid := roleID
			resources = append(resources, domainUserGrant{Cid: s.cid, UUID: uuid, RoleID: &rid})
		}
	}

	writeJSON(w, http.StatusOK, userGrantResponse{
		Meta:      meta{Pagination: &paging{Limit: 500, Offset: 0, Total: int64(len(resources))}},
		Resources: resources,
	})
}

func (s *store) handleUserRoles(w http.ResponseWriter, r *http.Request) {
	uuid := r.URL.Query().Get("user_uuid")

	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[uuid]
	if !ok {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	switch r.Method {
	case http.MethodPost:
		var req struct {
			RoleIDs []string `json:"roleIds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid body")
			return
		}
		for _, rid := range req.RoleIDs {
			if !contains(u.Roles, rid) {
				u.Roles = append(u.Roles, rid)
			}
		}
		writeJSON(w, http.StatusOK, idsResponse{Resources: req.RoleIDs})
	case http.MethodDelete:
		ids := r.URL.Query()["ids"]
		for _, rid := range ids {
			u.Roles = remove(u.Roles, rid)
		}
		writeJSON(w, http.StatusOK, idsResponse{Resources: ids})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func toDomainUser(u *user) domainUser {
	return domainUser{
		Cid: u.CID, UID: u.UID, UUID: u.UUID,
		FirstName: u.FirstName, LastName: u.LastName, Status: u.Status,
	}
}

func toDomainRole(r *role) domainRole {
	id, dn, desc, global := r.ID, r.DisplayName, r.Description, true
	return domainRole{Cid: "", ID: &id, DisplayName: &dn, Description: &desc, IsGlobal: &global}
}

func newUUID(seq int) string {
	return strings.ReplaceAll(
		// Deterministic, UUID-shaped identifier for created users.
		"99999999-0000-0000-0000-000000000000",
		"99999999",
		// pad the sequence into the first block.
		padSeq(seq),
	)
}

func padSeq(seq int) string {
	s := big.NewInt(int64(seq)).Text(16)
	for len(s) < 8 {
		s = "0" + s
	}
	return s
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func remove(xs []string, x string) []string {
	out := xs[:0]
	for _, v := range xs {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", "127.0.0.1:8443", "address to listen on")
	certOut := flag.String("cert-out", "test-server-cert.pem", "path to write the self-signed certificate so the connector can trust it via SSL_CERT_FILE")
	flag.Parse()

	s := newStore()

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", s.handleToken)
	mux.HandleFunc("/user-management/queries/users/v1", s.handleQueryUsers)
	mux.HandleFunc("/user-management/entities/users/GET/v1", s.handleRetrieveUsers)
	mux.HandleFunc("/user-management/entities/users/v1", s.handleUsersEntity)
	mux.HandleFunc("/user-management/queries/roles/v1", s.handleQueryRoles)
	mux.HandleFunc("/user-management/entities/roles/v1", s.handleEntitiesRoles)
	mux.HandleFunc("/user-management/combined/user-roles/v1", s.handleCombinedUserRoles)
	mux.HandleFunc("/user-roles/entities/user-roles/v1", s.handleUserRoles)

	cert, certPEM, err := selfSignedCert()
	if err != nil {
		return fmt.Errorf("test-server: failed to generate certificate: %w", err)
	}

	// Bind first; only write the certificate once we own the port. This avoids a
	// second, failed-to-bind instance clobbering the certificate of the server
	// that is actually serving (which causes TLS verification mismatches).
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", *addr)
	if err != nil {
		return fmt.Errorf("test-server: failed to listen on %s: %w", *addr, err)
	}

	if err := os.WriteFile(*certOut, certPEM, 0o600); err != nil {
		return fmt.Errorf("test-server: failed to write certificate to %s: %w", *certOut, err)
	}

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}

	log.Printf("test-server: listening on https://%s", *addr)
	log.Printf("test-server: certificate written to %s", *certOut)
	log.Printf("test-server: run the connector with SSL_CERT_FILE=%s --base-url %s", *certOut, *addr)
	if err := srv.ServeTLS(ln, "", ""); err != nil {
		return fmt.Errorf("test-server: server error: %w", err)
	}

	return nil
}

// selfSignedCert generates a self-signed certificate valid for localhost/127.0.0.1.
// It is marked as a CA so it can be added directly to a trust store (e.g. via
// SSL_CERT_FILE) and validate the server it signs. Returns the TLS certificate
// and its PEM encoding (so the caller can write it to disk for the connector).
func selfSignedCert() (tls.Certificate, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "baton-crowdstrike-test-server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	return tlsCert, certPEM, nil
}
