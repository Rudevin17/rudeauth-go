package rudeauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// testServer is a minimal RudeAuth server that signs and seals exactly as the
// real one does, so the SDK verifies real signatures and opens real payloads.
type testServer struct {
	priv       ed25519.PrivateKey
	pubB64     string
	sessionKey []byte // set during handshake, reused for the gating calls
	fail       string // if set, handshake returns success:false with this code
}

func newTestServer(t *testing.T) (*httptest.Server, *testServer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ts := &testServer{priv: priv, pubB64: base64.StdEncoding.EncodeToString(pub)}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/handshake", ts.handshake)
	mux.HandleFunc("/v1/variables", ts.variables)
	mux.HandleFunc("/v1/files", ts.files)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, ts
}

// respond signs a payload over the exact domain-separated message and writes the
// envelope, exactly like the server.
func (ts *testServer) respond(w http.ResponseWriter, endpoint string, payload any) {
	data, _ := json.Marshal(payload)
	sig := ed25519.Sign(ts.priv, signingInput(endpoint, data))
	_ = json.NewEncoder(w).Encode(envelope{
		Data:      base64.StdEncoding.EncodeToString(data),
		Signature: base64.StdEncoding.EncodeToString(sig),
	})
}

func (ts *testServer) seal(plaintext, aad []byte) string {
	aead, _ := chacha20poly1305.NewX(ts.sessionKey)
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	return base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, plaintext, aad))
}

func (ts *testServer) handshake(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientNonce string `json:"client_nonce"`
		EphPubkey   string `json:"eph_pubkey"`
	}
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &req)

	if ts.fail != "" {
		ts.respond(w, "handshake", handshakePayload{
			Success: false, ClientNonce: req.ClientNonce, ServerTime: time.Now().Unix(), Error: ts.fail,
		})
		return
	}

	clientEph, _ := base64.StdEncoding.DecodeString(req.EphPubkey)
	srvPub, srvPriv, err := ephemeral()
	if err != nil {
		http.Error(w, "eph", http.StatusInternalServerError)
		return
	}
	const sessionID = "test-session-0001"
	key, err := deriveSessionKey(srvPriv, clientEph, sessionID)
	if err != nil {
		http.Error(w, "derive", http.StatusInternalServerError)
		return
	}
	ts.sessionKey = key

	ts.respond(w, "handshake", handshakePayload{
		Success:          true,
		ClientNonce:      req.ClientNonce,
		ServerTime:       time.Now().Unix(),
		SessionToken:     "session-token-xyz",
		SessionExpiresAt: time.Now().Unix() + 3600,
		SessionID:        sessionID,
		ServerEphPubkey:  base64.StdEncoding.EncodeToString(srvPub),
		License:          &LicenseInfo{Level: 1, DevicesUsed: 1, MaxDevices: 1},
	})
}

func (ts *testServer) variables(w http.ResponseWriter, r *http.Request) {
	vars, _ := json.Marshal(map[string]string{"offset": "0x4A1F", "tier": "gold"})
	ts.respond(w, "variables", gatingPayload{Success: true, Sealed: ts.seal(vars, []byte("variables"))})
}

func (ts *testServer) files(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &req)
	payload := []byte("core-dll-bytes")
	ts.respond(w, "files", gatingPayload{Success: true, Version: 1, Sealed: ts.seal(payload, []byte("files:"+req.Name))})
}

func newTestClient(t *testing.T, srv *httptest.Server, ts *testServer) *Client {
	t.Helper()
	c, err := NewClient("app-uuid", ts.pubB64, srv.URL)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Deterministic, machine-independent fingerprint so the test does not depend
	// on the host's real hardware.
	c.collect = func() []string { return []string{"test:cpu", "test:disk"} }
	c.label = func() string { return "test-box" }
	return c
}

// The full path: handshake, session-key derivation, and opening two sealed
// payloads, all with signatures the SDK verifies and AEAD it opens.
func TestAuthenticateAndGating(t *testing.T) {
	srv, ts := newTestServer(t)
	c := newTestClient(t, srv, ts)

	sess, err := c.Authenticate("RUDE-XXXX")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	defer sess.Close()

	if sess.Info().MaxDevices != 1 || sess.Info().Level != 1 {
		t.Errorf("licence info not populated: %+v", sess.Info())
	}

	v, err := sess.Variable("offset")
	if err != nil {
		t.Fatalf("variable: %v", err)
	}
	if v != "0x4A1F" {
		t.Errorf("offset = %q, want 0x4A1F", v)
	}

	f, err := sess.File("core.dll")
	if err != nil {
		t.Fatalf("file: %v", err)
	}
	if string(f) != "core-dll-bytes" {
		t.Errorf("file = %q", f)
	}
}

// A response signed by anything other than the pinned key is refused, before any
// field is read.
func TestAuthenticateRejectsForgedSignature(t *testing.T) {
	srv, _ := newTestServer(t)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	c, err := NewClient("app", base64.StdEncoding.EncodeToString(otherPub), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.collect = func() []string { return []string{"a", "b"} }

	if _, err := c.Authenticate("k"); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("want ErrSignatureInvalid, got %v", err)
	}
}

// A rejected licence surfaces as the specific sentinel, matchable with errors.Is.
func TestAuthenticateMapsLicenceError(t *testing.T) {
	srv, ts := newTestServer(t)
	ts.fail = "LICENSE_EXPIRED"
	c := newTestClient(t, srv, ts)

	if _, err := c.Authenticate("k"); !errors.Is(err, ErrLicenseExpired) {
		t.Fatalf("want ErrLicenseExpired, got %v", err)
	}
}

// Fewer than two readable components and the SDK refuses rather than sending a
// weak identity the server would have to accept.
func TestAuthenticateRefusesWeakFingerprint(t *testing.T) {
	srv, ts := newTestServer(t)
	c := newTestClient(t, srv, ts)
	c.collect = func() []string { return []string{"only-one"} }

	if _, err := c.Authenticate("k"); err == nil {
		t.Fatal("accepted a one-component fingerprint")
	}
}
