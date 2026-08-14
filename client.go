// Package rudeauth is the Go client SDK for a RudeAuth licensing server.
//
// The client embeds only an application id and an Ed25519 public key. Every
// response is signed and verified against that key before any field of it is
// trusted, so a patched binary cannot be talked into a forged "success", and
// there is deliberately no function that returns a bool meaning "is licensed":
// Authenticate returns a *Session or an error, and the gating calls exist only
// on a *Session.
package rudeauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	maxResponseBytes = 32 << 20 // encrypted files can be large
	maxClockSkewSec  = 300
	minComponents    = 2
	defaultTimeout   = 15 * time.Second
)

// Client holds the pinned public key and talks to one RudeAuth server.
type Client struct {
	appID      string
	pub        ed25519.PublicKey
	baseURL    string
	appVersion string
	http       *http.Client

	// collect and label produce the hardware fingerprint. They are fields so a
	// test can inject deterministic values rather than reading real hardware.
	collect func() []string
	label   func() string
}

// Option configures a Client.
type Option func(*Client)

// WithTimeout sets the per-request timeout. The default is 15 seconds.
func WithTimeout(d time.Duration) Option { return func(c *Client) { c.http.Timeout = d } }

// WithAppVersion sets the app_version string reported to the server.
func WithAppVersion(v string) Option { return func(c *Client) { c.appVersion = v } }

// NewClient builds a client. appID and publicKeyB64 come from
// `rudeauth-cli app create`; both are safe to embed, because the public key
// verifies responses and cannot forge them.
func NewClient(appID, publicKeyB64, baseURL string, opts ...Option) (*Client, error) {
	pub, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("rudeauth: public key must be a base64 %d-byte Ed25519 key", ed25519.PublicKeySize)
	}
	c := &Client{
		appID:      appID,
		pub:        ed25519.PublicKey(pub),
		baseURL:    strings.TrimRight(baseURL, "/"),
		appVersion: "1.0.0",
		http:       &http.Client{Timeout: defaultTimeout},
		collect:    fingerprintCollect,
		label:      fingerprintLabel,
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// callEndpoint posts body and returns the VERIFIED payload bytes. There is no
// path through this function that yields unverified data.
func (c *Client) callEndpoint(ctx context.Context, path, endpoint string, body any) ([]byte, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("rudeauth: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("rudeauth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetwork, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// A non-200 carries no signed envelope, so nothing about it can be trusted.
		return nil, fmt.Errorf("%w: http status %d", ErrBadResponse, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetwork, err)
	}

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, ErrBadResponse
	}
	data, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil || len(data) == 0 {
		return nil, ErrBadResponse
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) == 0 {
		return nil, ErrBadResponse
	}

	// STEP ONE, before anything is parsed: the bytes must be signed by the key
	// pinned into this client. Everything downstream depends on it, and there is
	// no flag to skip it.
	if !verify(c.pub, endpoint, data, sig) {
		return nil, ErrSignatureInvalid
	}
	return data, nil
}

// Authenticate performs the handshake and returns a live Session, or an error.
// A rejected licence is a specific error (see the Err values), never a bool.
func (c *Client) Authenticate(licenseKey string) (*Session, error) {
	return c.AuthenticateContext(context.Background(), licenseKey)
}

// AuthenticateContext is Authenticate with a caller-supplied context governing
// the handshake request.
func (c *Client) AuthenticateContext(ctx context.Context, licenseKey string) (*Session, error) {
	components := c.collect()
	if len(components) < minComponents {
		// Refusing beats sending a weak identity the server would have to accept.
		return nil, fmt.Errorf("rudeauth: could not read enough hardware components (%d, need %d)", len(components), minComponents)
	}
	ephPub, ephPriv, err := ephemeral()
	if err != nil {
		return nil, fmt.Errorf("rudeauth: ephemeral key: %w", err)
	}
	nonceRaw, err := randomNonce()
	if err != nil {
		return nil, fmt.Errorf("rudeauth: rng: %w", err)
	}
	nonceB64 := base64.StdEncoding.EncodeToString(nonceRaw)

	data, err := c.callEndpoint(ctx, "/v1/handshake", "handshake", map[string]any{
		"app_id":                 c.appID,
		"app_version":            c.appVersion,
		"license_key":            licenseKey,
		"fingerprint_components": components,
		"fingerprint_label":      c.label(),
		"client_nonce":           nonceB64,
		"eph_pubkey":             base64.StdEncoding.EncodeToString(ephPub),
		"sent_at":                time.Now().Unix(),
	})
	if err != nil {
		return nil, err
	}

	var hs handshakePayload
	if err := json.Unmarshal(data, &hs); err != nil {
		return nil, ErrBadResponse
	}
	// The echoed nonce proves this response was produced for THIS request and is
	// not a recording of an earlier one.
	if hs.ClientNonce != nonceB64 {
		return nil, ErrNonceMismatch
	}
	if hs.ServerTime > 0 {
		if delta := time.Now().Unix() - hs.ServerTime; delta > maxClockSkewSec || delta < -maxClockSkewSec {
			return nil, ErrClockSkew
		}
	}
	if !hs.Success {
		return nil, wireError(hs.Error)
	}

	serverEph, err := base64.StdEncoding.DecodeString(hs.ServerEphPubkey)
	if err != nil {
		return nil, ErrBadResponse
	}
	key, err := deriveSessionKey(ephPriv, serverEph, hs.SessionID)
	if err != nil {
		return nil, ErrBadResponse
	}

	var info LicenseInfo
	if hs.License != nil {
		info = *hs.License
	}
	return newSession(c, hs.SessionToken, key, info, hs.SessionExpiresAt), nil
}
