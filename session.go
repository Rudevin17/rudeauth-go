package rudeauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Session is an authenticated, live connection to the server. It heartbeats on
// its own goroutine from construction. Close stops the heartbeat and zeroes the
// session key.
type Session struct {
	c     *Client
	token string

	mu        sync.Mutex
	key       []byte
	info      LicenseInfo
	expiresAt int64
	closed    bool

	stop     chan struct{}
	stopOnce sync.Once
}

func newSession(c *Client, token string, key []byte, info LicenseInfo, expiresAt int64) *Session {
	s := &Session{c: c, token: token, key: key, info: info, expiresAt: expiresAt, stop: make(chan struct{})}
	go s.beatLoop()
	return s
}

// Info returns what the server reported about the licence at handshake.
func (s *Session) Info() LicenseInfo { return s.info }

// Close stops the heartbeat and zeroes the session key. It is safe to call more
// than once.
func (s *Session) Close() {
	s.stopOnce.Do(func() { close(s.stop) })
	s.mu.Lock()
	s.closed = true
	zero(s.key)
	s.mu.Unlock()
}

// Variable returns a server-side value, fetched fresh. There is no cache and no
// fallback: a cached "last known good" value is exactly what an attacker
// induces by blocking the network.
func (s *Session) Variable(name string) (string, error) {
	data, err := s.sealedCall(context.Background(), "/v1/variables", "variables",
		map[string]any{"app_id": s.c.appID, "session_token": s.token}, []byte("variables"))
	if err != nil {
		return "", err
	}
	var vars map[string]string
	if err := json.Unmarshal(data, &vars); err != nil {
		return "", ErrBadResponse
	}
	v, ok := vars[name]
	if !ok {
		return "", fmt.Errorf("rudeauth: no such variable: %s", name)
	}
	return v, nil
}

// File returns a decrypted payload that never shipped inside your binary.
func (s *Session) File(name string) ([]byte, error) {
	return s.sealedCall(context.Background(), "/v1/files", "files",
		map[string]any{"app_id": s.c.appID, "session_token": s.token, "name": name},
		[]byte("files:"+name))
}

// Webhook asks the server to call one of your configured endpoints, so the URL
// never appears in your binary.
func (s *Session) Webhook(name string, params map[string]string) (string, error) {
	data, err := s.c.callEndpoint(context.Background(), "/v1/webhook", "webhook",
		map[string]any{"app_id": s.c.appID, "session_token": s.token, "name": name, "params": params})
	if err != nil {
		return "", err
	}
	var wp webhookPayload
	if err := json.Unmarshal(data, &wp); err != nil {
		return "", ErrBadResponse
	}
	if !wp.Success {
		return "", wireError(wp.Error)
	}
	decoded, err := base64.StdEncoding.DecodeString(wp.Body)
	if err != nil {
		return "", ErrBadResponse
	}
	return string(decoded), nil
}

// sealedCall performs a gating request and opens the returned payload under the
// session key.
func (s *Session) sealedCall(ctx context.Context, path, endpoint string, body any, aad []byte) ([]byte, error) {
	data, err := s.c.callEndpoint(ctx, path, endpoint, body)
	if err != nil {
		return nil, err
	}
	var gp gatingPayload
	if err := json.Unmarshal(data, &gp); err != nil {
		return nil, ErrBadResponse
	}
	if !gp.Success {
		return nil, wireError(gp.Error)
	}
	sealed, err := base64.StdEncoding.DecodeString(gp.Sealed)
	if err != nil {
		return nil, ErrBadResponse
	}

	// Lock only for the key access, not the HTTP call above.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrSessionExpired
	}
	out, err := openSealed(s.key, sealed, aad)
	if err != nil {
		return nil, ErrBadResponse
	}
	return out, nil
}

// beatLoop keeps the session alive. A missed beat is NOT a logout: it retries
// until the TTL genuinely lapses, so a brief network blip does not drop a paying
// customer.
func (s *Session) beatLoop() {
	for {
		s.mu.Lock()
		remaining := s.expiresAt - time.Now().Unix()
		s.mu.Unlock()

		wait := 2 * time.Second
		if remaining > 4 {
			wait = time.Duration(remaining/2) * time.Second
		}
		select {
		case <-s.stop:
			return
		case <-time.After(wait):
			s.beatOnce()
		}
	}
}

func (s *Session) beatOnce() {
	data, err := s.c.callEndpoint(context.Background(), "/v1/heartbeat", "heartbeat",
		map[string]any{"app_id": s.c.appID, "session_token": s.token})
	if err != nil {
		return // transient; the TTL still governs
	}
	var hp heartbeatPayload
	if err := json.Unmarshal(data, &hp); err != nil {
		return
	}
	if !hp.Valid {
		return // let the TTL lapse naturally
	}
	if hp.ExpiresAt > 0 {
		s.mu.Lock()
		s.expiresAt = hp.ExpiresAt
		s.mu.Unlock()
	}
}

// RequestDeviceReset unbinds a licence from its machines so it can be moved. The
// server bounds this by cooldown and lifetime cap; the client cannot.
func RequestDeviceReset(appID, publicKeyB64, baseURL, licenseKey string, opts ...Option) error {
	c, err := NewClient(appID, publicKeyB64, baseURL, opts...)
	if err != nil {
		return err
	}
	data, err := c.callEndpoint(context.Background(), "/v1/device/reset", "device_reset",
		map[string]any{"app_id": appID, "license_key": licenseKey})
	if err != nil {
		return err
	}
	var dr deviceResetPayload
	if err := json.Unmarshal(data, &dr); err != nil {
		return ErrBadResponse
	}
	if !dr.Success {
		return wireError(dr.Error)
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
