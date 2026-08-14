package rudeauth

// These response types mirror the server's internal/api/client wire.go exactly.
// Field tags must match, because the signature is verified over the raw bytes
// and only then are they parsed into these structs.

type envelope struct {
	Data      string `json:"data"`      // base64
	Signature string `json:"signature"` // base64 Ed25519
}

// LicenseInfo is what the server reports about the licence at handshake.
type LicenseInfo struct {
	Level       int   `json:"level"`
	ExpiresAt   int64 `json:"expires_at"` // unix seconds; 0 means perpetual
	DevicesUsed int   `json:"devices_used"`
	MaxDevices  int   `json:"max_devices"`
}

type handshakePayload struct {
	Success          bool         `json:"success"`
	ClientNonce      string       `json:"client_nonce"`
	ServerTime       int64        `json:"server_time"`
	SessionToken     string       `json:"session_token"`
	SessionExpiresAt int64        `json:"session_expires_at"`
	SessionID        string       `json:"session_id"`
	ServerEphPubkey  string       `json:"server_eph_pubkey"`
	License          *LicenseInfo `json:"license"`
	Error            string       `json:"error"`
}

type gatingPayload struct {
	Success bool   `json:"success"`
	Sealed  string `json:"sealed"` // base64
	Version int    `json:"version"`
	Error   string `json:"error"`
}

type heartbeatPayload struct {
	Valid     bool   `json:"valid"`
	ExpiresAt int64  `json:"expires_at"`
	Error     string `json:"error"`
}

type webhookPayload struct {
	Success bool   `json:"success"`
	Body    string `json:"body"` // base64
	Error   string `json:"error"`
}

type deviceResetPayload struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}
