package rudeauth

import "errors"

// The error vocabulary, one to one with the C++ SDK's Error enum. Callers match
// with errors.Is, so a rejected licence is a specific error rather than a bool.
//
// Note there is deliberately no "is licensed" boolean anywhere in this package.
// Authenticate returns a *Session or one of these errors, and the gating calls
// exist only on a *Session.
var (
	// ErrNetwork means the server could not be reached. It wraps the transport error.
	ErrNetwork = errors.New("rudeauth: network unreachable")
	// ErrBadResponse means the response was malformed or its envelope did not decode.
	ErrBadResponse = errors.New("rudeauth: malformed response")
	// ErrSignatureInvalid means the responder is not holding this application's key.
	ErrSignatureInvalid = errors.New("rudeauth: signature invalid, the server is not authentic")
	// ErrNonceMismatch means the response was replayed from an earlier request.
	ErrNonceMismatch = errors.New("rudeauth: nonce mismatch, replayed response")
	// ErrClockSkew means this machine's clock is too far from the server's.
	ErrClockSkew = errors.New("rudeauth: system clock is too far from the server's")

	ErrLicenseInvalid    = errors.New("rudeauth: licence invalid")
	ErrLicenseExpired    = errors.New("rudeauth: licence expired")
	ErrDeviceLimit       = errors.New("rudeauth: device limit reached")
	ErrDeviceBlacklisted = errors.New("rudeauth: device blacklisted")
	ErrRateLimited       = errors.New("rudeauth: rate limited")
	ErrSessionExpired    = errors.New("rudeauth: session expired")
	ErrEndpointDisabled  = errors.New("rudeauth: endpoint disabled")
	ErrAppDisabled       = errors.New("rudeauth: application unavailable")
	ErrResetUnavailable  = errors.New("rudeauth: device reset unavailable")
	ErrFileNotFound      = errors.New("rudeauth: no such file for this application")
	ErrServerError       = errors.New("rudeauth: server error")
)

// wireError maps the server's coarse error codes onto the sentinels above. An
// unrecognised code becomes ErrServerError rather than being ignored: a code
// this SDK does not know is a reason to stop, not to continue.
func wireError(code string) error {
	switch code {
	case "LICENSE_INVALID":
		return ErrLicenseInvalid
	case "LICENSE_EXPIRED":
		return ErrLicenseExpired
	case "DEVICE_LIMIT":
		return ErrDeviceLimit
	case "DEVICE_BLACKLISTED":
		return ErrDeviceBlacklisted
	case "RATE_LIMITED":
		return ErrRateLimited
	case "SESSION_EXPIRED":
		return ErrSessionExpired
	case "ENDPOINT_DISABLED":
		return ErrEndpointDisabled
	case "APP_DISABLED":
		return ErrAppDisabled
	case "CLOCK_SKEW":
		return ErrClockSkew
	case "RESET_UNAVAILABLE":
		return ErrResetUnavailable
	case "FILE_NOT_FOUND":
		return ErrFileNotFound
	default:
		return ErrServerError
	}
}
