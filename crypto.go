package rudeauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// These constants mirror the server (internal/crypto). They are protocol
// constants, not tunables: change one and the SDK stops agreeing with the
// server, which the known-answer vectors would catch immediately.
const (
	sigPrefix       = "rudeauth-v1:"
	ephemeralKeyLen = 32
	sessionKeyLen   = 32
)

// hkdfSalt is a fixed, public protocol constant. HKDF's security rests on the
// ECDH shared secret, not on the salt being secret; a constant lets both sides
// derive without an extra round trip.
var hkdfSalt = []byte("rudeauth-v1-session")

var errBadEphemeralKey = errors.New("rudeauth: ephemeral key must be 32 bytes")

// signingInput builds "rudeauth-v1:<endpoint>:" || sha256(data), the exact
// message the server signs. Hashing the body keeps the signed input fixed-size
// regardless of a large file-delivery response.
func signingInput(endpoint string, data []byte) []byte {
	sum := sha256.Sum256(data)
	msg := make([]byte, 0, len(sigPrefix)+len(endpoint)+1+len(sum))
	msg = append(msg, sigPrefix...)
	msg = append(msg, endpoint...)
	msg = append(msg, ':')
	msg = append(msg, sum[:]...)
	return msg
}

// verify checks a response signature against the pinned public key, over the
// exact bytes received. It is the one gate every response passes before any
// field of it is trusted.
func verify(pub ed25519.PublicKey, endpoint string, data, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, signingInput(endpoint, data), sig)
}

// ephemeral returns a fresh X25519 keypair for one handshake.
func ephemeral() (pub, priv []byte, err error) {
	priv = make([]byte, ephemeralKeyLen)
	if _, err := rand.Read(priv); err != nil {
		return nil, nil, err
	}
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// deriveSessionKey performs ECDH and expands the shared secret with HKDF, bound
// to the session id so a payload captured in one session cannot be opened in
// another. X25519 errors on low-order points, which stops an attacker forcing
// the shared secret to a known all-zero value.
func deriveSessionKey(ourPriv, theirPub []byte, sessionID string) ([]byte, error) {
	if len(ourPriv) != ephemeralKeyLen || len(theirPub) != ephemeralKeyLen {
		return nil, errBadEphemeralKey
	}
	shared, err := curve25519.X25519(ourPriv, theirPub)
	if err != nil {
		return nil, err
	}
	key := make([]byte, sessionKeyLen)
	// salt is the fixed constant; the session id is HKDF info.
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, hkdfSalt, []byte(sessionID)), key); err != nil {
		return nil, err
	}
	return key, nil
}

// openSealed reverses the server's SealForSession: XChaCha20-Poly1305 with the
// 24-byte nonce prepended, so a sealed blob is nonce || ciphertext || tag.
func openSealed(sessionKey, blob, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sessionKey)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("rudeauth: sealed blob too short")
	}
	return aead.Open(nil, blob[:ns], blob[ns:], aad)
}

// randomNonce returns 32 fresh bytes for a handshake client nonce.
func randomNonce() ([]byte, error) {
	n := make([]byte, 32)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return n, nil
}
