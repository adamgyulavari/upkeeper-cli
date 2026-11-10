package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Two-tier job keys (protocol 2).
//
// An offline root key, kept by the founder, certifies short-lived online
// keys. The control plane signs jobs with an online key and sends its
// certificate with every job. Agents carry the root public keys compiled
// in (rootkeys.go) and accept a job only through a valid certificate. A
// leaked online key stops working when its certificate expires, and
// nothing is pinned on first use.

// KeyCert certifies an online job-signing key.
type KeyCert struct {
	KeyID     string    `json:"key_id"`
	PublicKey []byte    `json:"public_key"` // Ed25519
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	RootID    string    `json:"root_id"`
	Signature []byte    `json:"signature,omitempty"` // root's signature over SignedBytes
}

// certDomain separates cert signatures from anything else a root key might sign.
const certDomain = "upkeeper-key-cert-v1\n"

// SignedBytes is what the root signs: a domain prefix plus the cert's
// canonical JSON without the signature (field order is fixed by the struct).
func (c KeyCert) SignedBytes() []byte {
	c.Signature = nil
	b, _ := json.Marshal(c)
	return append([]byte(certDomain), b...)
}

// RootKey is a trusted root public key.
type RootKey struct {
	ID        string
	PublicKey ed25519.PublicKey
}

// SignCert signs c with a root private key.
func SignCert(root ed25519.PrivateKey, rootID string, c KeyCert) KeyCert {
	c.RootID = rootID
	c.Signature = ed25519.Sign(root, c.SignedBytes())
	return c
}

// Verify checks the cert against roots and its validity period.
func (c KeyCert) Verify(roots []RootKey, now time.Time) error {
	ok := false
	for _, r := range roots {
		if r.ID == c.RootID && len(r.PublicKey) == ed25519.PublicKeySize && ed25519.Verify(r.PublicKey, c.SignedBytes(), c.Signature) {
			ok = true
			break
		}
	}
	if !ok {
		return ErrBadCert
	}
	if len(c.PublicKey) != ed25519.PublicKeySize || c.KeyID == "" {
		return ErrBadCert
	}
	if now.Add(Skew).Before(c.NotBefore) || now.After(c.NotAfter) {
		return ErrCertExpired
	}
	return nil
}

// Fingerprint is "SHA256:<base64>" of a public key, the way ssh shows them.
func Fingerprint(pub []byte) string {
	h := sha256.Sum256(pub)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}

// ParseRootKeys parses "id:base64pub[,id:base64pub…]".
func ParseRootKeys(s string) ([]RootKey, error) {
	var out []RootKey
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, b64, ok := strings.Cut(part, ":")
		if !ok || id == "" {
			return nil, fmt.Errorf("root key %q: want id:base64", part)
		}
		pub, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("root key %q: not a base64 Ed25519 public key", id)
		}
		out = append(out, RootKey{ID: id, PublicKey: pub})
	}
	if len(out) == 0 {
		return nil, errors.New("no root keys")
	}
	return out, nil
}
