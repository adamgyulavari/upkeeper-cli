package fakes

import (
	"crypto/ed25519"
	"crypto/sha256"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// TestRootSeedPhrase derives the TEST root key (protocol.TestRootPublicKey).
// It is public on purpose: never trust the TEST root in production.
const TestRootSeedPhrase = "upkeeper.sh TEST root key. Public on purpose. Never trust it in production."

// TestRoot returns the TEST root private key.
func TestRoot() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(TestRootSeedPhrase))
	return ed25519.NewKeyFromSeed(seed[:])
}

// Signer signs jobs like the control plane: an online key certified by a root.
type Signer struct {
	Roots  []protocol.RootKey
	Online ed25519.PrivateKey
	Cert   protocol.KeyCert
}

// NewSigner makes a fresh root and online key, valid around now.
func NewSigner(now time.Time) *Signer {
	rpub, rpriv, _ := ed25519.GenerateKey(nil)
	opub, opriv, _ := ed25519.GenerateKey(nil)
	cert := protocol.SignCert(rpriv, "root-test", protocol.KeyCert{KeyID: "online-1", PublicKey: opub, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour)})
	return &Signer{Roots: []protocol.RootKey{{ID: "root-test", PublicKey: rpub}}, Online: opriv, Cert: cert}
}

// Sign returns the wire form of j.
func (s *Signer) Sign(j protocol.Job) protocol.SignedJob {
	sj, _ := protocol.SignJob(s.Online, s.Cert.KeyID, j)
	c := s.Cert
	sj.Cert = &c
	return sj
}
