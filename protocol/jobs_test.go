package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type keys struct {
	roots  []RootKey
	root   ed25519.PrivateKey
	online ed25519.PrivateKey
	cert   KeyCert
}

func newKeys(t *testing.T, now time.Time) keys {
	rpub, rpriv, _ := ed25519.GenerateKey(nil)
	opub, opriv, _ := ed25519.GenerateKey(nil)
	cert := SignCert(rpriv, "root-1", KeyCert{KeyID: "k1", PublicKey: opub, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour)})
	return keys{roots: []RootKey{{ID: "root-1", PublicKey: rpub}}, root: rpriv, online: opriv, cert: cert}
}

func (k keys) sign(t *testing.T, j Job) SignedJob {
	sj, err := SignJob(k.online, "k1", j)
	if err != nil {
		t.Fatal(err)
	}
	c := k.cert
	sj.Cert = &c
	return sj
}

func TestSignVerifyJob(t *testing.T) {
	now := time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC)
	k := newKeys(t, now)
	j := Job{ID: "j1", ServerID: "s1", Kind: KindRun, Mode: ModeAuto, Trigger: TriggerSchedule,
		Approved: []string{"image|p/s|v2"}, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(3 * time.Hour), WindowEnd: now.Add(2 * time.Hour)}
	sj := k.sign(t, j)
	got, err := VerifyJob(k.roots, "s1", sj, now.Add(time.Minute))
	if err != nil || got.ID != "j1" || got.Approved[0] != "image|p/s|v2" {
		t.Fatalf("verify: %+v %v", got, err)
	}

	tampered := sj
	tampered.Payload = append([]byte{}, sj.Payload...)
	tampered.Payload[10] ^= 1
	noCert := sj
	noCert.Cert = nil
	wrongKeyID := sj
	wrongKeyID.KeyID = "k2"
	// A cert signed by a key that isn't a root.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	selfSigned := sj
	c := SignCert(otherPriv, "root-1", k.cert)
	selfSigned.Cert = &c
	// A cert whose key was swapped after signing.
	swapped := sj
	sc := k.cert
	otherPub, _, _ := ed25519.GenerateKey(nil)
	sc.PublicKey = otherPub
	swapped.Cert = &sc
	// A job signed directly with the root key, without a matching cert.
	byRoot, _ := SignJob(k.root, "k1", j)
	cc := k.cert
	byRoot.Cert = &cc

	long := j
	long.ExpiresAt = now.Add(7 * time.Hour)
	future := j
	future.IssuedAt = now.Add(time.Hour)
	future.NotBefore = now.Add(time.Hour)
	badWindow := j
	badWindow.WindowEnd = j.ExpiresAt.Add(time.Minute)
	noIssued := j
	noIssued.IssuedAt = time.Time{}

	for name, c := range map[string]struct {
		roots []RootKey
		sj    SignedJob
		at    time.Time
		want  error
	}{
		"tampered":           {k.roots, tampered, now, ErrBadSignature},
		"no cert":            {k.roots, noCert, now, ErrNoCert},
		"wrong key id":       {k.roots, wrongKeyID, now, ErrWrongKey},
		"cert not from root": {k.roots, selfSigned, now, ErrBadCert},
		"cert key swapped":   {k.roots, swapped, now, ErrBadCert},
		"signed by root":     {k.roots, byRoot, now, ErrBadSignature},
		"no roots":           {nil, sj, now, ErrBadCert},
		"cert expired":       {k.roots, sj, now.Add(31 * 24 * time.Hour), ErrCertExpired},
		"other server":       {k.roots, k.sign(t, func() Job { x := j; x.ServerID = "s2"; return x }()), now, ErrWrongServer},
		"expired":            {k.roots, sj, now.Add(4 * time.Hour), ErrExpired},
		"too early":          {k.roots, k.sign(t, func() Job { x := j; x.NotBefore = now.Add(time.Hour); return x }()), now, ErrNotYet},
		"lives too long":     {k.roots, k.sign(t, long), now, ErrLifetime},
		"no issued time":     {k.roots, k.sign(t, noIssued), now, ErrLifetime},
		"issued in future":   {k.roots, k.sign(t, future), now, ErrIssuedFuture},
		"window after exp":   {k.roots, k.sign(t, badWindow), now, ErrBadWindow},
	} {
		if _, err := VerifyJob(c.roots, "s1", c.sj, c.at); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

func TestSignedJobJSONBackwardCompatible(t *testing.T) {
	// A protocol-2 SignedJob without a cert still decodes (and is then rejected).
	var sj SignedJob
	if err := json.Unmarshal([]byte(`{"key_id":"k","payload":"e30=","signature":"AA=="}`), &sj); err != nil || sj.Cert != nil {
		t.Fatalf("%+v %v", sj, err)
	}
}

func TestTestRoot(t *testing.T) {
	seed := sha256.Sum256([]byte("upkeeper.sh TEST root key. Public on purpose. Never trust it in production."))
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	if base64.StdEncoding.EncodeToString(pub) != TestRootPublicKey {
		t.Error("TestRootPublicKey doesn't match the published seed")
	}
	// A plain `go test`/`go build` trusts no root at all.
	if r, err := Roots(); len(r) != 0 || err != nil || TestRootTrusted() {
		t.Errorf("default build trusts roots: %v %v", r, err)
	}
}

func TestParseRootKeys(t *testing.T) {
	r, err := ParseRootKeys("a:" + TestRootPublicKey + ", b:" + TestRootPublicKey)
	if err != nil || len(r) != 2 || r[1].ID != "b" {
		t.Fatalf("%v %v", r, err)
	}
	for _, bad := range []string{"", "nokey", "a:!!!", "a:AAAA"} {
		if _, err := ParseRootKeys(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if Fingerprint([]byte{1}) == "" {
		t.Error("fingerprint")
	}
}

func TestItemKey(t *testing.T) {
	if k := ItemKey(Item{Layer: LayerImage, Subject: "p/s", To: "v2"}); k != "image|p/s|v2" {
		t.Fatal(k)
	}
}
