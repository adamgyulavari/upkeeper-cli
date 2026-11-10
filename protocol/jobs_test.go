package protocol

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestSignVerifyJob(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 11, 10, 3, 0, 0, 0, time.UTC)
	j := Job{ID: "j1", ServerID: "s1", Kind: KindRun, Mode: ModeAuto, Trigger: TriggerSchedule,
		Approved: []string{"image|p/s|v2"}, IssuedAt: now, NotBefore: now, ExpiresAt: now.Add(time.Hour), WindowEnd: now.Add(2 * time.Hour)}
	sj, err := SignJob(priv, "k1", j)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyJob(pub, "k1", "s1", sj, now.Add(time.Minute))
	if err != nil || got.ID != "j1" || got.Approved[0] != "image|p/s|v2" {
		t.Fatalf("verify: %+v %v", got, err)
	}

	tampered := sj
	tampered.Payload = append([]byte{}, sj.Payload...)
	tampered.Payload[10] ^= 1
	otherPub, _, _ := ed25519.GenerateKey(nil)
	for name, c := range map[string]struct {
		pub    ed25519.PublicKey
		keyID  string
		server string
		sj     SignedJob
		at     time.Time
		want   error
	}{
		"tampered":     {pub, "k1", "s1", tampered, now, ErrBadSignature},
		"other key":    {otherPub, "k1", "s1", sj, now, ErrBadSignature},
		"wrong key id": {pub, "k2", "s1", sj, now, ErrWrongKey},
		"other server": {pub, "k1", "s2", sj, now, ErrWrongServer},
		"expired":      {pub, "k1", "s1", sj, now.Add(2 * time.Hour), ErrExpired},
		"too early":    {pub, "k1", "s1", sj, now.Add(-time.Hour), ErrNotYet},
	} {
		if _, err := VerifyJob(c.pub, c.keyID, c.server, c.sj, c.at); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

func TestItemKey(t *testing.T) {
	if k := ItemKey(Item{Layer: LayerImage, Subject: "p/s", To: "v2"}); k != "image|p/s|v2" {
		t.Fatal(k)
	}
}
