// Command upkeeper-keys manages the job-signing keys, offline.
//
//	upkeeper-keys gen-root  -id ROOT_ID -out root.key
//	    Creates the offline root key (seed file, 0600) and prints the public
//	    key line to build agents with (ROOT_KEYS=id:base64).
//	upkeeper-keys gen-online -id KEY_ID -out online.key
//	    Creates an online job-signing key for the control plane and prints
//	    its public key. The seed (base64) goes into the control plane's
//	    JOB_SIGNING_KEY.
//	upkeeper-keys sign-cert -root root.key -root-id ROOT_ID -key-id KEY_ID -pub BASE64 [-days 30]
//	    Signs a certificate for an online key with the root key and prints
//	    it as JSON (the control plane's JOB_KEY_CERT).
//	    -test-root instead of -root/-root-id signs with the public TEST root
//	    (development builds only; never for production).
//	upkeeper-keys show-cert < cert.json
//	    Prints a certificate's key ID, fingerprint and validity.
//
// Run gen-root and sign-cert on a machine that's offline, and keep root.key
// off every server.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// testRootSeedPhrase derives the TEST root (protocol.TestRootPublicKey).
const testRootSeedPhrase = "upkeeper.sh TEST root key. Public on purpose. Never trust it in production."

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "upkeeper-keys:", err)
		os.Exit(1)
	}
}

func writeSeed(path string, priv ed25519.PrivateKey) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func readSeed(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New(path + ": not a base64 Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: upkeeper-keys gen-root|gen-online|sign-cert|show-cert [flags]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	id := fs.String("id", "", "key ID")
	out := fs.String("out", "", "file for the private seed (created, 0600)")
	rootPath := fs.String("root", "", "root seed file")
	rootID := fs.String("root-id", "", "root key ID")
	keyID := fs.String("key-id", "", "online key ID")
	pub := fs.String("pub", "", "online public key (base64)")
	days := fs.Int("days", 30, "certificate validity in days")
	testRoot := fs.Bool("test-root", false, "sign with the public TEST root (development only)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	var err error
	switch args[0] {
	case "gen-root", "gen-online":
		if *id == "" || *out == "" {
			return errors.New("-id and -out are required")
		}
		p, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		if err := writeSeed(*out, priv); err != nil {
			return err
		}
		b64 := base64.StdEncoding.EncodeToString(p)
		if args[0] == "gen-root" {
			fmt.Fprintf(stdout, "Root key written to %s. Keep it offline.\nBuild agents with: ROOT_KEYS=%s:%s\nFingerprint: %s\n", *out, *id, b64, protocol.Fingerprint(p))
		} else {
			fmt.Fprintf(stdout, "Online key written to %s (its content is JOB_SIGNING_KEY).\nKey ID: %s\nPublic key: %s\nFingerprint: %s\n", *out, *id, b64, protocol.Fingerprint(p))
		}
		return nil
	case "sign-cert":
		if *testRoot {
			*rootID = protocol.TestRootID
		} else if *rootPath == "" || *rootID == "" {
			return errors.New("-root and -root-id (or -test-root) are required")
		}
		if *keyID == "" || *pub == "" {
			return errors.New("-key-id and -pub are required")
		}
		if *days < 1 || *days > 90 {
			return errors.New("-days must be between 1 and 90")
		}
		var root ed25519.PrivateKey
		if *testRoot {
			seed := sha256.Sum256([]byte(testRootSeedPhrase))
			root = ed25519.NewKeyFromSeed(seed[:])
		} else if root, err = readSeed(*rootPath); err != nil {
			return err
		}
		pk, err := base64.StdEncoding.DecodeString(*pub)
		if err != nil || len(pk) != ed25519.PublicKeySize {
			return errors.New("-pub: not a base64 Ed25519 public key")
		}
		now := time.Now().UTC().Truncate(time.Second)
		c := protocol.SignCert(root, *rootID, protocol.KeyCert{KeyID: *keyID, PublicKey: pk, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Duration(*days) * 24 * time.Hour)})
		b, _ := json.Marshal(c)
		fmt.Fprintln(stdout, string(b))
		return nil
	case "show-cert":
		var c protocol.KeyCert
		if err := json.NewDecoder(stdin).Decode(&c); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "Key ID: %s\nFingerprint: %s\nRoot: %s\nValid: %s to %s\n", c.KeyID, protocol.Fingerprint(c.PublicKey), c.RootID, c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339))
		return nil
	}
	return fmt.Errorf("unknown command %q", args[0])
}
