package protocol

import "sync"

// Root keys the agent trusts for job-key certificates.
//
// Production builds inject the founder's offline root public key at link
// time; nothing else is trusted:
//
//	go build -ldflags "-X github.com/adamgyulavari/upkeeper-cli/protocol.rootKeys=<id>:<base64 pub>"
//
// (`make build ROOT_KEYS=...`; the release workflow passes the repository
// variable UPKEEPER_ROOT_KEYS). A build without any root key accepts no
// jobs at all: automatic runs fail closed.
//
// Development builds may opt in to the TEST root below with
// -X …protocol.allowTestRoot=yes (`make build-dev`). Its private key is
// public (agent/fakes), so a binary that trusts it must never run on a
// server you care about. Release builds never set it.
var (
	rootKeys      string // set by -ldflags
	allowTestRoot string // "yes" in development builds only
)

// TestRootID and TestRootPublicKey are the TEST root. NOT FOR PRODUCTION:
// its private key is derived from TestRootSeedPhrase in agent/fakes.
const (
	TestRootID        = "TEST-ROOT-DO-NOT-USE"
	TestRootPublicKey = "JCTV7oOGqEFqXtiUj7RYVxUnuGayAP+sMUb6lYQJH9M="
)

var (
	rootsOnce sync.Once
	roots     []RootKey
	rootsErr  error
)

// Roots returns the root keys compiled into this binary.
func Roots() ([]RootKey, error) {
	rootsOnce.Do(func() {
		var list []RootKey
		if rootKeys != "" {
			list, rootsErr = ParseRootKeys(rootKeys)
			if rootsErr != nil {
				return
			}
		}
		if allowTestRoot == "yes" {
			t, err := ParseRootKeys(TestRootID + ":" + TestRootPublicKey)
			if err != nil {
				rootsErr = err
				return
			}
			list = append(list, t...)
		}
		roots = list
	})
	return roots, rootsErr
}

// TestRootTrusted reports whether this build trusts the TEST root.
func TestRootTrusted() bool { return allowTestRoot == "yes" }
