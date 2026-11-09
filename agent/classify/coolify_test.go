package classify

import (
	"strings"
	"testing"

	"github.com/adamgyulavari/upkeeper-cli/agent/discover"
	"github.com/adamgyulavari/upkeeper-cli/agent/versions"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

// On a Coolify host, Coolify-managed containers produce no image items and
// no floating-tag notes; one coolify_host note explains why.
func TestCoolifyManagedContainersAreLeftToCoolify(t *testing.T) {
	in := withService(base(), "traefik:latest", nil, "",
		discover.ImageUpdate{FromTag: "v3.1.7", ToTag: "v3.6.2", Change: versions.Minor})
	f := in.DockerFacts.Services["p/s"]
	f.Coolify = true
	in.DockerFacts.Services["p/s"] = f
	in.DockerFacts.CoolifyHost = true

	for _, it := range Items(in) {
		if it.Layer == protocol.LayerImage {
			t.Fatalf("Coolify-managed container produced an image item: %+v", it)
		}
	}
	var found bool
	for _, r := range Risks(in) {
		if r.Code == RiskFloatingTag {
			t.Fatalf("floating-tag note for a Coolify-managed container: %+v", r)
		}
		if r.Code == RiskCoolifyHost {
			found = true
			if !strings.Contains(r.Message, "1 container") || !strings.Contains(r.Message, "leaves the containers to Coolify") {
				t.Fatalf("unexpected coolify_host message: %q", r.Message)
			}
		}
	}
	if !found {
		t.Fatal("missing coolify_host note")
	}
}
