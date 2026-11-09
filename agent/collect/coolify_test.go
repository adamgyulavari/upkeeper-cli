package collect

import "testing"

func TestCoolifyManaged(t *testing.T) {
	cases := []struct {
		labels  map[string]string
		repo    string
		workDir string
		want    bool
	}{
		{map[string]string{"coolify.managed": "true"}, "library/postgres", "", true},
		{nil, "ghcr.io/coollabsio/coolify", "/data/coolify/source", true},
		{nil, "coollabsio/coolify-realtime", "", true},
		{nil, "library/traefik", "/data/coolify/proxy", true},
		{nil, "library/postgres", "/opt/immich", false},
		{map[string]string{"coolify.managed": "false"}, "library/redis", "/srv/app", false},
	}
	for _, c := range cases {
		if got := CoolifyManaged(c.labels, c.repo, c.workDir); got != c.want {
			t.Errorf("CoolifyManaged(%v, %q, %q) = %v, want %v", c.labels, c.repo, c.workDir, got, c.want)
		}
	}
}
