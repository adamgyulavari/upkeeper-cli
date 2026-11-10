package classify

import (
	"context"
	"strings"
	"testing"

	"github.com/adamgyulavari/upkeeper-cli/agent/collect"
	"github.com/adamgyulavari/upkeeper-cli/agent/discover"
	"github.com/adamgyulavari/upkeeper-cli/agent/registry"
	"github.com/adamgyulavari/upkeeper-cli/protocol"
)

type tagReg map[string][]string

func (r tagReg) Tags(_ context.Context, ref registry.Ref) ([]string, error) { return r[ref.Repo], nil }
func (r tagReg) Digest(context.Context, registry.Ref, string) (string, error) {
	return "sha256:" + strings.Repeat("a", 64), nil
}
func (r tagReg) Skipped() map[string]error { return nil }

// TestSuffixFamilies runs discovery and the classifier together on tags
// whose suffix carries a version (production bug: pgvector 0.7.2-pg16 →
// 0.7.4-pg17 was auto as a patch release, but it also moves Postgres 16 → 17).
func TestSuffixFamilies(t *testing.T) {
	type want struct {
		to       string
		decision protocol.Decision
		reason   string
	}
	tests := []struct {
		name  string
		image string
		tags  []string
		want  []want
	}{
		{
			name:  "pgvector stays on pg16; pg17 is flagged",
			image: "pgvector/pgvector:0.7.2-pg16",
			tags:  []string{"0.7.2-pg16", "0.7.4-pg16", "0.7.4-pg17", "0.7.2-pg17", "0.8.0-pg15"},
			want: []want{ // flagged items sort first
				{"0.7.4-pg17", protocol.Flagged, "0.7.2-pg16 → 0.7.4-pg17 also moves Postgres 16 → 17, which needs a data migration, so it waits for a supervised run."},
				{"0.7.4-pg16", protocol.Auto, "Patch release"},
			},
		},
		{
			name:  "pgvector: only the newest other family is offered",
			image: "pgvector/pgvector:0.7.2-pg16",
			tags:  []string{"0.7.4-pg17", "0.8.0-pg17", "0.8.0-pg18"},
			want:  []want{{"0.8.0-pg18", protocol.Flagged, "Postgres 16 → 18"}},
		},
		{
			name:  "postgres 16-alpine → 17-alpine is a major",
			image: "postgres:16-alpine",
			tags:  []string{"16-alpine", "17-alpine", "16-bookworm"},
			want:  []want{{"17-alpine", protocol.Flagged, "major version"}},
		},
		{
			name:  "node 20-alpine3.19 → 20-alpine3.20 is a base image update",
			image: "node:20-alpine3.19",
			tags:  []string{"20-alpine3.19", "20-alpine3.20", "20-alpine3.9", "22-alpine3.20"},
			want: []want{
				{"22-alpine3.20", protocol.Flagged, "major version"},
				{"20-alpine3.20", protocol.Auto, ""},
			},
		},
		{
			name:  "alpine 3.9 → 3.10 compares numerically",
			image: "example/app:1.2.0-alpine3.9",
			tags:  []string{"1.2.0-alpine3.10", "1.2.0-alpine3.8"},
			want:  []want{{"1.2.0-alpine3.10", protocol.Auto, ""}},
		},
		{
			name:  "build counters aren't families",
			image: "linuxserver/sonarr:4.0.10-ls260",
			tags:  []string{"4.0.10-ls261", "4.0.11-ls262"},
			want:  []want{{"4.0.11-ls262", protocol.Auto, "Patch release"}},
		},
		{
			name:  "java runtime major in the suffix",
			image: "example/svc:2.1.0-jdk17",
			tags:  []string{"2.1.1-jdk17", "2.1.1-jdk21"},
			want: []want{
				{"2.1.1-jdk21", protocol.Flagged, "also moves Java 17 → 21 inside the image"},
				{"2.1.1-jdk17", protocol.Auto, ""},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := withService(base(), tt.image, nil, "")
			in.Projects[0].Services[0].Digest = "sha256:" + strings.Repeat("a", 64)
			ref := in.DockerFacts.Services["p/s"].Ref
			var errs collect.Errs
			in.Images = discover.Images(context.Background(), tagReg{ref.Repo: tt.tags}, in.Projects, in.DockerFacts, &errs)
			var got []protocol.Item
			for _, it := range Items(in) {
				if it.Layer == protocol.LayerImage {
					got = append(got, it)
				}
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %s", dump(got))
			}
			for i, w := range tt.want {
				g := got[i]
				if g.To != w.to || g.Decision != w.decision || !strings.Contains(g.Reason, w.reason) {
					t.Errorf("item %d: got %s %s %q, want %s %s %q", i, g.To, g.Decision, g.Reason, w.to, w.decision, w.reason)
				}
			}
			checkVoice(t, got)
		})
	}
}
