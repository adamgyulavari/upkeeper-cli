# upkeeper agent (public, Apache-2.0)

The server agent for upkeeper.sh. The control plane lives in a separate private repo and imports `protocol/` from here.

Rules:
1. The agent never runs arbitrary commands. Every external command goes through the fixed allowlist in `agent/host`, and only with tests. LLM output is data, never executed.
2. Write actions live only in `agent/run`, behind the exact-shape allowlist in `agent/host` (a source-scan test enforces it). A server changes nothing unless its local policy (root-owned `/etc/upkeeper/policy.yaml`) allows it AND a job signed by a key certified by an embedded root key asks for it. Adding or widening a write action is a deliberate, reviewed change with tests.
3. Never rewrite the user's compose files: tags go in `compose.override.upkeeper.yml`. Never trust container or image labels for paths.
4. Coolify-managed containers are left to Coolify.
5. `protocol/` is the wire contract: change it only with a version bump and tests here; the control plane must be updated in step.
6. User-facing text (reasons, risk messages): calm, plain, concrete, no exclamation marks, no claims we can't prove.

Run `go vet ./... && go test ./...` before pushing.
