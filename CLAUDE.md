# upkeeper agent (public, Apache-2.0)

The server agent for upkeeper.sh. The control plane lives in a separate private repo and imports `protocol/` from here.

Rules:
1. The agent never runs arbitrary commands. Every external command goes through the fixed allowlist in `agent/host`, and only with tests. LLM output is data, never executed.
2. M0 is read-only: no action that changes the system. `agent/host`'s test enforces this; adding write actions (M1) is a deliberate, reviewed change.
3. Never rewrite the user's compose files (from M1: tags go in `compose.override.upkeeper.yml`).
4. Coolify-managed containers are left to Coolify.
5. `protocol/` is the wire contract: change it only with a version bump and tests here; the control plane must be updated in step.
6. User-facing text (reasons, risk messages): calm, plain, concrete, no exclamation marks, no claims we can't prove.

Run `go vet ./... && go test ./...` before pushing.
