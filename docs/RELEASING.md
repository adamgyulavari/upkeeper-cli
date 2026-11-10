# Releasing the agent

Releases are signed offline. The release workflow only builds a **draft**;
nobody can install a draft, and `deploy/install.sh` refuses a release whose
`checksums.txt` isn't signed with the release key embedded in it.

## One-time setup

1. **Release signing key** (SSH Ed25519, kept offline, ideally on a hardware key):

   ```sh
   ssh-keygen -t ed25519 -C release@upkeeper.sh -f ~/.ssh/upkeeper-release
   ```

   Put its public key into `deploy/install.sh`, replacing the placeholder:

   ```sh
   ALLOWED_SIGNERS='release@upkeeper.sh namespaces="upkeeper-release" ssh-ed25519 AAAA…'
   ```

   Until that's done every install fails closed (only
   `UPKEEPER_INSECURE_SKIP_SIGNATURE=1` gets past it, with a warning).

2. **Job-signing root key** (offline, separate from the release key):

   ```sh
   make keys
   bin/upkeeper-keys gen-root -id root-2026 -out root.key   # keep root.key offline
   ```

   Set the printed `id:base64` as the repository variable
   `UPKEEPER_ROOT_KEYS` (Settings → Secrets and variables → Actions →
   Variables). It's a public key, not a secret. Release builds embed it; a
   build without it accepts no jobs.

3. **Online job key for the control plane**, certified by the root, renewed
   before the certificate ends (at most 90 days, default 30):

   ```sh
   bin/upkeeper-keys gen-online -id online-2026-11 -out online.key
   bin/upkeeper-keys sign-cert -root root.key -root-id root-2026 -key-id online-2026-11 -pub <public key> -days 30
   ```

   The control plane gets `online.key`'s content as `JOB_SIGNING_KEY`, the key
   ID as `JOB_KEY_ID`, and the certificate JSON as `JOB_KEY_CERT`. It sends
   the certificate with every job.

4. GitHub settings: turn on immutable releases, add a tag ruleset so only the
   release workflow creates `v*` tags, require review on `main`, and set the
   default workflow token to read-only.

## Each release

1. Bump `VERSION` on `main` (through a reviewed PR). The Release workflow
   tests, builds and creates a draft release `vX.Y.Z` with the binaries,
   `checksums.txt` and `install.sh`.
2. On your own machine, download `checksums.txt` from the draft and check it
   matches a build you trust (for example `make build VERSION=vX.Y.Z
   ROOT_KEYS=…` from the tagged commit; builds use `-trimpath`).
3. Sign it:

   ```sh
   ssh-keygen -Y sign -n upkeeper-release -f ~/.ssh/upkeeper-release checksums.txt
   ```

4. Upload `checksums.txt.sig` to the draft and publish it:

   ```sh
   gh release upload vX.Y.Z checksums.txt.sig
   gh release edit vX.Y.Z --draft=false --latest
   ```

5. Check an install on a throwaway VM:

   ```sh
   curl --proto '=https' --tlsv1.2 -fsSL https://upkeeper.sh | sh   # prints "release signature ok."
   ```
