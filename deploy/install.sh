#!/bin/sh
# upkeeper.sh agent installer.
#
#   curl --proto '=https' --tlsv1.2 -fsSL https://upkeeper.sh | UPKEEPER_ENROLL_TOKEN=<token> sh
#   curl --proto '=https' --tlsv1.2 -fsSL https://upkeeper.sh | sh -s -- <enroll-token>
#
# Downloads the agent from GitHub releases, checks the release signature on
# checksums.txt (ssh-keygen -Y verify, against the key embedded below), checks
# the binary's sha256, installs /usr/local/bin/upkeeper and a systemd unit,
# then enrolls this server. The local policy starts as observe (report only).
# Run it again without a token to upgrade the agent in place.
#
# Options (or environment):
#   --url URL        control plane (UPKEEPER_URL, default https://upkeeper.sh)
#   --version vX.Y.Z release to install (UPKEEPER_VERSION, default latest)
#   --no-start       install and enroll, but don't start the service
#   --token-stdin    read the enroll token from the first line of stdin
# The enroll token can also come from UPKEEPER_ENROLL_TOKEN, which keeps it
# out of the process list and shell history.
# Also: UPKEEPER_DOWNLOAD_BASE overrides the release download URL (mirrors, tests);
# UPKEEPER_INSECURE_SKIP_SIGNATURE=1 skips the signature check (not recommended).
#
# Everything is inside main() so a cut-off download runs nothing.

set -eu

REPO="adamgyulavari/upkeeper-cli"
BIN_DIR="/usr/local/bin"
UNIT_PATH="/etc/systemd/system/upkeeper.service"
CONFIG_PATH="/etc/upkeeper/agent.json"
POLICY_PATH="/etc/upkeeper/policy.yaml"

# The release signing key (ssh-keygen allowed_signers format). Releases sign
# checksums.txt with: ssh-keygen -Y sign -n upkeeper-release -f <key> checksums.txt
# PLACEHOLDER until the founder publishes the real key; with the placeholder
# every install fails closed unless UPKEEPER_INSECURE_SKIP_SIGNATURE=1.
SIGNER_ID="release@upkeeper.sh"
ALLOWED_SIGNERS='release@upkeeper.sh namespaces="upkeeper-release" ssh-ed25519 PLACEHOLDER-REPLACE-WITH-THE-RELEASE-PUBLIC-KEY'

say() { printf '%s\n' "upkeeper: $*"; }
fail() { printf '%s\n' "upkeeper: $*" >&2; exit 1; }

unit_file() {
	# Keep in sync with deploy/upkeeper.service (a test checks this).
	cat <<'UNIT'
[Unit]
Description=upkeeper.sh agent
Documentation=https://upkeeper.sh
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/upkeeper run
Restart=always
RestartSec=30s
# If the service stops during a run, let apt-get or docker compose finish
# instead of killing them halfway. The agent marks the run as stopped and
# freezes the server when it starts again.
KillMode=process
TimeoutStopSec=90s

# Runs as root: the Docker socket and apt are root-only. From M1 the agent
# upgrades packages, and apt, dpkg and their maintainer scripts (kernel and
# grub hooks, initramfs, DKMS) run as children of this service. They must
# see the system exactly as they would from a root shell, so this unit has
# no sandbox: no device policy, no memory cap, no private /tmp, no
# read-only /home. README.md (Security) explains why and how to restore the
# strict sandbox on servers that stay in observe mode.
ConfigurationDirectory=upkeeper
ConfigurationDirectoryMode=0700
CacheDirectory=upkeeper
CacheDirectoryMode=0700
StateDirectory=upkeeper
StateDirectoryMode=0700
# The agent never writes its config or the local policy at runtime; only
# root on the server does, with `upkeeper policy set`.
ReadOnlyPaths=/etc/upkeeper
UMask=0022

[Install]
WantedBy=multi-user.target
UNIT
}

is_local_http() {
	case "$1" in
		http://localhost:*|http://localhost/*|http://127.0.0.1:*|http://127.0.0.1/*) return 0 ;;
	esac
	return 1
}

download() { # url dest
	# https only, including redirects. Plain http only for a local test server.
	proto='=https'
	if is_local_http "$1"; then proto='=http,https'; fi
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto "$proto" --proto-redir "$proto" --tlsv1.2 --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		if is_local_http "$1"; then
			wget -q -O "$2" "$1"
		else
			wget -q --https-only --secure-protocol=TLSv1_2 -O "$2" "$1"
		fi
	else
		fail "needs curl or wget to download the agent."
	fi
}

verify_signature() { # checksums sig
	if [ "${UPKEEPER_INSECURE_SKIP_SIGNATURE:-}" = "1" ]; then
		say "WARNING: skipping the release signature check (UPKEEPER_INSECURE_SKIP_SIGNATURE=1). Only the checksum is checked."
		return 0
	fi
	case "$ALLOWED_SIGNERS" in
		*PLACEHOLDER*) fail "this installer has no release signing key yet, so it can't check the release signature. Nothing was installed. (UPKEEPER_INSECURE_SKIP_SIGNATURE=1 skips the check.)" ;;
	esac
	[ -s "$2" ] || fail "the release has no checksums.txt.sig, so its signature can't be checked. Nothing was installed."
	command -v ssh-keygen >/dev/null 2>&1 || fail "needs ssh-keygen (openssh-client) to check the release signature. Nothing was installed."
	printf '%s\n' "$ALLOWED_SIGNERS" > "$tmp/allowed_signers"
	ssh-keygen -Y verify -f "$tmp/allowed_signers" -I "$SIGNER_ID" -n upkeeper-release -s "$2" < "$1" >/dev/null 2>&1 \
		|| fail "the release signature on checksums.txt doesn't verify. Nothing was installed."
	say "release signature ok."
}

sha256_of() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		fail "needs sha256sum or shasum to check the download."
	fi
}

main() {
	token=""
	url="${UPKEEPER_URL:-https://upkeeper.sh}"
	version="${UPKEEPER_VERSION:-latest}"
	start=1
	token_stdin=0
	while [ $# -gt 0 ]; do
		case "$1" in
			--url) [ $# -ge 2 ] || fail "--url needs a value"; url="$2"; shift 2 ;;
			--url=*) url="${1#--url=}"; shift ;;
			--version) [ $# -ge 2 ] || fail "--version needs a value"; version="$2"; shift 2 ;;
			--version=*) version="${1#--version=}"; shift ;;
			--no-start) start=0; shift ;;
			--token-stdin) token_stdin=1; shift ;;
			-h|--help) sed -n '2,24p' "$0" 2>/dev/null || true; exit 0 ;;
			-*) fail "unknown option $1" ;;
			*) [ -z "$token" ] || fail "only one enroll token, please"; token="$1"; shift ;;
		esac
	done

	if [ -z "$token" ] && [ -n "${UPKEEPER_ENROLL_TOKEN:-}" ]; then
		token="$UPKEEPER_ENROLL_TOKEN"
	fi
	if [ "$token_stdin" -eq 1 ]; then
		IFS= read -r token || true
	fi

	[ "$(uname -s)" = "Linux" ] || fail "the agent runs on Linux only."

	case "$(uname -m)" in
		x86_64|amd64) arch=amd64 ;;
		aarch64|arm64) arch=arm64 ;;
		*) fail "unsupported CPU architecture $(uname -m); amd64 and arm64 are supported." ;;
	esac

	os_id=""; os_version=""
	if [ -r /etc/os-release ]; then
		# shellcheck disable=SC1091
		os_id="$(. /etc/os-release && printf '%s' "${ID:-}")"
		os_version="$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")"
	fi
	case "$os_id $os_version" in
		"ubuntu 22.04"|"ubuntu 24.04"|"debian 12"|"debian 13") ;;
		*) say "note: ${os_id:-this OS} ${os_version} isn't supported yet (Ubuntu 22.04/24.04, Debian 12/13). The report will still work." ;;
	esac

	SUDO=""
	if [ "$(id -u)" -ne 0 ]; then
		command -v sudo >/dev/null 2>&1 || fail "run this as root (or install sudo)."
		SUDO="sudo"
	fi

	asset="upkeeper_linux_${arch}"
	if [ -n "${UPKEEPER_DOWNLOAD_BASE:-}" ]; then
		base="$UPKEEPER_DOWNLOAD_BASE"
	elif [ "$version" = "latest" ]; then
		base="https://github.com/${REPO}/releases/latest/download"
	else
		base="https://github.com/${REPO}/releases/download/${version}"
	fi

	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT INT TERM

	say "downloading ${asset} (${version}) …"
	download "${base}/${asset}" "$tmp/upkeeper" || fail "download failed: ${base}/${asset}"
	download "${base}/checksums.txt" "$tmp/checksums.txt" || fail "download failed: ${base}/checksums.txt"
	download "${base}/checksums.txt.sig" "$tmp/checksums.txt.sig" 2>/dev/null || : > "$tmp/checksums.txt.sig"
	verify_signature "$tmp/checksums.txt" "$tmp/checksums.txt.sig"

	want="$(awk -v a="$asset" '$2 == a || $2 == "*"a { print $1 }' "$tmp/checksums.txt")"
	[ -n "$want" ] || fail "checksums.txt has no entry for ${asset}."
	got="$(sha256_of "$tmp/upkeeper")"
	[ "$want" = "$got" ] || fail "checksum mismatch for ${asset} (expected ${want}, got ${got}). Nothing was installed."
	say "checksum ok."

	chmod 0755 "$tmp/upkeeper"
	"$tmp/upkeeper" version >/dev/null 2>&1 || fail "the downloaded binary doesn't run on this machine."
	$SUDO install -d -m 0755 "$BIN_DIR"
	$SUDO install -m 0755 "$tmp/upkeeper" "$BIN_DIR/upkeeper"
	say "installed $("$BIN_DIR/upkeeper" version)."

	$SUDO install -d -m 0700 /etc/upkeeper /var/cache/upkeeper /var/lib/upkeeper
	if ! $SUDO test -f "$POLICY_PATH"; then
		$SUDO "$BIN_DIR/upkeeper" policy set observe >/dev/null
		say "local policy: observe (reports only). See: upkeeper policy show"
	fi

	if [ -n "$token" ]; then
		# The token goes in on stdin, never on a command line.
		printf '%s\n' "$token" | $SUDO "$BIN_DIR/upkeeper" enroll - --url "$url"
	elif $SUDO test -f "$CONFIG_PATH"; then
		say "already enrolled; keeping ${CONFIG_PATH}."
	else
		say "no enroll token given. Enroll later with: sudo upkeeper enroll <token> --url ${url}"
		start=0
	fi

	if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
		unit_file > "$tmp/upkeeper.service"
		$SUDO install -m 0644 "$tmp/upkeeper.service" "$UNIT_PATH"
		$SUDO systemctl daemon-reload
		if [ "$start" -eq 1 ]; then
			$SUDO systemctl enable upkeeper.service >/dev/null 2>&1
			$SUDO systemctl restart upkeeper.service
			say "service started. Logs: journalctl -u upkeeper -f"
		else
			say "service installed but not started: sudo systemctl enable --now upkeeper"
		fi
	else
		say "systemd isn't running here, so no service was installed. Run 'upkeeper run' under your own supervisor."
	fi
	say "done. The local policy is observe: the agent reports and changes nothing until you run 'sudo upkeeper policy set dry-run' (or auto) and switch on automatic runs in the dashboard."
}

main "$@"
