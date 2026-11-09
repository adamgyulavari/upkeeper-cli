#!/bin/sh
# upkeeper.sh agent installer.
#
#   curl -fsSL upkeeper.sh | sh -s -- <enroll-token>
#   curl -fsSL upkeeper.sh | sh -s -- <enroll-token> --url http://localhost:8080
#
# Downloads the agent from GitHub releases, checks its sha256, installs
# /usr/local/bin/upkeeper and a systemd unit, then enrolls this server.
# Run it again without a token to upgrade the agent in place.
#
# Options (or environment):
#   --url URL        control plane (UPKEEPER_URL, default https://upkeeper.sh)
#   --version vX.Y.Z release to install (UPKEEPER_VERSION, default latest)
#   --no-start       install and enroll, but don't start the service
# Also: UPKEEPER_DOWNLOAD_BASE overrides the release download URL (mirrors, tests).
#
# Everything is inside main() so a cut-off download runs nothing.

set -eu

REPO="adamgyulavari/upkeeper-cli"
BIN_DIR="/usr/local/bin"
UNIT_PATH="/etc/systemd/system/upkeeper.service"
CONFIG_PATH="/etc/upkeeper/agent.json"

say() { printf '%s\n' "upkeeper: $*"; }
fail() { printf '%s\n' "upkeeper: $*" >&2; exit 1; }

unit_file() {
	# Keep in sync with deploy/upkeeper.service (a test checks this).
	cat <<'UNIT'
[Unit]
Description=upkeeper.sh agent (read-only staleness report)
Documentation=https://upkeeper.sh
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/upkeeper run
Restart=always
RestartSec=30s

# Runs as root: the Docker socket and apt's state are root-only. M0 never
# changes the system, so everything but its own config and cache is read-only.
ConfigurationDirectory=upkeeper
ConfigurationDirectoryMode=0700
CacheDirectory=upkeeper
CacheDirectoryMode=0700
ReadWritePaths=-/etc/upkeeper
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
}

download() { # url dest
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https,http' --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		fail "needs curl or wget to download the agent."
	fi
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
	while [ $# -gt 0 ]; do
		case "$1" in
			--url) [ $# -ge 2 ] || fail "--url needs a value"; url="$2"; shift 2 ;;
			--url=*) url="${1#--url=}"; shift ;;
			--version) [ $# -ge 2 ] || fail "--version needs a value"; version="$2"; shift 2 ;;
			--version=*) version="${1#--version=}"; shift ;;
			--no-start) start=0; shift ;;
			-h|--help) sed -n '2,16p' "$0" 2>/dev/null || true; exit 0 ;;
			-*) fail "unknown option $1" ;;
			*) [ -z "$token" ] || fail "only one enroll token, please"; token="$1"; shift ;;
		esac
	done

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

	$SUDO install -d -m 0700 /etc/upkeeper /var/cache/upkeeper

	if [ -n "$token" ]; then
		$SUDO "$BIN_DIR/upkeeper" enroll "$token" --url "$url"
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
	say "done. This version only reads and reports; it changes nothing on this server."
}

main "$@"
