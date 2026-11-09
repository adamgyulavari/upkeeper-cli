# upkeeper

The open-source server agent for [upkeeper.sh](https://upkeeper.sh): it keeps an Ubuntu/Debian Docker host up to date, covering OS packages, the kernel, Docker Engine and container images.

> **Status: M0, read-only.** This version only reads the server and reports what's out of date. It contains no action that changes anything, and a test (`agent/host`) fails the build if one appears.

## Install

```sh
curl -fsSL upkeeper.sh | sh -s -- <enroll-token>
```

Get the enroll token from your upkeeper.sh dashboard (**Add server**). The installer:

- detects your OS and architecture;
- downloads the binary from this repo's [releases](https://github.com/adamgyulavari/upkeeper-cli/releases) and verifies its sha256;
- installs `/usr/local/bin/upkeeper` and a hardened systemd unit;
- enrolls the server.

Read [`deploy/install.sh`](deploy/install.sh) before running it.

To try it without the dashboard:

```sh
upkeeper report --print --offline   # collect once, print JSON, send nothing
```

## What it does

| | |
|---|---|
| Connection | Outbound HTTPS only, to the control plane. No inbound ports, no SSH, no cloud provider keys |
| Collects | OS and kernel, pending apt updates (simulated, never applied), Docker Engine/Compose versions, Compose projects, containers, health, ports |
| Looks up | Newer image versions on Docker Hub, ghcr.io and quay.io (anonymous, cached 6 h); newer Docker Engine releases |
| Classifies | Every pending update as **auto**, **flagged** (needs a supervised run) or **never** (pinned/held/Coolify-managed), with a plain-language reason |
| Writes | Only `/etc/upkeeper/agent.json` (its token, 0600) and `/var/cache/upkeeper` |

Supported: Ubuntu 22.04 / 24.04, Debian 12 / 13, `docker-ce` or `docker.io`, Compose v2. On Coolify hosts, Coolify keeps managing its containers; the agent only looks at the host.

## Layout

```
cmd/upkeeper/   CLI and daemon
agent/          collectors, update discovery, classifier, report loop
protocol/       the wire contract with the control plane (imported by it)
deploy/         install.sh and the systemd unit
```

## Develop

```sh
make check   # go vet + go test
make build   # static linux/amd64 and linux/arm64 binaries + checksums in bin/
```

Releases are published by pushing a `v*` tag.

## License

Apache-2.0
