# upkeeper

The open-source server agent for [upkeeper.sh](https://upkeeper.sh): it keeps an Ubuntu/Debian Docker host up to date, covering OS packages, the kernel, Docker Engine and container images.

> **About this project.** I built upkeeper for my own servers, and most of the code was written with AI coding agents, with reviews and tests along the way. I'm opening it up because it may be useful to others. It runs as root, so read the code before you install it, and don't take my word for anything you can check.
>
> **Status: early, not announced anywhere.** The hosted service isn't open for sign-ups yet.
>
> **Status: M1.** The agent reports what's out of date and, when you allow it, applies OS updates and image updates it can undo. It starts in **observe** mode, which only reports, as in M0. Docker Engine updates and reboots come in M2.

## Install

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://upkeeper.sh | UPKEEPER_ENROLL_TOKEN=<enroll-token> sh
```

The dashboard's **Add server** page shows the exact line with a one-time token. Always fetch the script over `https://`; it runs as root. The installer:

- detects your OS and architecture;
- downloads the binary from this repo's [releases](https://github.com/adamgyulavari/upkeeper-cli/releases), checks the release signature on `checksums.txt` with `ssh-keygen -Y verify`, then the binary's sha256;
- installs `/usr/local/bin/upkeeper`, a systemd unit and `/etc/upkeeper/policy.yaml` (`mode: observe`);
- enrolls the server (the token goes in on stdin, not on a command line).

Read [`deploy/install.sh`](deploy/install.sh) before running it. To try the agent without the dashboard:

```sh
upkeeper report --print --offline   # collect once, print JSON, send nothing
```

## Turning on automatic runs

A server runs nothing until **both** keys are turned:

1. **On the server**, as root:

   ```sh
   sudo upkeeper policy set dry-run   # go through runs, change nothing
   sudo upkeeper policy set auto      # apply updates that can be undone
   ```

2. **In the dashboard**: switch on "Automatic runs" for the server.

The dashboard can never allow more than the local policy. Even in `auto`, the agent keeps its own limits:

- the first run after the policy becomes `auto` is a dry run;
- at most one full run and one security run every 20 hours;
- an optional local window: `sudo upkeeper policy window "sun 03:00-05:00"` (server time); jobs outside it are refused;
- a job runs at most once, and only if it's signed with a key certified by the root key built into the binary.

`upkeeper status` shows the policy, the freeze state, the root keys this build trusts and the key of the last job.

## What a run does

`pre-flight → plan → OS packages → images (one at a time) → verify → keep`

| Step | What happens |
|---|---|
| Pre-flight | No dpkg lock, at least 2 GB free on `/` and `/var/lib/docker`, Docker answers. Records every container's state, health, restart count and ports |
| Plan | Looks for updates again. An item is applied only if the job approved it, the agent's own classifier still rates it **auto**, and the policy allows it |
| OS | `apt-get update`, a simulation of the exact install, then `apt-get install --only-upgrade pkg=version…`. Only packages from the distribution's own archive; never Docker packages or held packages. A new kernel is installed but not booted |
| Images | Pulled by the digest seen when planning, then one service at a time is recreated with `docker compose up` and the project is watched for 3 minutes. If it doesn't come back healthy, the previous image is put back (L1) |
| Verify | The whole server is compared with the pre-flight state |
| Keep | Old images stay, so they can be put back |

Anything unexpected (an apt error, a project that stays unhealthy after L1, a run cut off by a crash) stops the run and **freezes** the server: no more runs until you check it and run `sudo upkeeper unfreeze`. OS updates can't be undone automatically, so the agent stops and says what happened.

**Version updates and your compose files.** The agent never edits your compose files. A new version tag goes into `compose.override.upkeeper.yml` next to your first compose file, and the agent adds it with `-f` when it runs compose. If you run `docker compose up` yourself without that file, the old tag comes back: copy the tag into your compose file to make it permanent, and remove the entry from the override.

What stays out of automatic runs (and waits for a supervised run): major versions, minor versions of services that keep database data, images younger than 3 days, packages from third-party apt sources, anything Coolify manages, containers whose image sets Docker Compose labels itself, and projects whose compose files aren't owned by root or sit inside a container's mount.

## Security

**Connection.** Outbound HTTPS only, to the control plane. No inbound ports, no SSH, no cloud provider keys.

**No arbitrary commands.** Every command the agent can run is in a fixed allowlist with exact argument shapes ([`agent/host`](agent/host)); a source-scan test fails the build if write code appears outside [`agent/run`](agent/run). There is no shell: every argument is passed as a separate value and must match the allowed shape (package names and versions, absolute paths, service names). The write commands are `apt-get update`, `apt-get install --only-upgrade pkg=version…`, and `docker compose … up -d --no-deps --pull never <services>`, plus two Docker Engine API calls (pull by digest, tag).

**Signed jobs.** Jobs are signed by an online key whose certificate is signed by an offline root key compiled into the binary (`make build ROOT_KEYS=…`). Nothing is pinned from the network. A build without a root key accepts no jobs. Development builds (`make build-dev`) also trust a TEST root whose private key is public; never run one on a server you care about.

**Files from containers aren't trusted.** Docker labels can come from an image, so compose paths from labels are used only after checking ownership, permissions, symlinks and container mounts, and the files must not change between the check and `compose up`.

**The systemd unit.** In M0 the unit had a strict read-only sandbox. M1 upgrades packages, and apt, dpkg and their maintainer scripts run as children of the agent's service. Those scripts write `/usr`, `/etc`, `/boot` and `/var`, set setuid bits, open block devices (`update-grub`, `grub-probe`, `blkid` in initramfs hooks), load kernel modules, build DKMS modules and compress initramfs images, which can take more than a gigabyte of memory. Any sandbox setting is inherited by them: `ProtectClock` or `PrivateDevices` closes the device list, `MemoryMax` lets the kernel kill a postinst halfway, `ProtectHome` blocks the override file under `/root` or `/home`, and a syscall filter kills foreign-architecture scripts.

Two ways were considered: start apt in a separate transient unit (`systemd-run`), or run it in the agent's unit without a sandbox. M1 does the second. It is one fixed file that a test checks, it behaves the same on every supported release, and it doesn't add another command to the allowlist. So the M1 unit keeps only `/etc/upkeeper` read-only for the service (the policy and config change only through `sudo upkeeper …`), a normal umask, and `KillMode=process`, so a stopped service lets apt finish instead of killing it halfway. Everything else from M0 (`ProtectSystem`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `ProtectClock`, `ProtectKernel*`, `ProtectControlGroups`, `MemoryMax`, `TasksMax`, syscall and address-family filters, `NoNewPrivileges`, `CapabilityBoundingSet`) is gone, and a test (`deploy/deploy_test.go`) fails if one comes back.

Be clear about what the sandbox meant: the agent can use the Docker socket, which is root-equivalent, so the sandbox never contained a compromised agent, in M0 either. The real limits are the allowlist, the signed-job checks and the local policy.

On a server that stays in **observe** mode you can bring back the strict M0 sandbox with a drop-in:

```ini
# /etc/systemd/system/upkeeper.service.d/observe-only.conf
[Service]
ProtectSystem=strict
ReadWritePaths=-/var/cache/upkeeper -/var/lib/upkeeper
ProtectHome=read-only
PrivateTmp=yes
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
MemoryDenyWriteExecute=yes
UMask=0077
```

then `sudo systemctl daemon-reload && sudo systemctl restart upkeeper`. With it, any run fails at its first write and freezes the server, which is what you want there.

## Supported

Ubuntu 22.04 / 24.04, Debian 12 / 13, `docker-ce` or `docker.io`, Compose v2 (2.20 or newer for image updates). On Coolify hosts, Coolify keeps managing its containers; the agent only looks after the host.

## Uninstall

```sh
sudo systemctl disable --now upkeeper
sudo rm -f /etc/systemd/system/upkeeper.service /usr/local/bin/upkeeper
sudo rm -rf /etc/upkeeper /var/lib/upkeeper /var/cache/upkeeper
sudo systemctl daemon-reload
```

`compose.override.upkeeper.yml` files stay where they are; remove them after copying any tags you want to keep into your compose files.

## Layout

```
cmd/upkeeper/        CLI and daemon
cmd/upkeeper-keys/   offline tool for the job-signing keys
agent/               collectors, discovery, classifier, report loop,
                     policy, job client (jobs), run engine (run), health check (verify)
protocol/            the wire contract with the control plane (imported by it)
deploy/              install.sh and the systemd unit
docs/                release steps, the real-VM test plan
```

## Develop

```sh
make check      # go vet + go test
make build      # static linux/amd64 and linux/arm64 binaries + checksums in bin/ (add ROOT_KEYS=…)
make build-dev  # also trusts the TEST root; for local testing only
```

Releases: bump `VERSION` on `main`; the Release workflow builds a draft, which is signed offline and then published ([docs/RELEASING.md](docs/RELEASING.md)).

## License

Apache-2.0
