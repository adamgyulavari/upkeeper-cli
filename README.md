# upkeeper

The open-source server agent for [upkeeper.sh](https://upkeeper.sh): it keeps an Ubuntu/Debian Docker host up to date. This version (M1) updates OS packages and container images; it reports, but doesn't apply, Docker Engine updates and reboots.

> **About this project.** I built upkeeper for my own servers, and most of the code was written with AI coding agents, with reviews and tests along the way. I'm opening it up because it may be useful to others. It runs as root, so read the code before you install it, and don't take my word for anything you can check.
>
> **Status: early, not announced anywhere.** The hosted service isn't open for sign-ups yet.
>
> **This version (M1).** The agent reports what's out of date and, when you allow it on the server and in the dashboard, applies OS package updates and container image updates. An image update that doesn't come back healthy is put back automatically; OS updates can't be undone, so the agent checks the server after them and stops if something looks wrong. It starts in **observe** mode, which only reports, as v0.1.0 did. Docker Engine updates and reboots are not done by this version. Updates that need a person (major versions, for example) are reported and left to you.

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

## Upgrading from v0.1.0

Run the install line again, without a token:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://upkeeper.sh | sh
```

What changes:

- `/usr/local/bin/upkeeper` is replaced by the new version, after the same signature and checksum checks as a new install.
- The systemd unit is replaced. The v0.1.0 unit had a strict read-only sandbox; the new one has none, because apt runs under it (see Security). Drop-ins in `/etc/systemd/system/upkeeper.service.d/` are kept; if you want the old sandbox on a server that stays in observe mode, add the drop-in shown there.
- `/etc/upkeeper/policy.yaml` is created with `mode: observe` if it doesn't exist. v0.1.0 didn't have one, so after the upgrade the server still only reports. Nothing changes on it until you set the policy and switch on automatic runs in the dashboard.
- `/etc/upkeeper/agent.json` is kept, so the server stays enrolled.
- The service is restarted. If a run is in progress, the installer stops without changing anything; run it again later.

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
| Pre-flight | At least 2 GB free on `/` and `/var/lib/docker`; Docker answers if it's installed (otherwise the run is refused and nothing changes). Records every container's state, health, restart policy, restart count and ports |
| Plan | Looks for updates again. An item is applied only if the job approved it, the agent's own classifier still rates it **auto**, and the policy allows it. An image that was put back in an earlier run isn't tried again until a newer one is published |
| OS | Pauses the `apt-daily` and `apt-daily-upgrade` timers if they're active (started again at the end), runs `apt-get update` (one retry after 90 seconds), simulates the exact install, then `apt-get install --only-upgrade pkg=version…`, waiting up to two minutes for apt's lock. Only packages from the distribution's own archive; never Docker packages or held packages. Afterwards it reads the installed versions back with `dpkg-query`. A new kernel is installed but not booted, and running services keep old library versions until they restart: this version restarts nothing |
| Images | Per Compose project, per service: checks that the project's files still describe what's running (below), pulls the new image by the digest seen when planning, recreates the one service with `docker compose up --no-deps`, checks that it got exactly the expected configuration and image, and watches the project. If it doesn't come back healthy, the previous image is put back (L1) |
| Verify | The whole server is compared with the pre-flight state |
| Keep | Old images stay, so they can be put back |

**When the server is frozen.** If something changed and couldn't be checked or put back (an apt error after dpkg started, a project still unhealthy after L1, a run cut off by a crash or a stop of the agent), the run stops and **freezes** the server: no more runs until you check it and run `sudo upkeeper unfreeze`. A failure before anything changed (apt busy, `apt-get update` failing, a download failing) only skips those updates; the next run tries again.

**The health check** is generic: it compares the server with the state recorded at pre-flight, and knows nothing about your apps.

- Every container that was running is running. A container that finished on its own doesn't count against this: one that exited with code 0 and whose restart policy is `no` or `on-failure`, or one started with `--rm` that is gone (a cron-started backup, a CI job). A container with restart policy `always` or `unless-stopped` must keep running.
- Containers with a healthcheck are healthy. "starting" is waited for as long as the healthcheck can take (its start period, then retries × (interval + timeout)), at most 10 minutes; a project whose healthcheck can't report within 10 minutes is skipped.
- Restart counts don't rise during the check; no new out-of-memory kills.
- Published TCP ports that accepted connections still do, and ports that answered HTTP answer with the same status class. The probe connects to the container's own address and port, because on the host side Docker's proxy accepts connections whenever the container runs, listening or not. Containers without their own address (host networking) are probed on the host port, which only shows that something accepts there.
- No new failed systemd units; Docker still answers if it answered before.

Log lines that look bad are notes in the run record; they never decide the check.

**Image updates and your compose files.** The agent never edits your compose files. Before touching a project it asks Compose for each service's configuration hash (`docker compose config --hash`, with the same files and project directory, and the agent's own environment) and requires it to equal the hash on the running containers. So a run only ever changes the image. A project is skipped, with the reason in the run record and a `compose_mismatch` risk in the report, when:

- its compose files were changed after the last `docker compose up` (run `docker compose up -d` yourself first);
- it uses variables that aren't set for the agent (from your shell or a script; put them in the project's `.env` file);
- it runs a different number of containers than its files ask for (started with `--scale`);
- its compose files use `include:` or `extends:`.

A new version tag goes into `compose.override.upkeeper.yml` next to your first compose file, and the agent adds it with `-f` when it runs compose. If you run `docker compose up` yourself without that file, the old tag comes back and the agent then skips the project until the files and the running service agree again: run compose with `-f compose.override.upkeeper.yml` after your own files, or copy the tag into your compose file and remove the entry from the override.

**About undo.** Putting an image back restores the container, not your data. If the new version changed data in a volume or bind mount while it ran (a migration on start, for example), that change stays. That's why, for services that write data on the host, only patch releases are automatic.

**What stays out of automatic runs** (reported, and left to you): major versions; minor versions of services that write data on the host (label a service `upkeeper.policy=auto-minor` to allow them; database images stay out regardless), and floating tags like `latest` on those services; images this agent first saw less than 3 days ago; packages from third-party apt sources; anything Coolify manages; services that weren't running when the run started (the agent never starts a stopped service or a finished job); containers whose image sets Docker Compose labels itself; projects whose compose files aren't owned by root, are writable by group or others, or sit inside a container's mount (in practice, projects under `/opt`, `/srv` or `/root` work, and projects in a user's home directory don't). Labels `upkeeper.policy=pin` and `upkeeper.policy=supervised` keep a service out entirely.

## Security

**Connection.** Outbound HTTPS only, to the control plane. No inbound ports, no SSH, no cloud provider keys.

**No arbitrary commands.** Every command the agent can run is in a fixed allowlist with exact argument shapes ([`agent/host`](agent/host)); a source-scan test fails the build if write code appears outside [`agent/run`](agent/run). There is no shell: every argument is passed as a separate value and must match the allowed shape (package names and versions, absolute paths, service names). The write commands are `apt-get update`, `apt-get install --only-upgrade pkg=version…`, `docker compose … up -d --no-deps --no-build --force-recreate --pull never <service>`, and `systemctl stop|start` of exactly `apt-daily.timer` and `apt-daily-upgrade.timer`, plus two Docker Engine API calls (pull by digest, tag). `docker compose … config --hash|--format json` and `systemctl is-active` of those two timers only read.

**Signed jobs.** Jobs are signed by an online key whose certificate is signed by an offline root key compiled into the binary (`make build ROOT_KEYS=…`). Nothing is pinned from the network. A build without a root key accepts no jobs. Development builds (`make build-dev`) also trust a TEST root whose private key is public; never run one on a server you care about.

**Files from containers aren't trusted.** Docker labels can come from an image, so compose paths from labels are used only after checking ownership, permissions, symlinks and container mounts; projects whose compose files use `include:` or `extends:` are skipped, because those pull in files the agent doesn't check. The files must not change between the check and `compose up`, and the configuration hash check above makes sure `compose up` reproduces what was already running, apart from the image.

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

then `sudo systemctl daemon-reload && sudo systemctl restart upkeeper`. Keep that server's policy at `observe`: with this sandbox apt can't work, and the override file can't be written under `/root` or `/home`.

## Supported

Ubuntu 22.04 / 24.04, Debian 12 / 13, `docker-ce` or `docker.io`, Compose v2 (2.20 or newer for image updates). On Coolify hosts, Coolify keeps managing its containers; the agent only looks after the host.

Other releases, Ubuntu 26.04 among them, aren't supported yet: the agent reports on them but refuses automatic runs, and says so in the report. Supporting a release means checking apt's output and its maintainer scripts there first, which hasn't been done for 26.04.

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
docs/                the real-VM test plan
```

## Develop

```sh
make check      # go vet + go test
make build      # static linux/amd64 and linux/arm64 binaries + checksums in bin/ (add ROOT_KEYS=…)
make build-dev  # also trusts the TEST root; for local testing only
```

Releases: bump `VERSION` on `main`; the Release workflow builds a draft, which is signed offline and then published.

## License

Apache-2.0
