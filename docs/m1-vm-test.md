# M1 real-VM test plan

The first runs that change a server happen on a throwaway VM, never first on a real server (M1 spec §0.7). This plan takes about two hours, most of it waiting for checks.

What it proves:

1. Install, enroll, observe mode: reports only.
2. The dry run changes nothing and lists what it would do.
3. An auto run upgrades packages and one image, catches a deliberately broken image, puts the old one back (L1) and ends `undone`.
4. A run cut off halfway freezes the server, and `upkeeper unfreeze` lifts it.
5. Uninstall leaves nothing behind but the override file.

You need: an account with any VPS provider (the steps below use a DigitalOcean droplet; Hetzner, Vultr or anything else with Ubuntu images works the same, since upkeeper never talks to the provider), a GitHub account with a **public** GHCR package you can push to, and a control plane (M1) the VM can reach over HTTPS.

There are two parts:

- **Part A, a throwaway VM** (sections 1 to 9): the image update, the deliberately broken image, undo, freeze and uninstall. A fresh VM has few pending OS updates, so it says little about the OS step.
- **Part B, a staging server you can afford to break** (section 10): a real backlog of OS updates. Do it after part A, with a snapshot or backup taken first.

## 0. Keys and builds (on your laptop)

Jobs are signed. The agent only accepts a job whose key carries a certificate from a root key built into the agent binary. So you need a root key, an online key certified by it, and agent builds that trust that root.

```sh
cd upkeeper-cli && git checkout m1
make keys                                        # bin/upkeeper-keys
bin/upkeeper-keys gen-root -id root-2026 -out root.key      # keep root.key off every server
# prints: Build agents with: ROOT_KEYS=root-2026:<base64>
bin/upkeeper-keys gen-online -id online-1 -out online.key   # prints the public key
bin/upkeeper-keys sign-cert -root root.key -root-id root-2026 -key-id online-1 -pub <public key printed above> -days 14 > cert.json
```

Set these on the control plane and redeploy it:

- `JOB_SIGNING_KEY` = content of `online.key`
- `JOB_KEY_CERT` = content of `cert.json`
- `JOB_ROOT_KEYS` = `root-2026:<base64>` (the value printed by `gen-root`)

A control plane that isn't running in development mode refuses certificates from the public TEST root, so use your own root key as above.

Build two agents, both trusting your root:

```sh
make build-dev ROOT_KEYS=root-2026:<base64>   # bin/upkeeper_dev_linux_amd64: for the throwaway VM only
make build     ROOT_KEYS=root-2026:<base64>   # bin/upkeeper_linux_amd64: for the staging server
```

The **development build** also accepts `UPKEEPER_DEV_MIN_RELEASE_AGE`, so a freshly pushed test image doesn't have to wait 3 days, and it also trusts the public TEST root. Never install it on a server you care about; delete the throwaway VM when you're done.

## 1. The VM

1. Create a VM with **Ubuntu 24.04**, 2 GB RAM or more, and your SSH key. On DigitalOcean: Create → Droplets → Ubuntu 24.04 (LTS) x64 → Basic, Regular, 2 GB / 1 CPU. Name it `upk-m1-test`. (The checks in section 3a also ask for a second run on Ubuntu 22.04; create that droplet when you get there.)
2. Log in and update nothing yet (we want pending updates):

   ```sh
   ssh root@<ip>
   apt-get update            # refresh the lists only, so updates show up
   apt list --upgradable | head
   ```

3. Install Docker from Docker's repository (docs.docker.com/engine/install/ubuntu), then check:

   ```sh
   docker version --format '{{.Server.Version}}'
   docker compose version     # 2.20 or newer
   ```

## 2. The test images

On your laptop, build two tags of a tiny web image and push them to GHCR. Make the package **public** (GitHub → Packages → upk-demo → Package settings → Change visibility), since the agent looks up tags anonymously.

```sh
mkdir upk-demo && cd upk-demo
cat > Dockerfile.good <<'EOF'
FROM busybox:1.36
RUN mkdir -p /www && echo ok > /www/index.html
HEALTHCHECK --interval=5s --timeout=2s --retries=3 CMD wget -q -O- http://127.0.0.1:8080/ || exit 1
CMD ["httpd", "-f", "-p", "8080", "-h", "/www"]
EOF
cat > Dockerfile.broken <<'EOF'
FROM busybox:1.36
CMD ["sh", "-c", "echo 'FATAL: this release is broken on purpose'; exit 1"]
EOF
docker buildx build --platform linux/amd64 -f Dockerfile.good   -t ghcr.io/<you>/upk-demo:1.0.0 --push .
docker buildx build --platform linux/amd64 -f Dockerfile.broken -t ghcr.io/<you>/upk-demo:1.0.1 --push .
```

## 3. The Compose project (on the VM)

```sh
mkdir -p /opt/demo && cd /opt/demo
cat > compose.yml <<'EOF'
services:
  web:
    image: ghcr.io/<you>/upk-demo:1.0.0
    ports: ["8080:8080"]
    restart: unless-stopped
  cache:
    image: redis:7.4.1
    restart: unless-stopped
EOF
docker compose up -d
docker compose ps            # both running, web healthy
curl -s localhost:8080       # ok
ls -ld /opt /opt/demo /opt/demo/compose.yml   # root-owned, not group/world-writable
```

The agent refuses projects whose compose files aren't root-owned or are writable by group or others, so keep the default modes.

## 3a. Check the assumptions first

The agent relies on how apt, systemd, Docker and Compose behave on a real server. Run these nine checks on the VM before installing the agent (steps 1, 6 and 7 need it installed; do those parts during sections 6 and 7). Each has an expected result; if one doesn't match, stop and report it.

Some were already checked with Docker 29.9.2 and Compose 5.6.1 on Ubuntu 24.04 during development (marked "seen locally"); repeat them here anyway, since your versions differ.

1. **apt and kernel scripts work under the agent's unit.**
   Before installing the agent: `systemd-run --wait --pipe -p ReadOnlyPaths=/etc/upkeeper grub-probe --target=fs_uuid /` and `systemd-run --wait --pipe blkid`.
   **Expect** a UUID and the block devices, no "Permission denied" or "cannot open".
   During section 6, with a kernel update in the plan: **expect** `dpkg --audit` to print nothing, `journalctl -k | grep -i oom` to show nothing new, and `systemctl show upkeeper -p DevicePolicy -p MemoryMax` to show `DevicePolicy=auto` and `MemoryMax=infinity`. Repeat once on **Ubuntu 22.04**.

2. **Compose reproduces the project, or the agent skips it.**
   Start three extra projects: one with `FOO=bar docker compose up -d` where `${FOO}` is used in `environment:`; one with `docker compose up -d --scale web=2`; one started from the parent directory with `-f sub/compose.yml`. Then edit `/opt/demo/compose.yml` (add an environment variable) without running `up`.
   **Expect** in the next run's record: the first skipped with "use variables that aren't set … (FOO)", the second with "runs 2 containers, but its compose files ask for 1", the edited one with "The compose files on disk no longer match what's running", each with code `compose_mismatch`, and the dashboard showing the risk. `docker inspect` of those containers is unchanged (same IDs). Revert the edit and run `docker compose up -d`; the next run updates the project again.

3. **`docker compose config --hash` equals the container label** (seen locally).
   `docker compose -p demo -f /opt/demo/compose.yml config --hash web` and `docker inspect demo-web-1 -f '{{index .Config.Labels "com.docker.compose.config-hash"}}'`.
   **Expect** the same value. With a `.env` in `/opt/demo`, again the same. If they differ on a fresh, untouched project, every project is skipped: report the Compose version.

4. **The port probe goes to the container** (docker-proxy accepting with nothing listening was seen locally).
   `docker run -d --name probe -p 5555:5555 busybox sleep 1d`; `nc -vz 127.0.0.1 5555` (**expect** "succeeded": that's docker-proxy) and `nc -vz $(docker inspect probe -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}') 5555` (**expect** "refused"). `docker rm -f probe`.

5. **Labels after the agent's `up`.**
   After section 6: `docker inspect demo-cache-1 -f '{{index .Config.Labels "com.docker.compose.project.config_files"}}'`.
   **Expect** `/opt/demo/compose.yml,/opt/demo/compose.override.upkeeper.yml`, and `demo-web-1` lists only `compose.yml`. A second run with another update to `demo` must not skip it as "disagree about the project's directory or compose files".

6. **Recreate keeps anonymous volumes and leaves other services alone** (anonymous volumes seen locally).
   Add a service `pg: {image: postgres:16.4, environment: {POSTGRES_PASSWORD: x}}` with no `volumes:`, `docker compose up -d`, then `docker compose exec pg psql -U postgres -c 'create table t(x int); insert into t values (1)'`. Let a patch update of `pg` run (or tag an older 16.x to force one).
   **Expect** `select * from t` still returns 1 after the update and after an undo, and `demo-web-1` keeps its container ID.

7. **Pull by digest and tag back, on both image stores.**
   During section 6, on the default store of your Docker version, then again with `"features": {"containerd-snapshotter": true}` (or `false`) in `/etc/docker/daemon.json` and a Docker restart.
   **Expect** `docker image inspect ghcr.io/<you>/upk-demo@sha256:<digest>` to work after the pull, the web container to run exactly that image ID, and after the undo `docker image inspect ghcr.io/<you>/upk-demo:1.0.0 -f '{{.Id}}'` to equal the ID it ran before.

8. **A failed `up` can be put back.**
   Push a third tag whose `HEALTHCHECK` refers to a missing binary, or publish a port that's already taken on the host, and let a run update to it.
   **Expect** the run to end `undone`, `docker ps -a` to show no leftover `<hash>_demo-web-1` containers, and the web container running the previous image.

9. **apt keeps marks, config files and holds.**
   Before section 6: `apt-mark showauto > /root/auto-before`; edit `/etc/ssh/sshd_config` (add a comment) if an openssh update is pending; `apt-mark hold` one dependency of a pending package.
   **Expect** after the run: `diff <(apt-mark showauto) /root/auto-before` shows no package moving from auto to manual (if it does, note which: the agent installs with `pkg=version`); your `sshd_config` edit is still there and no prompt blocked the run; the held package is unchanged, and the package that needs it is skipped with apt's reason rather than half-installed.

## 4. Install and enroll

There's no signed release of M1 yet, so copy the development build by hand:

```sh
# laptop
scp bin/upkeeper_dev_linux_amd64 root@<ip>:/usr/local/bin/upkeeper
scp deploy/upkeeper.service root@<ip>:/etc/systemd/system/upkeeper.service

# VM
chmod 0755 /usr/local/bin/upkeeper
install -d -m 0700 /etc/upkeeper /var/lib/upkeeper /var/cache/upkeeper
upkeeper policy set observe
mkdir -p /etc/systemd/system/upkeeper.service.d
cat > /etc/systemd/system/upkeeper.service.d/vm-test.conf <<'EOF'
[Service]
Environment=UPKEEPER_DEV_MIN_RELEASE_AGE=0s
EOF
read -r UPKEEPER_ENROLL_TOKEN && export UPKEEPER_ENROLL_TOKEN   # paste the token from "Add server"
upkeeper enroll --url https://<your control plane>
systemctl daemon-reload && systemctl enable --now upkeeper
journalctl -u upkeeper -f
```

**Expect** in the log: `Local policy: observe`, `Trusted root keys:` listing `root-2026` and `TEST-ROOT-DO-NOT-USE`, a warning that this is a development build, and `report sent` lines.

**Check:**

- `upkeeper status`: mode observe, not frozen, your root key and the TEST root, "no job has arrived yet".
- Dashboard: the server shows OS updates (auto), `demo/cache` 7.4.1 → 7.4.x (auto), `demo/web` 1.0.0 → 1.0.1 (auto), redis 8 (flagged, major), and "Local policy: observe".
- Switch on "Automatic runs" and press "Run now". **Expect** the run to be **rejected**: "the local policy on this server is observe …" (or the dashboard doesn't offer runs while it shows observe). Nothing changed (`ls /opt/demo` shows no override file).

## 5. Dry run

```sh
upkeeper policy set auto       # the agent turns the next job into a dry run anyway
upkeeper policy show
```

Press "Run now".

**Expect:**

- Run record: preflight, plan, `Would refresh the package lists`, `Would upgrade N packages`, `Would pull … and recreate web/cache`, `Would check …`, keep.
- Summary: `Dry run: would update N packages and 2 images. Nothing was changed.`
- On the VM nothing changed: `apt list --upgradable` unchanged, `docker compose ps` shows the same container IDs, no `/opt/demo/compose.override.upkeeper.yml`, no `/var/lib/upkeeper/run.json`.

## 6. Auto run with a broken image

Press "Run now" again (the scheduler's job works too, inside the window).

**Expect, in about 10–15 minutes:**

1. OS: `apt-get update`, `Upgraded N packages.` If a kernel was in the list: "The new kernel is used after the next reboot; this version doesn't reboot."
2. A 3-minute whole-server check after the OS step: green.
3. `cache` pulled by digest, recreated, `demo` checked for 3 minutes: healthy.
4. `web 1.0.1` pulled and recreated; it exits at once and restarts. The check goes red ("demo/web isn't running" or "restarted N times"); a note quotes the `FATAL:` log line.
5. L1: `Put the previous image of web back; it's healthy again.`
6. Final check green, keep.
7. Summary: `web 1.0.1 didn't come back healthy, so 1.0.0 is running again. Updated N packages and 1 image.` Outcome **undone**, not frozen.

**Check on the VM:**

```sh
cd /opt/demo
cat compose.override.upkeeper.yml   # only cache: image "redis:7.4.x"; no web entry
docker compose -f compose.yml -f compose.override.upkeeper.yml ps   # web on 1.0.0 and healthy
curl -s localhost:8080               # ok
cat compose.yml                      # unchanged: still web 1.0.0, cache 7.4.1
apt list --upgradable                # the upgraded packages are gone from the list
upkeeper status                      # job key vmtest-1, last full run just now
```

Press "Run now" once more. **Expect** it to be rejected locally: "The last full run was … ago. This server allows one every 20 hours."

## 7. A run cut off halfway: freeze and unfreeze

1. Reset the local run history so a run can start again. This also means the next job is a dry run first:

   ```sh
   rm /var/lib/upkeeper/runs.json
   ```

2. Press "Run now" (dry run), then "Run now" again (auto). While its events show the OS step or a 3-minute check:

   ```sh
   systemctl kill -s KILL upkeeper     # simulates a crash; systemd restarts it
   ```

3. **Expect** after the restart: the log says a run was cut off; the run record ends **stopped**, frozen, with "The agent stopped in the middle of a run (during the … step) …". `upkeeper status` shows `Frozen: yes`. The next "Run now" is rejected: "This server is frozen …".
4. Check the server, then:

   ```sh
   upkeeper unfreeze
   upkeeper status        # Frozen: no
   ```

If apt was killed halfway, `dpkg --audit` lists half-configured packages; `dpkg --configure -a` fixes them. That's why the agent freezes instead of carrying on.

## 8. Things worth trying if there's time

- `upkeeper policy window "sun 03:00-05:00"` on a weekday, then "Run now": rejected, "outside this server's local maintenance window".
- `chmod g+w /opt/demo/compose.yml`, then a run with an image update: the project is skipped with "Can't verify where this project's compose file lives (… writable by group or others …)". Undo with `chmod g-w`.
- `upkeeper policy set dry-run` with an auto job: it runs as a dry run.
- `systemctl stop docker`, then "Run now": the run is rejected at pre-flight, "Docker is installed but isn't answering … Nothing was changed."
- `systemctl list-timers apt-daily*` during an auto run: both timers are stopped while the OS step runs and listed again afterwards.
- Start `apt-get install -y sl` in another shell just before the OS step: the agent waits for the lock (up to two minutes) and either goes on or skips the OS updates with "Another program kept apt busy … Nothing was installed". It doesn't freeze.
- `systemctl restart upkeeper` during the apt step (not `kill -KILL`): apt finishes (`dpkg --audit` is clean), and the run is recorded as stopped and the server frozen.
- `docker compose stop cache`, then a run with a cache update: cache stays stopped, and the item is skipped with "It wasn't running when the run started".
- Run the installer again (as an upgrade) while a run is in progress: it stops with "a maintenance run is in progress … Nothing was changed."

## 9. Uninstall

```sh
systemctl disable --now upkeeper
rm -rf /etc/systemd/system/upkeeper.service /etc/systemd/system/upkeeper.service.d /usr/local/bin/upkeeper
rm -rf /etc/upkeeper /var/lib/upkeeper /var/cache/upkeeper
systemctl daemon-reload
```

`/opt/demo/compose.override.upkeeper.yml` stays. Then delete the VM at your provider and remove the server in the dashboard.

## 10. Part B: a staging server with a real backlog

Do this only after part A went as expected, on a server you can afford to break, with a provider snapshot or backup taken first.

What it adds: an OS step with many pending packages (a fresh VM has few), on a server with real services. On a Dokku or other non-Compose host, upkeeper updates OS packages only: containers outside a Compose project are left alone and listed as skipped with that reason.

1. Take a snapshot or backup at your provider.
2. Install the **regular** build (not the development build):

   ```sh
   # laptop
   scp bin/upkeeper_linux_amd64 root@<staging>:/usr/local/bin/upkeeper.new
   scp deploy/upkeeper.service root@<staging>:/etc/systemd/system/upkeeper.service
   # staging
   systemctl stop upkeeper
   install -m 0755 /usr/local/bin/upkeeper.new /usr/local/bin/upkeeper && rm /usr/local/bin/upkeeper.new
   install -d -m 0700 /var/lib/upkeeper
   systemctl daemon-reload && systemctl start upkeeper
   upkeeper status        # mode observe, your root key only (no TEST root)
   ```

   The server keeps its enrollment (`/etc/upkeeper/agent.json`).
3. `upkeeper policy set dry-run`, switch on "Automatic runs" for the server in the dashboard, press "Run now". **Expect** a dry run that lists the OS packages it would upgrade and skips everything else with a reason. `apt list --upgradable | wc -l` is unchanged.
4. `upkeeper policy set auto`, "Run now" again (at most one full run per 20 hours; the first run after switching to auto is a dry run, so this is the second day at the earliest).
   **Expect:**
   - the pending packages installed, except held ones, Docker's packages and anything from a third-party repository;
   - the kernel installed but **no reboot**;
   - the same containers running afterwards as before;
   - the run ends `done` or `partial`, with reasons for what was skipped.
5. Afterwards: `dpkg --audit` prints nothing, `systemctl --failed` shows nothing new, `systemctl is-active apt-daily.timer apt-daily-upgrade.timer` says active, and the apps answer.

If anything looks wrong: `upkeeper policy set observe` stops further runs at once, and `journalctl -u upkeeper` plus the run record show what happened.

## What to send back

- The run records of the dry run, the auto run and the cut-off run (screenshots or the JSON).
- `journalctl -u upkeeper --since today > upkeeper.log`.
- Anything in the wording that sounds wrong or alarming.
