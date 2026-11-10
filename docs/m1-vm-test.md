# M1 real-VM test plan

The first runs that change a server happen on a throwaway VM, never first on a real server (M1 spec §0.7). This plan takes about two hours, most of it waiting for checks.

What it proves:

1. Install, enroll, observe mode: reports only.
2. The dry run changes nothing and lists what it would do.
3. An auto run upgrades packages and one image, catches a deliberately broken image, puts the old one back (L1) and ends `undone`.
4. A run cut off halfway freezes the server, and `upkeeper unfreeze` lifts it.
5. Uninstall leaves nothing behind but the override file.

You need: a Hetzner Cloud account, a GitHub account with a **public** GHCR package you can push to, and the control plane from the `m1-cloud` branch running somewhere the VM can reach over HTTPS.

## 0. Keys and builds (on your laptop)

This test uses a **development build** of the agent: it trusts the public TEST root key and accepts `UPKEEPER_DEV_MIN_RELEASE_AGE`, so a freshly pushed image doesn't have to wait 3 days. Never install a development build on a real server.

```sh
cd upkeeper-cli && git checkout m1
make build-dev keys                     # bin/upkeeper_dev_linux_amd64, bin/upkeeper-keys
bin/upkeeper-keys gen-online -id vmtest-1 -out online.key
bin/upkeeper-keys sign-cert -test-root -key-id vmtest-1 -pub <public key printed above> -days 7 > cert.json
```

Configure the control plane with the online key and its certificate:

- `JOB_SIGNING_KEY` = content of `online.key` (base64 seed)
- `JOB_KEY_ID` = `vmtest-1`
- `JOB_KEY_CERT` = content of `cert.json`

The control plane must send the certificate in `SignedJob.cert` with every job. Without it every job is refused with "isn't signed with a key this agent trusts".

## 1. The VM

1. Create a Hetzner **CX22**, **Ubuntu 24.04**, with your SSH key. Name it `upk-m1-test`.
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

**Expect** in the log: `Local policy: observe`, `Trusted root keys: TEST-ROOT-DO-NOT-USE`, a warning that this is a development build, and `report sent` lines.

**Check:**

- `upkeeper status`: mode observe, not frozen, the TEST root, "no job has arrived yet".
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
cat compose.override.upkeeper.yml   # only cache: image "redis:7.4.x@sha256:…"; no web entry
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
- `systemctl stop docker` during the dry run: the final check reports Docker isn't answering (dry runs don't freeze).

## 9. Uninstall

```sh
systemctl disable --now upkeeper
rm -rf /etc/systemd/system/upkeeper.service /etc/systemd/system/upkeeper.service.d /usr/local/bin/upkeeper
rm -rf /etc/upkeeper /var/lib/upkeeper /var/cache/upkeeper
systemctl daemon-reload
```

`/opt/demo/compose.override.upkeeper.yml` stays. Then delete the VM in the Hetzner console and remove the server in the dashboard.

## What to send back

- The run records of the dry run, the auto run and the cut-off run (screenshots or the JSON).
- `journalctl -u upkeeper --since today > upkeeper.log`.
- Anything in the wording that sounds wrong or alarming.
