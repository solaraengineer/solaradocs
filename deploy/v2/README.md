# solaradocs v2 deploy (sol-ctl v2)

Parallel to the existing v1 deploy in `.github/workflows/deploy.yml`. v1 is
left untouched; v2 ships as a separate, manually-triggered workflow so you
can test v2 without disturbing prod.

```
.github/workflows/deploy.yml       ← v1 (current prod, push-to-master)
.github/workflows/deploy-v2.yml    ← v2 (manual workflow_dispatch)
manifests/{vpc,services}.yaml      ← v2 declarative spec
deploy/v2/deploy.sh                ← server-side runner invoked by deploy-v2.yml
```

## One-time prerequisites on the EC2 (before the first v2 deploy)

These match `sol-ctl/CUTOVER.md` §1 — pre-cutover, no v1 disruption.

1. **etcd installed + running**
   ```bash
   sudo apt install -y etcd-server protobuf-compiler
   sudo systemctl enable --now etcd
   etcdctl endpoint health  # expect: "...is healthy"
   ```

2. **sol-ctl v2 binaries + systemd unit installed** (from the sol-ctl repo,
   not this one):
   ```bash
   # On dev machine: build + scp
   cd ~/Desktop/sol-ctl
   cargo build --release --bin solctl-v2 --bin sol-control-v2
   scp target/release/{solctl-v2,sol-control-v2} ubuntu@<server>:/tmp/
   scp systemd/sol-control-v2.service ubuntu@<server>:/tmp/

   # On server
   sudo install -m 755 /tmp/solctl-v2 /usr/local/bin/
   sudo install -m 755 /tmp/sol-control-v2 /usr/local/bin/
   sudo install -m 644 /tmp/sol-control-v2.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

3. **`/etc/sol-ctl-v2/ctl.toml`** — copy from `sol-ctl/examples/ctl-v2.toml`
   and fill in the `[router] secret` (must match wardent's secret) and
   `[targets] path` if you want Prom file_sd:
   ```bash
   sudo mkdir -p /etc/sol-ctl-v2
   sudo nano /etc/sol-ctl-v2/ctl.toml
   sudo chmod 600 /etc/sol-ctl-v2/ctl.toml
   ```

4. **Prod env file updated for v2 service-name DNS.** v1 had bridge IPs
   hardcoded in the env file; v2 uses service-name resolution via
   `/etc/hosts` bind mounts. Open `/var/sol-ctl/soldocs/.env` and change:
   ```
   REDIS_HOST=redis             # was 172.100.0.2
   REDIS_URL=redis://:Mucia850@@redis:6379
   REDIS_ADDR=redis://:Mucia850@@redis:6379
   CE_BROKER_URL=redis://:Mucia850@@redis:6379/0
   ```
   Everything else in the env file stays the same.

5. **GitHub Actions secrets** — `deploy-v2.yml` reuses the existing
   secrets from `deploy.yml`:
   - `SOLARA_BASE64` — base64-encoded SSH private key
   - `SERVER_IP_1` — primary server IP

## To deploy v2 (testing alongside v1)

GitHub Actions → Actions tab → "Deploy (v2 sol-ctl)" → "Run workflow"
→ pick branch (usually master) → Run.

The workflow:
1. Validates manifests parse as YAML
2. Rsyncs source to the EC2 (same exclusions as v1 deploy.yml, plus
   keeps `manifests/` and `deploy/v2/` which v1 ignored)
3. SSHes in and runs `sudo bash /home/ubuntu/solaradocs/deploy/v2/deploy.sh`
   - Starts sol-control-v2 if inactive
   - Spins up a local `registry:2` container (if not already there)
   - Builds the solaradocs image from `/home/ubuntu/solaradocs/` and
     pushes to `localhost:5000/solaradocs:<short-sha>`
   - Stages configs (prometheus.yml etc.) under
     `/var/sol-ctl/volumes/soldocs/configs/`. Substitutes
     `{BREVO_API_KEY}` into alertmanager.yml.
   - sed-substitutes `__IMAGE_TAG__` in services.yaml → the short SHA
   - Runs `solctl-v2 validate -f` then `apply -f`
   - Polls until all 11 health-checked services are Healthy (max 10 min)
   - Runs `manage.py migrate --noinput` against the web container
   - Smokes the router (curl :9040 with WARDENT_SECRET + soldocs env)
4. CI runs an external smoke afterward to double-check the router

If anything's wrong, the script exits with FAIL and dumps the daemon
log + `solctl-v2 status` snapshot so you can diagnose without SSHing in.

## Rollback to v1 (during the dual-deploy testing period)

v1's `sol-control` is **still installed and enabled**. v2 doesn't touch
v1's `/etc/sol-ctl/` or `/var/sol-ctl/<vpc>/.env`. To roll back:

```bash
# On the server
sudo systemctl stop sol-control-v2
sudo docker ps -a --format '{{.Names}}' | grep -E '\-soldocs-[0-9]+(-g[0-9]+)?$' \
  | xargs -r sudo docker rm -f
sudo ip link del sol-br-soldocs 2>/dev/null || true
etcdctl del --prefix /solctl/      # wipe v2 state
sudo systemctl start sol-control   # v1 takes over
# Re-deploy v1 via GitHub Actions → "Deploy" workflow
```

~90s to be back on v1.

## Cutting over for real (v1 → v2 as the default)

Once you've run `deploy-v2.yml` a few times and it's stable, two options:

**Option A: keep both workflows, just stop running v1.** Don't push to
master without first running deploy-v2.yml; push-to-master would re-deploy
v1 and stomp on v2. Fragile but reversible.

**Option B: replace.** Delete `.github/workflows/deploy.yml`, change
`deploy-v2.yml` to also fire on push to master:
```yaml
on:
  push:
    branches: [master]
  workflow_dispatch:
    inputs: { target: { ... } }
```
Then push a commit. v2 becomes the only deploy path.

After 1 week of stable v2 in prod, do `sol-ctl/CUTOVER.md` §5 to
delete v1 modules + uninstall v1 binaries from the server.
