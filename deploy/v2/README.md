# solaradocs deploy (sol-ctl v2)

Two scripts, two roles:

| Script | When | What it does |
|---|---|---|
| `deploy.sh` | Normal deploys | No-downtime blue/green flip: build → apply to standby → wait Healthy → promote |
| `stabilize.sh` | Emergency hotfix | Nuke both VPCs + wipe etcd + rebuild + deploy to ONE VPC. Downtime expected |

Both run manually over SSH after `git pull` on the server. No CI. No auto-deploy on push.

## Normal deploy (deploy.sh)

Automatic on push to master via `.github/workflows/deploy.yml` — validates
manifests, SSHes to the server, git-pulls, runs `deploy.sh`, then smokes
the new active VPC via the router. Also triggerable manually from the
Actions tab (workflow_dispatch).

Manual fallback (when CI is down or you want to deploy without pushing):
```bash
ssh -i ~/Downloads/SOLARA.pem ubuntu@52.58.203.176
cd /home/ubuntu && git pull
sudo bash /home/ubuntu/deploy/v2/deploy.sh
```

Behavior:
- Reads `/solctl/deploy/active` from etcd → picks the VPC currently at `0` as the standby target.
- Builds `localhost:5000/solaradocs:<GIT_SHA>` on the server, pushes to the local registry.
- `solctl-v2 apply` for `vpc.yaml` + `blue-green.yaml` + `services-<standby>.yaml`.
- Waits (max 10 min) for every health-checked service in standby to report `healthy` in etcd.
- `solctl-v2 promote <standby>` — atomic flip: docker start standby → sed wardent.toml → restart wardent → docker stop old active → CAS active map.
- Post-flip smoke: curl `:9040/metrics` with `WARDENT_SECRET` + new `X-Sol-Environment`.

If **any** step fails, the old active keeps serving. Half-down is safer than half-up. Rollback: `sudo solctl-v2 rollback`.

Optional env:
- `GIT_SHA` — image tag (default: `git rev-parse --short HEAD` in `SOLARADOCS_DIR`)
- `SOLARADOCS_DIR` — default `/home/ubuntu`
- `HEALTHY_TIMEOUT` — default `600` (10 min)

## Emergency hotfix (stabilize.sh)

Use when the mesh is stuck and blue/green can't recover:
- IP counters exhausted (loki restart storms)
- half-alive containers that `solctl-v2 apply` can't reconcile
- corrupted etcd state
- both VPCs unhealthy at once

```bash
sudo bash /home/ubuntu/deploy/v2/stabilize.sh                # → sd-blue
sudo TARGET_VPC=sd-green bash /home/ubuntu/deploy/v2/stabilize.sh
```

Nukes every soldocs container on both VPCs, wipes `/solctl/services/*`, `/solctl/state/services/*`, `/solctl/bluegreen/*`, `/solctl/deploy/*`, `/solctl/internal/vpcs/*`, then reseeds `deploy/active` with the target at 1 and other at 0 and applies fresh. Blue/green routing is OFF after — you need to run a normal `deploy.sh` afterward to hydrate the standby.

Optional env: `TARGET_VPC` (default `sd-blue`), `SOLARADOCS_DIR` (default `/home/ubuntu`), `WAIT_SEC` (default 180).

## One-time server prerequisites

- `etcd-server` installed + `sudo systemctl enable --now etcd`
- `solctl-v2` + `sol-control-v2` binaries in `/usr/local/bin/` (from the sol-ctl repo)
- `/etc/sol-ctl-v2/ctl.toml` with `[router] secret` matching wardent's
- `/var/sol-ctl/{sd-blue,sd-green}/.env` files present (`BREVO_API_KEY`, `WARDENT_SECRET`, etc.)
- Bootstrap once so `deploy.sh` has something to read:
  ```bash
  etcdctl put /solctl/deploy/active '{"sd-blue":0,"sd-green":0}'
  ```
  On the very first deploy, both zeros → deploy.sh picks sd-blue.

## Rollback

```bash
sudo solctl-v2 rollback           # flip active back to the previous VPC
sudo journalctl -u sol-control-v2 -f
```

If rollback itself is broken → `stabilize.sh` is the escape hatch.
