# deploy/sol-ctl

Migration scripts + configs for running SolaraDocs on a sol-ctl-managed test box.

```
deploy/sol-ctl/
├── migrate.sh         # local: push binaries + source + deploy. Idempotent.
├── ctl.toml.example   # /etc/sol-ctl/ctl.toml template (router secret + targets_path)
├── prometheus.yml     # host-level Prometheus using sol-ctl's file_sd
└── README.md          # this file
```

## What `migrate.sh` does

Runs from a Mac. Targets `ec2-user@18.192.211.150` by default. Override with
`REMOTE_HOST=`, `SSH_KEY=`, `VPC_NAME=`.

1. Ships the locally-built `sol-control` / `solctl` / `sol-vpc` binaries from
   `~/Desktop/sol-ctl/target/release/` to `/usr/local/bin/` on the server,
   plus the systemd unit. Restarts `sol-control`.
2. Ensures `[router] targets_path = "/var/sol-ctl/targets.json"` exists in
   `/etc/sol-ctl/ctl.toml`. Restarts again if it changed.
3. Destroys + recreates the `soldocs` VPC. **Other VPCs on the box are left
   alone** — only `soldocs` is touched.
4. `rsync`'s the SolaraDocs source to `~/solaradocs/` on the server,
   `docker build`'s the image, tags it three ways (web/celery/beat) so the
   router can pick `web-*` deterministically.
5. Reads the `.env` from `~/Desktop/solaradocs/.env`, substitutes the
   docker-compose service name `redis:6379` with the mesh IP allocated to the
   redis container, and ships the result via `solctl addenv`.
6. `solctl assign` for redis (with a `--volume` for AOF persistence), then web,
   celery-worker, celery-beat — each with the right `--cmd`. Finally
   `solctl deploy soldocs`.

## What the test server needs *before* the first run

- `wardent` already installed and pointing at `127.0.0.1:9040` (the sol-control
  router port). Confirmed already done on the test box.
- `/etc/sol-ctl/ctl.toml` should have `[router] secret = "..."` matching what
  wardent sends as `X-Wardent-Secret`. See `ctl.toml.example`. The migration
  script adds `targets_path` if missing, but it will **not** set `secret` —
  do that manually once per host:

  ```bash
  sudo install -m 600 deploy/sol-ctl/ctl.toml.example /etc/sol-ctl/ctl.toml
  sudo vi /etc/sol-ctl/ctl.toml   # paste the real wardent shared secret
  sudo systemctl restart sol-control
  ```

- `~/Desktop/sol-ctl/target/release/` populated:

  ```bash
  cd ~/Desktop/sol-ctl
  cargo build --workspace --release
  ```

- `~/Desktop/solaradocs/.env` with all the secrets Django + Celery need
  (`DJANGO_SECRET_KEY`, `DB_MAIN`, `REDIS_URL`, `STRIPE_*`, `BREVO_API_KEY`,
  `R2_*`, `WARDENT_SECRET`, etc. — see top of `logic/settings.py`).
  The local `.env` stays put; the script doesn't mutate it.

## Run it

```bash
bash deploy/sol-ctl/migrate.sh
```

Re-running is safe — every step is idempotent. The VPC is recreated, the
image is rebuilt, the `.env` is regenerated, containers are re-assigned.

## Routing

Once `migrate.sh` finishes, requests should flow:

```
client → wardent (HTTPS) → 127.0.0.1:9040 (sol-control router)
       → finds the web container in vpc 'soldocs'
       → forwards to <mesh_ip>:8000
```

wardent must inject:

```
X-Wardent-Secret: <matches [router].secret in ctl.toml>
X-Sol-Environment: soldocs
```

## Prometheus

`sol-control` writes `/var/sol-ctl/targets.json` after every lifecycle event.
One entry per container, labeled with `vpc`, `container`, and `service`. To
hook up a host-level Prometheus:

```bash
sudo install -m 644 deploy/sol-ctl/prometheus.yml /etc/prometheus/prometheus.yml
# however your Prometheus install gets restarted
```

Then check `http://<host>:9090/targets` — all containers should show UP.

## Troubleshooting

```bash
# is sol-control alive?
ssh -i ~/Downloads/SOLARA.pem ec2-user@18.192.211.150 'sudo solctl ping'

# what's deployed?
ssh -i ~/Downloads/SOLARA.pem ec2-user@18.192.211.150 'sudo solctl list'

# logs
ssh -i ~/Downloads/SOLARA.pem ec2-user@18.192.211.150 'sudo journalctl -u sol-control -f'

# a specific container's logs (via solctl, in-mesh)
ssh -i ~/Downloads/SOLARA.pem ec2-user@18.192.211.150 'sudo solctl join soldocs'
# then inside the prompt: containers / logs <name> / leave

# current prometheus targets
ssh -i ~/Downloads/SOLARA.pem ec2-user@18.192.211.150 'sudo cat /var/sol-ctl/targets.json'
```
