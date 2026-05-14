#!/usr/bin/env bash
#
# Full sol-ctl deployment of SolaraDocs including observability stack.
# Runs from your Mac; SSHes into EC2 for every step.
#
#   bash migrate.sh
#   REMOTE_HOST=1.2.3.4 SSH_KEY=~/keys/foo.pem bash migrate.sh
#
# Idempotent: re-running tears the VPC down and rebuilds it cleanly.
#
# Container roster (15, deterministic IP allocation in a fresh VPC):
#   subnet 172.100.<OCTET>.0/24, first container = .2 and increments
#
#   1.  redis-soldocs-1                 .2   redis:7-alpine
#   2.  solaradocs-web-soldocs-1        .3   solaradocs-web:latest (gunicorn)
#   3.  solaradocs-web-soldocs-2        .4   solaradocs-web:latest (gunicorn, 2nd)
#   4.  solaradocs-celery-soldocs-1     .5   solaradocs-celery:latest (worker -E)
#   5.  solaradocs-beat-soldocs-1       .6   solaradocs-beat:latest   (beat)
#   6.  otel-collector-soldocs-1        .7   otel-collector:latest (retagged)
#   7.  tempo-soldocs-1                 .8   grafana/tempo:2.7.0
#   8.  prometheus-soldocs-1            .9   prom/prometheus:latest
#   9.  grafana-soldocs-1              .10   grafana/grafana:latest
#  10.  alertmanager-soldocs-1         .11   prom/alertmanager:v0.27.0
#  11.  node-exporter-soldocs-1        .12   prom/node-exporter:latest
#  12.  redis-exporter-soldocs-1       .13   redis-exporter:latest (retagged)
#  13.  loki-soldocs-1                 .14   grafana/loki:3.0.0
#  14.  promtail-soldocs-1             .15   grafana/promtail:3.0.0
#  15.  celery-exporter-soldocs-1      .16   danihodovic/celery-exporter:latest
#
# Phase 2 (Grafana access) — DECISION: Option B.
#   The sol-ctl router and wardent are *not* modified. Grafana is internal
#   tooling; routing it through the public proxy would require code changes,
#   a Grafana sub-path (GF_SERVER_ROOT_URL), and wardent.toml updates with
#   no real security benefit. Instead, reach Grafana via an SSH tunnel:
#     ssh -i $SSH_KEY -L 3000:<grafana-mesh-ip>:3000 ec2-user@$REMOTE_HOST
#   then open http://localhost:3000 in your browser. Mesh IPs are routable
#   from the EC2 host because the host is the bridge gateway.
#

set -euo pipefail

# -------- config --------------------------------------------------------------
REMOTE_USER="${REMOTE_USER:-ec2-user}"
REMOTE_HOST="${REMOTE_HOST:-18.192.211.150}"
SSH_KEY="${SSH_KEY:-$HOME/Downloads/SOLARA.pem}"
VPC_NAME="${VPC_NAME:-soldocs}"           # max 8 chars (sol-ctl constraint)

SOLCTL_DIR="${SOLCTL_DIR:-$HOME/Desktop/sol-ctl}"
SOLARADOCS_DIR="${SOLARADOCS_DIR:-$HOME/Desktop/solaradocs}"
LOCAL_ENV="${LOCAL_ENV:-$SOLARADOCS_DIR/.env}"
MON_DIR="$SOLARADOCS_DIR/deploy/monitoring"

REMOTE="$REMOTE_USER@$REMOTE_HOST"
SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30)

# Image tags (after retag step) and CMD overrides.
WEB_IMAGE="solaradocs-web:latest"
CELERY_IMAGE="solaradocs-celery:latest"
BEAT_IMAGE="solaradocs-beat:latest"
OTEL_IMAGE_SRC="otel/opentelemetry-collector-contrib:0.96.0"
OTEL_IMAGE="otel-collector:latest"
REDIS_EXPORTER_SRC="oliver006/redis_exporter:latest"
REDIS_EXPORTER_IMAGE="redis-exporter:latest"
CELERY_EXPORTER_IMAGE="danihodovic/celery-exporter:latest"

GUNICORN_CMD='gunicorn logic.wsgi:application --bind 0.0.0.0:8000 --workers 3 --access-logfile - --error-logfile -'
# `-E` makes the worker emit task-{sent,received,started,succeeded,failed}
# events on the broker — required for celery-exporter to see anything.
CELERY_WORKER_CMD='celery -A logic worker -l info -E'
CELERY_BEAT_CMD='celery -A logic beat -l info'
# sh -c so $REDIS_PASSWORD / $REDIS_IP-style expansion happens at container
# start, not pre-baked into state.toml.
REDIS_CMD='sh -c "redis-server --appendonly yes --requirepass $REDIS_PASSWORD"'

# -------- helpers -------------------------------------------------------------
log()  { printf '\n\033[1;36m[migrate]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\n\033[1;31m[migrate FAIL]\033[0m %s\n' "$*" >&2; exit 1; }
rsh()  { ssh "${SSH_OPTS[@]}" "$REMOTE" "$@"; }
rcp()  { scp "${SSH_OPTS[@]}" "$@"; }

# Substitute __KEY__ placeholders in a file and write the result to stdout.
# Usage: render <template> KEY=val KEY=val...
render() {
    local tmpl="$1"; shift
    local content; content=$(cat "$tmpl")
    local kv key val
    for kv in "$@"; do
        key="${kv%%=*}"
        val="${kv#*=}"
        # Use awk for safe substitution (no regex metachars in val to worry about).
        content=$(printf '%s' "$content" | awk -v k="$key" -v v="$val" '{gsub(k, v); print}')
    done
    printf '%s\n' "$content"
}

read_env_var() {
    grep -E "^${1}=" "$LOCAL_ENV" | head -1 | cut -d= -f2- | sed -E 's/^"//; s/"$//'
}

# Retry docker pull up to 3x — t2.small networking flakes occasionally.
docker_pull() {
    local img="$1" i
    for i in 1 2 3; do
        if rsh "sudo docker pull $img"; then return 0; fi
        warn "docker pull $img failed (attempt $i/3), retrying in 5s"
        sleep 5
    done
    die "docker pull $img failed 3 times"
}

# -------- preflight -----------------------------------------------------------
log "preflight"
[[ -r "$SSH_KEY" ]]                || die "ssh key not readable: $SSH_KEY"
[[ -r "$LOCAL_ENV" ]]              || die "no .env at $LOCAL_ENV"
[[ -d "$SOLCTL_DIR/src" ]]         || die "sol-ctl source not found at $SOLCTL_DIR"
[[ -f "$SOLCTL_DIR/Cargo.toml" ]]  || die "$SOLCTL_DIR/Cargo.toml missing — wrong SOLCTL_DIR?"
[[ -d "$MON_DIR" ]]                || die "monitoring config dir missing: $MON_DIR"
[[ -f "$MON_DIR/prometheus.yml.tmpl" ]] || die "prometheus.yml.tmpl missing"
[[ -f "$MON_DIR/grafana/dashboards/dashboard.json" ]] || die "dashboard.json missing"

rsh "true" || die "ssh to $REMOTE failed"
rsh "command -v cargo >/dev/null"  || die "remote ec2-user has no 'cargo' on PATH"
rsh "command -v docker >/dev/null" || die "remote has no 'docker' on PATH"

# Read secrets we need to substitute into configs / env-derived commands.
BREVO_API_KEY=$(read_env_var BREVO_API_KEY)
REDIS_PASSWORD=$(read_env_var REDIS_PASSWORD)
GRAFANA_USER=$(read_env_var GRAFANA_USER)
GRAFANA_PASSWORD=$(read_env_var GRAFANA_PASSWORD)
[[ -n "$BREVO_API_KEY" ]]    || warn ".env has no BREVO_API_KEY — alertmanager email will fail"
[[ -n "$REDIS_PASSWORD" ]]   || die  ".env has no REDIS_PASSWORD — redis would start without auth"
[[ -n "$GRAFANA_USER" ]]     || warn ".env has no GRAFANA_USER — Grafana will use admin/admin"
[[ -n "$GRAFANA_PASSWORD" ]] || warn ".env has no GRAFANA_PASSWORD — Grafana will use admin/admin"

# -------- 1. ship sol-ctl + install ------------------------------------------
log "rsync sol-ctl source to $REMOTE:~/sol-ctl/"
rsync -az --delete -e "ssh ${SSH_OPTS[*]}" \
    --exclude='target' --exclude='.git' --exclude='.idea' --exclude='.DS_Store' \
    "$SOLCTL_DIR/" "$REMOTE:sol-ctl/"

log "building sol-ctl on server (cold ~5min, warm ~30s)"
rsh "cd ~/sol-ctl && cargo build --workspace --release 2>&1 | tail -20"

log "installing fresh binaries + restarting sol-control"
rsh "sudo install -m 755 ~/sol-ctl/target/release/sol-control /usr/local/bin/sol-control \
  && sudo install -m 755 ~/sol-ctl/target/release/solctl       /usr/local/bin/solctl \
  && sudo install -m 755 ~/sol-ctl/target/release/sol-vpc      /usr/local/bin/sol-vpc \
  && sudo install -m 644 ~/sol-ctl/systemd/sol-control.service /etc/systemd/system/sol-control.service \
  && sudo systemctl daemon-reload \
  && sudo systemctl restart sol-control"

# -------- 2. ensure ctl.toml has router + targets_path -----------------------
# targets_path is the *source* path sol-ctl writes; we point it at the
# Prometheus volume so the file is visible inside the prometheus container at
# /etc/prometheus/targets.json without any extra mount.
log "writing /etc/sol-ctl/ctl.toml"
WARDENT_SECRET=$(read_env_var WARDENT_SECRET)
[[ -n "$WARDENT_SECRET" ]] || warn ".env has no WARDENT_SECRET — router will not validate"

rsh "sudo mkdir -p /etc/sol-ctl && sudo tee /etc/sol-ctl/ctl.toml >/dev/null <<EOF
[router]
secret = \"${WARDENT_SECRET}\"
port = 9040
upstream_port = 8000
targets_path = \"/var/sol-ctl/volumes/${VPC_NAME}/prometheus/config/targets.json\"
EOF
sudo systemctl restart sol-control"

log "waiting for sol-control to accept connections"
rsh 'for i in 1 2 3 4 5 6 7 8 9 10; do sudo solctl ping >/dev/null 2>&1 && exit 0; sleep 1; done; sudo solctl ping' \
    || die "sol-control not responding to ping"

# -------- 3. nuke everything and start fresh ----------------------------------
log "nuking all docker containers, images, volumes"
rsh "sudo docker rm -f \$(sudo docker ps -aq) 2>/dev/null || true"
rsh "sudo docker system prune -a -f 2>/dev/null || true"
rsh "sudo docker volume prune -f 2>/dev/null || true"

log "destroying sol-ctl VPC '$VPC_NAME' (other VPCs untouched)"
rsh "sudo solctl destroyvpc $VPC_NAME 2>/dev/null || true"
rsh "sudo docker network prune -f 2>/dev/null || true"

# Wait until the VPC is fully gone from state — destroyvpc returns when the
# request is acknowledged, but the worker process and netns teardown can
# linger and trip a subsequent createvpc.
log "waiting for VPC '$VPC_NAME' to disappear from solctl list"
for i in 1 2 3 4 5 6 7 8 9 10; do
    if ! rsh "sudo solctl list | awk '{print \$1}' | grep -qx $VPC_NAME"; then
        break
    fi
    sleep 1
    [[ $i -eq 10 ]] && die "VPC '$VPC_NAME' still present after destroyvpc"
done

log "wiping volume dirs"
rsh "sudo rm -rf /var/sol-ctl/volumes/$VPC_NAME"

log "creating vpc '$VPC_NAME'"
rsh "sudo solctl createvpc $VPC_NAME"

SUBNET=$(rsh "sudo solctl list | awk -v n=$VPC_NAME '\$1 == n {print \$2}'")
[[ -n "$SUBNET" ]] || die "couldn't read subnet for $VPC_NAME from 'solctl list'"
OCTET=$(echo "$SUBNET" | awk -F'[./]' '{print $3}')
[[ "$OCTET" =~ ^[0-9]+$ ]] || die "couldn't parse 3rd octet from subnet '$SUBNET'"

# Deterministic IP allocation: first assigned container gets .2, then .3, etc.
REDIS_IP="172.100.$OCTET.2"
WEB_IP="172.100.$OCTET.3"
WEB2_IP="172.100.$OCTET.4"
CELERY_IP="172.100.$OCTET.5"
BEAT_IP="172.100.$OCTET.6"
OTEL_IP="172.100.$OCTET.7"
TEMPO_IP="172.100.$OCTET.8"
PROMETHEUS_IP="172.100.$OCTET.9"
GRAFANA_IP="172.100.$OCTET.10"
ALERTMANAGER_IP="172.100.$OCTET.11"
NODE_EXPORTER_IP="172.100.$OCTET.12"
REDIS_EXPORTER_IP="172.100.$OCTET.13"
LOKI_IP="172.100.$OCTET.14"
PROMTAIL_IP="172.100.$OCTET.15"
CELERY_EXPORTER_IP="172.100.$OCTET.16"
log "subnet=$SUBNET → redis=$REDIS_IP web1=$WEB_IP web2=$WEB2_IP prom=$PROMETHEUS_IP graf=$GRAFANA_IP"

# -------- 4. sync solaradocs source + build the web image --------------------
log "rsync solaradocs source to $REMOTE:/home/$REMOTE_USER/solaradocs/"
rsync -az --delete -e "ssh ${SSH_OPTS[*]}" \
    --exclude='.git' --exclude='.venv' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='node_modules' --exclude='errors.log' --exclude='dump.rdb' \
    --exclude='deploy/sol-ctl/migrate.sh' --exclude='migrate.sh' \
    "$SOLARADOCS_DIR/" "$REMOTE:/home/$REMOTE_USER/solaradocs/"

# tracing.py hardcodes endpoint="http://otel-collector:4317". sol-ctl has no
# DNS, so rewrite the hostname to the mesh IP for the deployed copy only.
# Local source is untouched (docker-compose still resolves "otel-collector").
log "rewriting tracing.py OTel endpoint to mesh IP $OTEL_IP"
rsh "sed -i 's|http://otel-collector:4317|http://$OTEL_IP:4317|g' \
       /home/$REMOTE_USER/solaradocs/solaradocs/tracing.py"

log "building solaradocs-web image + tagging celery/beat"
rsh "cd /home/$REMOTE_USER/solaradocs && sudo docker build -t $WEB_IMAGE . \
  && sudo docker tag $WEB_IMAGE $CELERY_IMAGE \
  && sudo docker tag $WEB_IMAGE $BEAT_IMAGE"

# -------- 5. pull stock images + retag the underscored ones ------------------
log "pulling stock observability images (with retry on flaky network)"
docker_pull "redis:7-alpine"
docker_pull "$OTEL_IMAGE_SRC"
docker_pull "grafana/tempo:2.7.0"
docker_pull "prom/prometheus:latest"
docker_pull "grafana/grafana:latest"
docker_pull "prom/alertmanager:v0.27.0"
docker_pull "prom/node-exporter:latest"
docker_pull "$REDIS_EXPORTER_SRC"
docker_pull "grafana/loki:3.0.0"
docker_pull "grafana/promtail:3.0.0"
docker_pull "$CELERY_EXPORTER_IMAGE"

# Retag to hyphen-only image bases so container names are clean (no underscores).
rsh "sudo docker tag $OTEL_IMAGE_SRC $OTEL_IMAGE \
  && sudo docker tag $REDIS_EXPORTER_SRC $REDIS_EXPORTER_IMAGE \
  && sudo docker tag $CELERY_EXPORTER_IMAGE celery-exporter:latest"

# -------- 6. generate the deployed .env + ship via solctl addenv -------------
log "generating deployed .env (REDIS pointed at $REDIS_IP)"
TMP_ENV=$(mktemp)
trap 'rm -f "$TMP_ENV"' EXIT

# Substitute docker-compose service names with mesh IPs in the env file.
sed -E \
    -e "s|@redis:6379|@$REDIS_IP:6379|g" \
    -e "s|//redis:6379|//$REDIS_IP:6379|g" \
    -e "s|=redis://redis:|=redis://$REDIS_IP:|g" \
    -e "s|^REDIS_HOST=.*|REDIS_HOST=$REDIS_IP|g" \
    "$LOCAL_ENV" > "$TMP_ENV"

# Append vars the deployed containers need that may not be in the local .env.
# These are idempotent: addenv overwrites the previous env file on each run.
{
    grep -q '^OTEL_EXPORTER_OTLP_ENDPOINT=' "$TMP_ENV" || echo "OTEL_EXPORTER_OTLP_ENDPOINT=http://$OTEL_IP:4317"
    grep -q '^PROMETHEUS_MULTIPROC_DIR=' "$TMP_ENV" || echo "PROMETHEUS_MULTIPROC_DIR=/tmp/prometheus_multiproc"
    # Grafana env vars (image expects GF_*, .env uses GRAFANA_*).
    echo "GF_SECURITY_ADMIN_USER=${GRAFANA_USER:-admin}"
    echo "GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}"
    # Redis exporter reads REDIS_ADDR (not REDIS_URL)
    echo "REDIS_ADDR=redis://:${REDIS_PASSWORD}@${REDIS_IP}:6379"
    # Celery exporter reads CE_BROKER_URL
    echo "CE_BROKER_URL=redis://:${REDIS_PASSWORD}@${REDIS_IP}:6379/0"
} >> "$TMP_ENV"

rcp "$TMP_ENV" "$REMOTE:/tmp/soldocs.env"
rsh "sudo solctl addenv $VPC_NAME /tmp/soldocs.env && rm -f /tmp/soldocs.env"

# -------- 7. render monitoring configs locally + ship to volume dirs ---------
log "rendering monitoring configs with mesh IPs and uploading to volume dirs"
STAGE=$(mktemp -d)
trap 'rm -f "$TMP_ENV"; rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE"/{prometheus,alertmanager,otel-collector,tempo,loki,promtail,grafana/provisioning/datasources,grafana/provisioning/dashboards,grafana/dashboards}

render "$MON_DIR/prometheus.yml.tmpl" \
    "__WEB_IP__=$WEB_IP" \
    "__REDIS_EXPORTER_IP__=$REDIS_EXPORTER_IP" \
    "__NODE_EXPORTER_IP__=$NODE_EXPORTER_IP" \
    "__ALERTMANAGER_IP__=$ALERTMANAGER_IP" \
    "__TEMPO_IP__=$TEMPO_IP" \
    "__LOKI_IP__=$LOKI_IP" \
    "__CELERY_EXPORTER_IP__=$CELERY_EXPORTER_IP" \
    > "$STAGE/prometheus/prometheus.yml"
# alert-rules.yml: new hardened file in deploy/monitoring/ supersedes the
# root copy. Root file kept for docker-compose use; not referenced here.
cp "$MON_DIR/alert-rules.yml" "$STAGE/prometheus/alert-rules.yml"

render "$MON_DIR/alertmanager.yml.tmpl" \
    "__BREVO_API_KEY__=$BREVO_API_KEY" \
    > "$STAGE/alertmanager/alertmanager.yml"

render "$MON_DIR/otel-collector-config.yaml.tmpl" \
    "__TEMPO_IP__=$TEMPO_IP" \
    > "$STAGE/otel-collector/otel-collector-config.yaml"

render "$MON_DIR/tempo.yaml.tmpl" \
    "__PROMETHEUS_IP__=$PROMETHEUS_IP" \
    > "$STAGE/tempo/tempo.yaml"

cp "$MON_DIR/loki-config.yaml" "$STAGE/loki/loki-config.yaml"

render "$MON_DIR/promtail-config.yaml.tmpl" \
    "__LOKI_IP__=$LOKI_IP" \
    > "$STAGE/promtail/promtail-config.yaml"

render "$MON_DIR/grafana/provisioning/datasources/datasource.yml.tmpl" \
    "__PROMETHEUS_IP__=$PROMETHEUS_IP" \
    "__TEMPO_IP__=$TEMPO_IP" \
    "__LOKI_IP__=$LOKI_IP" \
    "__ALERTMANAGER_IP__=$ALERTMANAGER_IP" \
    > "$STAGE/grafana/provisioning/datasources/datasource.yml"
cp "$MON_DIR/grafana/provisioning/dashboards/dashboard.yml" \
   "$STAGE/grafana/provisioning/dashboards/dashboard.yml"
cp "$MON_DIR/grafana/dashboards/dashboard.json" \
   "$STAGE/grafana/dashboards/dashboard.json"

# Create the volume tree on the box (sol-ctl will also mkdir at assign, but
# we need the dirs before we can scp the config files in).
log "pre-creating volume tree under /var/sol-ctl/volumes/$VPC_NAME/"
rsh "sudo mkdir -p \
        /var/sol-ctl/volumes/$VPC_NAME/redis/data \
        /var/sol-ctl/volumes/$VPC_NAME/prometheus/data \
        /var/sol-ctl/volumes/$VPC_NAME/prometheus/config \
        /var/sol-ctl/volumes/$VPC_NAME/alertmanager/data \
        /var/sol-ctl/volumes/$VPC_NAME/alertmanager/config \
        /var/sol-ctl/volumes/$VPC_NAME/otel-collector/config \
        /var/sol-ctl/volumes/$VPC_NAME/tempo/data \
        /var/sol-ctl/volumes/$VPC_NAME/tempo/config \
        /var/sol-ctl/volumes/$VPC_NAME/loki/data \
        /var/sol-ctl/volumes/$VPC_NAME/loki/config \
        /var/sol-ctl/volumes/$VPC_NAME/promtail/config \
        /var/sol-ctl/volumes/$VPC_NAME/grafana/data/dashboards \
        /var/sol-ctl/volumes/$VPC_NAME/grafana/provisioning/datasources \
        /var/sol-ctl/volumes/$VPC_NAME/grafana/provisioning/dashboards \
   && sudo chmod -R 777 /var/sol-ctl/volumes/$VPC_NAME/"

# Ship staged configs over with rsync (single SSH connection).
log "uploading rendered configs to /tmp/soldocs-cfg/ then moving into place"
rsync -az -e "ssh ${SSH_OPTS[*]}" "$STAGE/" "$REMOTE:/tmp/soldocs-cfg/"
rsh "sudo cp /tmp/soldocs-cfg/prometheus/prometheus.yml          /var/sol-ctl/volumes/$VPC_NAME/prometheus/config/ \
  && sudo cp /tmp/soldocs-cfg/prometheus/alert-rules.yml         /var/sol-ctl/volumes/$VPC_NAME/prometheus/config/ \
  && sudo cp /tmp/soldocs-cfg/alertmanager/alertmanager.yml       /var/sol-ctl/volumes/$VPC_NAME/alertmanager/config/ \
  && sudo cp /tmp/soldocs-cfg/otel-collector/otel-collector-config.yaml /var/sol-ctl/volumes/$VPC_NAME/otel-collector/config/config.yaml \
  && sudo cp /tmp/soldocs-cfg/tempo/tempo.yaml                    /var/sol-ctl/volumes/$VPC_NAME/tempo/config/ \
  && sudo cp /tmp/soldocs-cfg/loki/loki-config.yaml               /var/sol-ctl/volumes/$VPC_NAME/loki/config/local-config.yaml \
  && sudo cp /tmp/soldocs-cfg/promtail/promtail-config.yaml       /var/sol-ctl/volumes/$VPC_NAME/promtail/config/config.yml \
  && sudo cp /tmp/soldocs-cfg/grafana/dashboards/dashboard.json   /var/sol-ctl/volumes/$VPC_NAME/grafana/data/dashboards/ \
  && sudo cp /tmp/soldocs-cfg/grafana/provisioning/datasources/datasource.yml /var/sol-ctl/volumes/$VPC_NAME/grafana/provisioning/datasources/ \
  && sudo cp /tmp/soldocs-cfg/grafana/provisioning/dashboards/dashboard.yml   /var/sol-ctl/volumes/$VPC_NAME/grafana/provisioning/dashboards/ \
  && sudo rm -rf /tmp/soldocs-cfg/"

# -------- 8. assign all 15 containers (deterministic IP order) --------------
log "assigning redis ($REDIS_IP)"
rsh "sudo solctl assign redis:7-alpine $VPC_NAME \
        --volume /var/sol-ctl/volumes/$VPC_NAME/redis/data:/data \
        --cmd $(printf %q "$REDIS_CMD")"

log "assigning solaradocs-web-soldocs-1 ($WEB_IP, gunicorn)"
rsh "sudo solctl assign $WEB_IMAGE $VPC_NAME --cmd $(printf %q "$GUNICORN_CMD")"

log "assigning solaradocs-web-soldocs-2 ($WEB2_IP, gunicorn, 2nd instance)"
# Same image as -1 ⇒ sol-ctl auto-increments idx, container becomes
# solaradocs-web-soldocs-2 with mesh IP .4. Both surface in file_sd with
# service=solaradocs-web — Grafana's $container var distinguishes them.
rsh "sudo solctl assign $WEB_IMAGE $VPC_NAME --cmd $(printf %q "$GUNICORN_CMD")"

log "assigning solaradocs-celery ($CELERY_IP, worker with -E)"
rsh "sudo solctl assign $CELERY_IMAGE $VPC_NAME --cmd $(printf %q "$CELERY_WORKER_CMD")"

log "assigning solaradocs-beat ($BEAT_IP, celery beat)"
rsh "sudo solctl assign $BEAT_IMAGE $VPC_NAME --cmd $(printf %q "$CELERY_BEAT_CMD")"

log "assigning otel-collector ($OTEL_IP)"
rsh "sudo solctl assign \
        --volume /var/sol-ctl/volumes/$VPC_NAME/otel-collector/config:/etc/otel \
        $OTEL_IMAGE $VPC_NAME"

log "assigning tempo ($TEMPO_IP)"
rsh "sudo solctl assign \
        --volume /var/sol-ctl/volumes/$VPC_NAME/tempo/config:/etc/tempo \
        --volume /var/sol-ctl/volumes/$VPC_NAME/tempo/data:/var/tempo \
        grafana/tempo:2.7.0 $VPC_NAME"

log "assigning prometheus ($PROMETHEUS_IP)"
rsh "sudo solctl assign \
        --volume /var/sol-ctl/volumes/$VPC_NAME/prometheus/config:/etc/prometheus \
        --volume /var/sol-ctl/volumes/$VPC_NAME/prometheus/data:/prometheus \
        prom/prometheus:latest $VPC_NAME"

log "assigning grafana ($GRAFANA_IP)"
rsh "sudo solctl assign grafana/grafana:latest $VPC_NAME \
        --volume /var/sol-ctl/volumes/$VPC_NAME/grafana/data:/var/lib/grafana \
        --volume /var/sol-ctl/volumes/$VPC_NAME/grafana/provisioning:/etc/grafana/provisioning"

log "assigning alertmanager ($ALERTMANAGER_IP)"
# Default CMD: --config.file=/etc/alertmanager/alertmanager.yml
# Gossip cluster should find mesh IP as private address.
rsh "sudo solctl assign \
        --volume /var/sol-ctl/volumes/$VPC_NAME/alertmanager/config:/etc/alertmanager \
        --volume /var/sol-ctl/volumes/$VPC_NAME/alertmanager/data:/alertmanager \
        prom/alertmanager:v0.27.0 $VPC_NAME"

log "assigning node-exporter ($NODE_EXPORTER_IP)"
# NOTE: node-exporter runs inside the netns rather than with pid:host. It will
# report the container view (its own /proc, /sys) — not the host's. Real
# host-level metrics need a separate systemd unit; that's out of scope here.
rsh "sudo solctl assign prom/node-exporter:latest $VPC_NAME"

log "assigning redis-exporter ($REDIS_EXPORTER_IP)"
# Reads REDIS_ADDR from the VPC .env — no --cmd needed.
rsh "sudo solctl assign $REDIS_EXPORTER_IMAGE $VPC_NAME"

log "assigning loki ($LOKI_IP)"
rsh "sudo solctl assign \
        --volume /var/sol-ctl/volumes/$VPC_NAME/loki/config:/etc/loki \
        --volume /var/sol-ctl/volumes/$VPC_NAME/loki/data:/loki \
        grafana/loki:3.0.0 $VPC_NAME"

log "assigning promtail ($PROMTAIL_IP)"
rsh "sudo solctl assign \
        --volume /var/sol-ctl/volumes/$VPC_NAME/promtail/config:/etc/promtail \
        grafana/promtail:3.0.0 $VPC_NAME"

log "assigning celery-exporter ($CELERY_EXPORTER_IP)"
# Reads CE_BROKER_URL from the VPC .env — no --cmd needed.
# Volume mount ensures /tmp/prometheus_multiproc exists at container start —
# the shared .env leaks PROMETHEUS_MULTIPROC_DIR and prometheus_client flips
# to mmap mode, crashing if the dir is missing.
rsh "sudo solctl assign \
        --volume /var/sol-ctl/volumes/$VPC_NAME/celery-exporter/multiproc:/tmp/prometheus_multiproc \
        celery-exporter:latest $VPC_NAME"

# -------- 9. deploy ----------------------------------------------------------
log "deploying all containers"
rsh "sudo solctl deploy $VPC_NAME"

# Give services a moment to come up before validation curls.
sleep 8



# -------- 10. validate -------------------------------------------------------
log "validation"
echo "--- solctl list ---"
rsh "sudo solctl list" || true
echo

check() {
    local name="$1" url="$2" expect="$3"
    local out
    out=$(rsh "curl -s -m 10 -o /dev/null -w '%{http_code}' $url" 2>/dev/null || echo "ERR")
    if [[ "$out" == "$expect" ]]; then
        printf '  \033[1;32mOK\033[0m   %-20s %s\n' "$name" "$url"
    else
        printf '  \033[1;33mWARN\033[0m %-20s %s (got %s, want %s)\n' "$name" "$url" "$out" "$expect"
    fi
}

check "django-1"      "http://$WEB_IP:8000/"                          "200"
check "django-2"      "http://$WEB2_IP:8000/"                         "200"
check "django-metrics" "http://$WEB_IP:8000/metrics"                  "200"
check "prometheus"    "http://$PROMETHEUS_IP:9090/-/healthy"          "200"
check "grafana"       "http://$GRAFANA_IP:3000/api/health"            "200"
check "alertmanager"  "http://$ALERTMANAGER_IP:9093/-/healthy"        "200"
check "redis-export"  "http://$REDIS_EXPORTER_IP:9121/metrics"        "200"
check "node-export"   "http://$NODE_EXPORTER_IP:9100/metrics"         "200"
check "celery-export" "http://$CELERY_EXPORTER_IP:9808/metrics"       "200"
check "tempo"         "http://$TEMPO_IP:3200/ready"                   "200"
check "loki"          "http://$LOKI_IP:3100/ready"                    "200"

# Verify redis-exporter is actually reading Redis (not just up).
echo
echo "--- redis-exporter sanity (redis_up should be 1) ---"
rsh "curl -s -m 10 http://$REDIS_EXPORTER_IP:9121/metrics | grep '^redis_up '" || true

# Verify celery-exporter sees the worker.
echo
echo "--- celery-exporter sanity (celery_worker_up should be 1) ---"
rsh "curl -s -m 10 http://$CELERY_EXPORTER_IP:9808/metrics | grep '^celery_worker_up'" || true

echo
echo "--- targets.json ---"
rsh "sudo test -f /var/sol-ctl/volumes/$VPC_NAME/prometheus/config/targets.json \
        && sudo head -c 600 /var/sol-ctl/volumes/$VPC_NAME/prometheus/config/targets.json; echo" || \
    warn "targets.json not yet present"

echo
echo "--- prometheus targets (count UP) ---"
UP_COUNT=$(rsh "curl -s -m 10 http://$PROMETHEUS_IP:9090/api/v1/targets" 2>/dev/null \
    | grep -c '\"health\":\"up\"' || true)
echo "  $UP_COUNT scrape targets reporting UP"

echo
echo "--- grafana dashboard provisioned? ---"
rsh "curl -s -m 10 -u \"${GRAFANA_USER:-admin}:${GRAFANA_PASSWORD:-admin}\" http://$GRAFANA_IP:3000/api/search?query=SolaraDocs" 2>/dev/null \
    | head -c 400; echo

# -------- 11. summary --------------------------------------------------------
cat <<EOF

\033[1;32m[migrate] done.\033[0m
  VPC:        $VPC_NAME (subnet $SUBNET)
  Web:        http://$WEB_IP:8000        (django+gunicorn)
  Prometheus: http://$PROMETHEUS_IP:9090
  Grafana:    http://$GRAFANA_IP:3000    (login: ${GRAFANA_USER:-admin} / ${GRAFANA_PASSWORD:-admin})
  Alertmgr:   http://$ALERTMANAGER_IP:9093

Reach Grafana from your Mac (Phase 2 = Option B, no proxy changes):
  ssh -i $SSH_KEY -L 3000:$GRAFANA_IP:3000 $REMOTE
  → http://localhost:3000

Live logs:           ssh -i $SSH_KEY $REMOTE 'sudo journalctl -u sol-control -f'
Per-container list:  ssh -i $SSH_KEY $REMOTE 'sudo solctl list'
sol-ctl targets:     ssh -i $SSH_KEY $REMOTE 'sudo cat /var/sol-ctl/volumes/$VPC_NAME/prometheus/config/targets.json'

Reminder: wardent.toml on $REMOTE_HOST must set X-Sol-Environment = "$VPC_NAME"
and X-Wardent-Secret = WARDENT_SECRET from .env (currently configured) for
prod routing to work end-to-end.
EOF