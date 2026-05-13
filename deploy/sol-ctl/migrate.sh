#!/usr/bin/env bash
# Push a SolaraDocs build to a sol-ctl-managed test box.
#
# Pre-conditions:
#   - You can ssh to $REMOTE_HOST with $SSH_KEY.
#   - sol-control + wardent are already installed on the host. We push
#     fresh source and rebuild on the box (the binary architecture has to
#     match the box, not your dev Mac).
#   - The remote already has `cargo` on PATH for ec2-user.
#   - `~/Desktop/sol-ctl/` exists locally — we rsync source from here.
#   - `~/Desktop/solaradocs/.env` exists and has all the secrets Django needs.
#
# What it does (idempotent — safe to re-run):
#   1. ssh in, ship new sol-control/solctl/sol-vpc, restart the daemon.
#   2. Make sure `[router] targets_path` is set in /etc/sol-ctl/ctl.toml.
#   3. (Re-)create the `soldocs` VPC. Other VPCs on the box are untouched.
#   4. Sync solaradocs source, `docker build`, tag three ways.
#   5. Generate a .env with the mesh redis IP and ship it via `solctl addenv`.
#   6. Assign redis + web + celery-worker + celery-beat. Deploy.
#
# Run from a Mac:
#   bash deploy/sol-ctl/migrate.sh
#
# Override anything via env:
#   SSH_KEY=/some/key.pem REMOTE_HOST=1.2.3.4 bash deploy/sol-ctl/migrate.sh
#

set -euo pipefail

# -------- config --------
REMOTE_USER="${REMOTE_USER:-ec2-user}"
REMOTE_HOST="${REMOTE_HOST:-18.192.211.150}"
SSH_KEY="${SSH_KEY:-$HOME/Downloads/SOLARA.pem}"
VPC_NAME="${VPC_NAME:-soldocs}"        # max 8 chars (sol-ctl constraint)

SOLCTL_DIR="${SOLCTL_DIR:-$HOME/Desktop/sol-ctl}"
SOLARADOCS_DIR="${SOLARADOCS_DIR:-$HOME/Desktop/solaradocs}"
LOCAL_ENV="${LOCAL_ENV:-$SOLARADOCS_DIR/.env}"

REMOTE="$REMOTE_USER@$REMOTE_HOST"
SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30)

GUNICORN_CMD='gunicorn logic.wsgi:application --bind 0.0.0.0:8000 --workers 3 --access-logfile - --error-logfile -'
CELERY_WORKER_CMD='celery -A logic worker -l info'
CELERY_BEAT_CMD='celery -A logic beat -l info'

# -------- helpers --------
log() { printf '\n\033[1;36m[migrate]\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31m[migrate FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

rsh()  { ssh "${SSH_OPTS[@]}" "$REMOTE" "$@"; }
rcp()  { scp "${SSH_OPTS[@]}" "$@"; }

# -------- preflight --------
log "preflight"
[[ -r "$SSH_KEY" ]]            || die "ssh key not readable: $SSH_KEY"
[[ -r "$LOCAL_ENV" ]]          || die "no .env at $LOCAL_ENV"
[[ -d "$SOLCTL_DIR/src" ]]     || die "sol-ctl source not found at $SOLCTL_DIR (override with SOLCTL_DIR=...)"
[[ -f "$SOLCTL_DIR/Cargo.toml" ]] || die "$SOLCTL_DIR/Cargo.toml missing — wrong SOLCTL_DIR?"

# Quick connectivity check before doing anything destructive.
rsh "true" || die "ssh to $REMOTE failed"
rsh "command -v cargo >/dev/null" || die "remote ec2-user has no 'cargo' on PATH — install rust on the box first"

# -------- 1. sync source + build on the server --------
# We rebuild on the box every run. cargo's incremental cache makes the
# second-and-onwards build fast (~30s typical). Fresh builds are ~5min.
log "rsync sol-ctl source to $REMOTE:~/sol-ctl/"
rsync -az --delete -e "ssh ${SSH_OPTS[*]}" \
    --exclude='target' \
    --exclude='.git' \
    --exclude='.idea' \
    --exclude='.DS_Store' \
    "$SOLCTL_DIR/" "$REMOTE:sol-ctl/"

log "building sol-ctl on server (this is slow on a cold cache)"
rsh "cd ~/sol-ctl && cargo build --workspace --release 2>&1 | tail -20"

log "installing fresh binaries + restarting sol-control"
rsh "sudo install -m 755 ~/sol-ctl/target/release/sol-control /usr/local/bin/sol-control \
  && sudo install -m 755 ~/sol-ctl/target/release/solctl       /usr/local/bin/solctl \
  && sudo install -m 755 ~/sol-ctl/target/release/sol-vpc      /usr/local/bin/sol-vpc \
  && sudo install -m 644 ~/sol-ctl/systemd/sol-control.service /etc/systemd/system/sol-control.service \
  && sudo systemctl daemon-reload \
  && sudo systemctl restart sol-control"

# -------- 2. ensure targets_path is set in ctl.toml --------
log "ensuring [router] targets_path is set in /etc/sol-ctl/ctl.toml"
rsh "sudo mkdir -p /etc/sol-ctl && sudo touch /etc/sol-ctl/ctl.toml \
  && (sudo grep -q '^\[router\]' /etc/sol-ctl/ctl.toml || echo '[router]' | sudo tee -a /etc/sol-ctl/ctl.toml >/dev/null) \
  && (sudo grep -q '^targets_path' /etc/sol-ctl/ctl.toml || echo 'targets_path = \"/var/sol-ctl/targets.json\"' | sudo tee -a /etc/sol-ctl/ctl.toml >/dev/null) \
  && sudo systemctl restart sol-control"

# wait for the socket to come back
log "waiting for sol-control to accept connections"
rsh 'for i in 1 2 3 4 5 6 7 8 9 10; do sudo solctl ping >/dev/null 2>&1 && exit 0; sleep 1; done; sudo solctl ping' \
    || die "sol-control not responding to ping"

# -------- 3. (re-)create the VPC --------
log "(re-)creating vpc '$VPC_NAME' (other vpcs left alone)"
rsh "sudo solctl destroyvpc $VPC_NAME 2>/dev/null || true"
rsh "sudo solctl createvpc $VPC_NAME"

# Figure out which subnet this VPC got — IPs are deterministic within it.
SUBNET=$(rsh "sudo solctl list | awk -v n=$VPC_NAME '\$1 == n {print \$2}'")
[[ -n "$SUBNET" ]] || die "couldn't read subnet for $VPC_NAME from 'solctl list'"
OCTET=$(echo "$SUBNET" | awk -F'[./]' '{print $3}')
[[ "$OCTET" =~ ^[0-9]+$ ]] || die "couldn't parse 3rd octet from subnet '$SUBNET'"
REDIS_IP="172.100.$OCTET.2"   # first container in a fresh vpc always gets .2
log "subnet=$SUBNET, redis will be $REDIS_IP"

# -------- 4. sync source + build image --------
log "rsync solaradocs source to $REMOTE:/home/$REMOTE_USER/solaradocs/"
rsync -az --delete -e "ssh ${SSH_OPTS[*]}" \
    --exclude='.git' \
    --exclude='.venv' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='node_modules' \
    --exclude='errors.log' \
    --exclude='dump.rdb' \
    --exclude='deploy/sol-ctl/migrate.sh' \
    "$SOLARADOCS_DIR/" "$REMOTE:/home/$REMOTE_USER/solaradocs/"

log "building solaradocs-web image on the host (this can take a while on first run)"
rsh "cd /home/$REMOTE_USER/solaradocs && sudo docker build -t solaradocs-web:latest . \
  && sudo docker tag solaradocs-web:latest solaradocs-celery:latest \
  && sudo docker tag solaradocs-web:latest solaradocs-beat:latest"

# -------- 5. generate .env with mesh redis IP and ship it --------
log "generating .env with REDIS_URL pointing at $REDIS_IP"
TMP_ENV=$(mktemp)
trap 'rm -f "$TMP_ENV"' EXIT
# Rewrite anything pointing at the old docker-compose service name `redis`.
sed -E "s|@redis:6379|@$REDIS_IP:6379|g; s|//redis:6379|//$REDIS_IP:6379|g; s|=redis://redis:|=redis://$REDIS_IP:|g" \
    "$LOCAL_ENV" > "$TMP_ENV"

rcp "$TMP_ENV" "$REMOTE:/tmp/soldocs.env"
rsh "sudo solctl addenv $VPC_NAME /tmp/soldocs.env && rm -f /tmp/soldocs.env"

# -------- 6. assign + deploy --------
log "assigning redis (gets $REDIS_IP, volume on /var/sol-ctl/volumes/$VPC_NAME/redis/data)"
rsh "sudo solctl assign redis:7-alpine $VPC_NAME \
        --volume /var/sol-ctl/volumes/$VPC_NAME/redis/data:/data"

log "assigning solaradocs-web (gunicorn)"
rsh "sudo solctl assign solaradocs-web:latest $VPC_NAME \
        --cmd '$GUNICORN_CMD'"

log "assigning solaradocs-celery (worker)"
rsh "sudo solctl assign solaradocs-celery:latest $VPC_NAME \
        --cmd '$CELERY_WORKER_CMD'"

log "assigning solaradocs-beat (celery beat)"
rsh "sudo solctl assign solaradocs-beat:latest $VPC_NAME \
        --cmd '$CELERY_BEAT_CMD'"

log "deploying all containers in $VPC_NAME"
rsh "sudo solctl deploy $VPC_NAME"

# -------- summary --------
log "done. current state:"
rsh "sudo solctl list"
echo
echo "wardent should now route requests with  X-Sol-Environment: $VPC_NAME  to the web container."
echo "tail logs:        ssh -i $SSH_KEY $REMOTE 'sudo journalctl -u sol-control -f'"
echo "list containers:  ssh -i $SSH_KEY $REMOTE 'sudo solctl list'"
echo "prom targets:     ssh -i $SSH_KEY $REMOTE 'sudo cat /var/sol-ctl/targets.json'"
