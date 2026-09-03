#!/usr/bin/env bash
# deploy/v2/stabilize.sh — bring solaradocs to a stable single-VPC state.
#
# One script, one job: nuke ALL soldocs containers on both VPCs, wipe etcd
# clean (including the exhausted IP counters), rebuild the app image from
# whatever source is currently at /home/ubuntu/solaradocs, and deploy fresh
# to ONE VPC. No blue/green, no rollback monitor, no CI.
#
# Run manually on the server (as root):
#   sudo bash /home/ubuntu/solaradocs/deploy/v2/stabilize.sh
#   sudo TARGET_VPC=sd-green bash /home/ubuntu/solaradocs/deploy/v2/stabilize.sh
#
# Optional env:
#   TARGET_VPC       — sd-blue or sd-green (default: sd-blue)
#   SOLARADOCS_DIR   — default /home/ubuntu/solaradocs
#   REGISTRY_PORT    — default 5000
#   REGISTRY_NAME    — default sol-prod-registry
#   WARDENT_TOML     — default /etc/wardent/wardent.toml
#   WAIT_SEC         — default 180 (each of: web container appears, /metrics=200)
#   GIT_SHA          — default: `git rev-parse --short HEAD` in SOLARADOCS_DIR
#
# Exit codes: 0 OK, 1 failure, 2 preflight failure.

set -euo pipefail

TARGET_VPC="${TARGET_VPC:-sd-blue}"
case "$TARGET_VPC" in
  sd-blue)  OTHER_VPC=sd-green ;;
  sd-green) OTHER_VPC=sd-blue  ;;
  *) echo "TARGET_VPC must be sd-blue or sd-green (got: $TARGET_VPC)" >&2; exit 2 ;;
esac

SOLARADOCS_DIR="${SOLARADOCS_DIR:-/home/ubuntu/solaradocs}"
REGISTRY_PORT="${REGISTRY_PORT:-5000}"
REGISTRY_NAME="${REGISTRY_NAME:-sol-prod-registry}"
WARDENT_TOML="${WARDENT_TOML:-/etc/wardent/wardent.toml}"
WAIT_SEC="${WAIT_SEC:-180}"
GIT_SHA="${GIT_SHA:-$(cd "$SOLARADOCS_DIR" 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || echo unknown)}"

log()  { printf '\033[1;35m[stabilize]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[stabilize]   OK\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[stabilize] FAIL\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. Preflight -----------------------------------------------------------

[ "$(id -u)" -eq 0 ] || fail "must run as root (sudo)"

[ -d "$SOLARADOCS_DIR" ]                       || fail "$SOLARADOCS_DIR not found"
[ -f "$SOLARADOCS_DIR/Dockerfile" ]            || fail "$SOLARADOCS_DIR/Dockerfile missing"
VPC_MANIFEST="$SOLARADOCS_DIR/manifests/vpc.yaml"
SERVICES_MANIFEST="$SOLARADOCS_DIR/manifests/services-${TARGET_VPC}.yaml"
[ -f "$VPC_MANIFEST" ]                         || fail "$VPC_MANIFEST missing"
[ -f "$SERVICES_MANIFEST" ]                    || fail "$SERVICES_MANIFEST missing"

ENV_FILE="/var/sol-ctl/${TARGET_VPC}/.env"
[ -f "$ENV_FILE" ]                             || fail "$ENV_FILE missing"
[ -s "$ENV_FILE" ]                             || fail "$ENV_FILE is empty (populate it first)"

[ -f "$WARDENT_TOML" ]                         || fail "$WARDENT_TOML missing"
grep -q '^X-Sol-Environment' "$WARDENT_TOML"   || fail "$WARDENT_TOML has no X-Sol-Environment line"

command -v solctl-v2 >/dev/null                || fail "solctl-v2 not installed"
command -v etcdctl   >/dev/null                || fail "etcdctl not installed"

BREVO_KEY="$(grep -E '^BREVO_API_KEY=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' || echo '')"
[ -n "$BREVO_KEY" ] || fail "BREVO_API_KEY missing in $ENV_FILE"

IMAGE_TAG="${GIT_SHA}"
IMAGE_REF="localhost:${REGISTRY_PORT}/solaradocs:${IMAGE_TAG}"

log "TARGET_VPC=$TARGET_VPC   OTHER_VPC=$OTHER_VPC (will be empty)"
log "IMAGE_REF=$IMAGE_REF"
log "WARDENT_TOML=$WARDENT_TOML"

# --- 1. Daemon up -----------------------------------------------------------

systemctl start sol-control-v2 2>/dev/null || true
sleep 2
systemctl is-active --quiet sol-control-v2 || fail "sol-control-v2 not active"
ok "sol-control-v2 active"

# --- 2. Nuke ALL soldocs containers on both VPCs ---------------------------
# Non-graceful. We're stabilizing from a broken state; no requests to drain.

log "removing all soldocs containers (sd-blue + sd-green)"
DOOMED=$(docker ps -a --format '{{.Names}}' \
  | grep -E '\-(sd-blue|sd-green)-[0-9]+(-g[0-9]+)?$' || true)
if [ -n "$DOOMED" ]; then
  echo "$DOOMED" | xargs -r docker rm -f > /dev/null
  ok "$(echo "$DOOMED" | wc -l) container(s) removed"
else
  ok "no soldocs containers were running"
fi

# --- 3. Wipe etcd clean ----------------------------------------------------
# Services live at /solctl/services/{name} (global, VPC-in-value), so we
# nuke the whole prefix. Also reset the per-VPC IP counters — today's
# sd-blue counter is exhausted at 255/253 from loki's restart storm.

log "wiping etcd: services, state, bluegreen, deploy flags, IP counters"
etcdctl del --prefix /solctl/services/       > /dev/null 2>&1 || true
etcdctl del --prefix /solctl/state/services/ > /dev/null 2>&1 || true
etcdctl del --prefix /solctl/bluegreen/      > /dev/null 2>&1 || true
etcdctl del /solctl/deploy/flipping          > /dev/null 2>&1 || true
etcdctl del /solctl/deploy/active            > /dev/null 2>&1 || true
etcdctl del --prefix /solctl/internal/vpcs/  > /dev/null 2>&1 || true
ok "etcd wiped"

etcdctl put /solctl/deploy/active "{\"${TARGET_VPC}\":1,\"${OTHER_VPC}\":0}" > /dev/null
ok "active map set: ${TARGET_VPC}=1, ${OTHER_VPC}=0"

# --- 4. Registry -----------------------------------------------------------

if ! docker ps --format '{{.Names}}' | grep -q "^${REGISTRY_NAME}\$"; then
  if docker ps -a --format '{{.Names}}' | grep -q "^${REGISTRY_NAME}\$"; then
    docker start "$REGISTRY_NAME" > /dev/null
  else
    docker run -d --restart=always --name "$REGISTRY_NAME" \
      -p "${REGISTRY_PORT}:5000" registry:2 > /dev/null
  fi
  for i in $(seq 1 10); do
    curl -sf "http://localhost:${REGISTRY_PORT}/v2/" > /dev/null && break
    sleep 1
  done
fi
ok "registry up at :${REGISTRY_PORT}"

# --- 5. Build + push -------------------------------------------------------
# --network=host: the default docker bridge can't reach the AWS VPC DNS
# (172.31.0.2) on this host, so pip install can't resolve pypi.org.

log "building $IMAGE_REF"
docker build --network=host -q -t "$IMAGE_REF" "$SOLARADOCS_DIR" > /dev/null
log "pushing $IMAGE_REF"
docker push -q "$IMAGE_REF" > /dev/null
ok "image built + pushed"

# --- 6. Stage configs for TARGET_VPC ---------------------------------------

VOLROOT="/var/sol-ctl/volumes/${TARGET_VPC}"
log "staging configs into $VOLROOT/"
mkdir -p \
  "$VOLROOT/configs" \
  "$VOLROOT/redis-data" \
  "$VOLROOT/prometheus-data" \
  "$VOLROOT/grafana-data" \
  "$VOLROOT/tempo-data" \
  "$VOLROOT/alertmanager-data" \
  "$VOLROOT/loki-data" \
  "$VOLROOT/prom-multiproc" \
  "$VOLROOT/app-logs"

for f in prometheus.yml alert-rules.yml loki-config.yaml \
         promtail-config.yaml tempo.yaml otel-collector-config.yaml; do
  [ -f "$SOLARADOCS_DIR/$f" ] || fail "$SOLARADOCS_DIR/$f missing"
  cp -f "$SOLARADOCS_DIR/$f" "$VOLROOT/configs/$f"
done

[ -f "$SOLARADOCS_DIR/alertmanager.yml" ] || fail "$SOLARADOCS_DIR/alertmanager.yml missing"
sed "s|{BREVO_API_KEY}|${BREVO_KEY}|g" \
  "$SOLARADOCS_DIR/alertmanager.yml" > "$VOLROOT/configs/alertmanager.yml"

chmod 777 \
  "$VOLROOT/redis-data" "$VOLROOT/prometheus-data" "$VOLROOT/grafana-data" \
  "$VOLROOT/tempo-data" "$VOLROOT/alertmanager-data" "$VOLROOT/loki-data" \
  "$VOLROOT/prom-multiproc" "$VOLROOT/app-logs"
touch "$VOLROOT/app-logs/errors.log"
chmod 666 "$VOLROOT/app-logs/errors.log"
ok "configs staged"

# --- 7. Apply manifests ----------------------------------------------------

RESOLVED_MANIFEST="$(mktemp --suffix=.yaml)"
sed "s|__IMAGE_TAG__|${IMAGE_TAG}|g" "$SERVICES_MANIFEST" > "$RESOLVED_MANIFEST"
if grep -q '__IMAGE_TAG__' "$RESOLVED_MANIFEST"; then
  cat "$RESOLVED_MANIFEST"; fail "unresolved __IMAGE_TAG__ in services manifest"
fi

log "validating manifests"
solctl-v2 validate -f "$VPC_MANIFEST" > /dev/null      || fail "vpc.yaml validation failed"
solctl-v2 validate -f "$RESOLVED_MANIFEST" > /dev/null \
  || { echo "--- failing manifest ---"; cat "$RESOLVED_MANIFEST"; fail "services manifest validation failed"; }
ok "manifests validated"

log "applying vpc.yaml"
solctl-v2 apply -f "$VPC_MANIFEST" || fail "vpc apply failed"

log "applying services-${TARGET_VPC}.yaml (image tag = $IMAGE_TAG)"
solctl-v2 apply -f "$RESOLVED_MANIFEST" || fail "services apply failed"
rm -f "$RESOLVED_MANIFEST"
ok "manifests applied — daemon is bringing containers up"

# --- 8. Point wardent at TARGET_VPC ----------------------------------------

log "rewriting wardent.toml → X-Sol-Environment = \"${TARGET_VPC}\""
sed -i "s|^X-Sol-Environment[[:space:]]*=.*|X-Sol-Environment = \"${TARGET_VPC}\"|" "$WARDENT_TOML"
grep -q "^X-Sol-Environment = \"${TARGET_VPC}\"" "$WARDENT_TOML" \
  || fail "sed did not update X-Sol-Environment in $WARDENT_TOML"
systemctl restart wardent
ok "wardent restarted → ${TARGET_VPC}"

# --- 9. Wait for web + /metrics --------------------------------------------

log "waiting up to ${WAIT_SEC}s for web-${TARGET_VPC}-1 to appear"
FOUND=0
for i in $(seq 1 $((WAIT_SEC / 2))); do
  if docker ps --format '{{.Names}}' | grep -qE "^web-${TARGET_VPC}-1(-g[0-9]+)?\$"; then
    FOUND=1; break
  fi
  sleep 2
done
[ "$FOUND" = "1" ] || fail "web-${TARGET_VPC}-1 did not appear in ${WAIT_SEC}s (check 'solctl-v2 status' + 'journalctl -u sol-control-v2 -n 100')"
ok "web container up"

WARDENT_SECRET="$(grep -E '^WARDENT_SECRET=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' || echo '')"
if [ -n "$WARDENT_SECRET" ]; then
  log "waiting up to ${WAIT_SEC}s for /metrics=200 via router"
  START=$(date +%s)
  LAST=000
  while true; do
    LAST=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
      -H "X-Wardent-Secret: ${WARDENT_SECRET}" \
      -H "X-Sol-Environment: ${TARGET_VPC}" \
      "http://127.0.0.1:9040/metrics" 2>/dev/null || echo 000)
    [ "$LAST" = "200" ] && { ok "/metrics → 200"; break; }
    NOW=$(date +%s)
    if [ $((NOW - START)) -ge "$WAIT_SEC" ]; then
      fail "/metrics not 200 after ${WAIT_SEC}s (last=$LAST)"
    fi
    sleep 3
  done
else
  log "WARN: WARDENT_SECRET not in $ENV_FILE — /metrics smoke SKIPPED"
fi

# --- Done ------------------------------------------------------------------

RUNNING_T=$(docker ps --format '{{.Names}}' | grep -cE "\-${TARGET_VPC}-[0-9]+(-g[0-9]+)?\$" || echo 0)
RUNNING_O=$(docker ps --format '{{.Names}}' | grep -cE "\-${OTHER_VPC}-[0-9]+(-g[0-9]+)?\$" || echo 0)

echo
log "STABILIZE complete"
log "  active VPC:   $TARGET_VPC ($RUNNING_T containers)"
log "  other VPC:    $OTHER_VPC ($RUNNING_O containers, expected 0)"
log "  image:        $IMAGE_REF"
log "  wardent:      $(systemctl is-active wardent)"
log "  daemon:       $(systemctl is-active sol-control-v2)"
log
log "  Blue/green policy is OFF. No rollback monitor."
log "  Loki networking (root cause of today's IP-counter thrash) is NOT"
log "  addressed here — expect loki to be Unhealthy. Fix separately."
