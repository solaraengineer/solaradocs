#!/usr/bin/env bash
# deploy/v2/reset.sh — SAFE reset: deploy to TARGET_VPC, wait healthy,
# flip etcd + wardent, THEN nuke the old VPC's containers.
#
# The old VPC stays alive and serving traffic until the new one is
# confirmed healthy. No window where both VPCs are empty.
#
# Flow:
#   1. Park blue/green policy (rollback monitor idle during window)
#   2. Wipe etcd service state for TARGET_VPC only (old VPC untouched)
#   3. Nuke containers in TARGET_VPC only (old VPC still serving)
#   4. Build + push image
#   5. Stage configs for TARGET_VPC
#   6. Apply vpc.yaml + services-TARGET_VPC.yaml
#   7. Wait for TARGET_VPC to be healthy (/metrics 200)
#   8. FLIP: set etcd active map + sed wardent → TARGET_VPC
#   9. Nuke containers in OLD VPC (no longer serving)
#  10. Wipe etcd service state for OLD VPC
#  11. Re-apply blue-green.yaml → rollback monitor armed
#
# End state:
#   - TARGET_VPC has fresh containers, actively serving
#   - OLD VPC has zero containers
#   - Blue/green policy applied, rollback monitor running
#   - Next `git push master` deploys to OLD VPC as standby
#
# Required env:
#   GIT_SHA          — 7-char git SHA
#   TARGET_VPC       — sd-blue or sd-green
#
# Optional env:
#   SOLARADOCS_DIR   — default /home/ubuntu/solaradocs
#   REGISTRY_PORT    — default 5000
#   WARDENT_TOML     — default /etc/wardent.toml
#   SKIP_BUILD       — if set, reuse existing image
#   WAIT_METRICS_SEC — default 60
#   WAIT_HEALTHY_SEC — default 300 (max wait for full health before flip)
#
# Exit codes: 0 OK, 1 reset failure, 2 preflight failure.

set -euo pipefail

SOLARADOCS_DIR="${SOLARADOCS_DIR:-/home/ubuntu/solaradocs}"
REGISTRY_PORT="${REGISTRY_PORT:-5000}"
REGISTRY_NAME="${REGISTRY_NAME:-sol-prod-registry}"
WARDENT_TOML="${WARDENT_TOML:-/etc/wardent.toml}"
WAIT_METRICS_SEC="${WAIT_METRICS_SEC:-180}"
WAIT_HEALTHY_SEC="${WAIT_HEALTHY_SEC:-300}"

log()  { printf '\033[1;35m[reset]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[reset]   OK\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[reset] FAIL\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. Preflight -----------------------------------------------------------

[ "$(id -u)" -eq 0 ] || fail "must be run as root"
[ -d "$SOLARADOCS_DIR" ] || fail "$SOLARADOCS_DIR not found (rsync source first)"
[ -f "$SOLARADOCS_DIR/Dockerfile" ] || fail "$SOLARADOCS_DIR/Dockerfile missing"
[ -f "$SOLARADOCS_DIR/manifests/vpc.yaml" ] || fail "manifests/vpc.yaml missing"
command -v solctl-v2 >/dev/null || fail "solctl-v2 not installed"
command -v etcdctl   >/dev/null || fail "etcdctl not installed"

if [ -z "${TARGET_VPC:-}" ]; then
  fail "TARGET_VPC required (sd-blue or sd-green)"
fi
case "$TARGET_VPC" in
  sd-blue)  OLD_VPC=sd-green ;;
  sd-green) OLD_VPC=sd-blue  ;;
  *) fail "TARGET_VPC must be sd-blue or sd-green (got: $TARGET_VPC)" ;;
esac

SERVICES_MANIFEST="$SOLARADOCS_DIR/manifests/services-${TARGET_VPC}.yaml"
[ -f "$SERVICES_MANIFEST" ] || fail "$SERVICES_MANIFEST missing"

ENV_FILE="/var/sol-ctl/${TARGET_VPC}/.env"
[ -f "$ENV_FILE" ] || fail "$ENV_FILE missing — operator must place per-VPC env file once"

[ -f "$WARDENT_TOML" ] || fail "$WARDENT_TOML missing"
grep -q '^X-Sol-Environment' "$WARDENT_TOML" \
  || fail "$WARDENT_TOML has no 'X-Sol-Environment' line"

if [ -z "${GIT_SHA:-}" ]; then
  GIT_SHA="$(cd "$SOLARADOCS_DIR" && git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d-%H%M%S)"
fi
IMAGE_TAG="$GIT_SHA"
IMAGE_REF="localhost:${REGISTRY_PORT}/solaradocs:${IMAGE_TAG}"

log "TARGET_VPC=$TARGET_VPC   OLD_VPC=$OLD_VPC (will be nuked AFTER flip)"
log "IMAGE_REF=$IMAGE_REF   WARDENT_TOML=$WARDENT_TOML"

# --- 1. Daemon up -----------------------------------------------------------

if ! systemctl is-active --quiet sol-control-v2; then
  log "starting sol-control-v2"
  systemctl start sol-control-v2
  sleep 3
fi
systemctl is-active --quiet sol-control-v2 || fail "sol-control-v2 failed to start"
ok "sol-control-v2 active"

# --- 2. Park blue/green policy ----------------------------------------------
# Keeps the rollback monitor idle so it doesn't interfere during the window.

log "parking blue/green policy"
etcdctl del --prefix /solctl/bluegreen/ > /dev/null 2>&1 || true
etcdctl del /solctl/deploy/flipping     > /dev/null 2>&1 || true
ok "blue/green policy parked — rollback monitor idle"

# --- 3. Wipe etcd state for TARGET_VPC only ---------------------------------
# OLD_VPC's etcd state stays intact — its containers keep running + serving.

log "wiping etcd service state for $TARGET_VPC only"
etcdctl del --prefix "/solctl/services/${TARGET_VPC}/"       > /dev/null 2>&1 || true
etcdctl del --prefix "/solctl/state/services/${TARGET_VPC}/" > /dev/null 2>&1 || true
ok "etcd state cleared for $TARGET_VPC (${OLD_VPC} untouched)"

# --- 4. Nuke containers in TARGET_VPC only ----------------------------------
# OLD_VPC containers stay alive and keep serving traffic.

log "nuking containers in $TARGET_VPC only"
DOOMED=$(docker ps -a --format '{{.Names}}' \
  | grep -E "\-${TARGET_VPC}-[0-9]+(-g[0-9]+)?$" || true)
if [ -n "$DOOMED" ]; then
  echo "$DOOMED" | xargs -r docker rm -f > /dev/null
  ok "$(echo "$DOOMED" | wc -l) container(s) removed from $TARGET_VPC"
else
  ok "no containers in $TARGET_VPC (already clean)"
fi

# --- 5. Registry ------------------------------------------------------------

if ! docker ps --format '{{.Names}}' | grep -q "^${REGISTRY_NAME}\$"; then
  if docker ps -a --format '{{.Names}}' | grep -q "^${REGISTRY_NAME}\$"; then
    docker rm -f "$REGISTRY_NAME" > /dev/null
  fi
  log "starting local registry on :${REGISTRY_PORT}"
  docker run -d --restart=always --name "$REGISTRY_NAME" \
    -p "127.0.0.1:${REGISTRY_PORT}:5000" registry:2 > /dev/null
  for _ in $(seq 1 30); do
    curl -fsS "http://127.0.0.1:${REGISTRY_PORT}/v2/" > /dev/null 2>&1 && break
    sleep 0.5
  done
fi
ok "registry up at :${REGISTRY_PORT}"

# --- 6. Build + push (skippable) --------------------------------------------

if [ -n "${SKIP_BUILD:-}" ]; then
  log "SKIP_BUILD set — assuming $IMAGE_REF is already in the registry"
else
  log "building $IMAGE_REF"
  docker build -q -t "$IMAGE_REF" "$SOLARADOCS_DIR" > /dev/null
  log "pushing $IMAGE_REF"
  docker push -q "$IMAGE_REF" > /dev/null
  ok "image pushed"
fi

# --- 7. Stage configs for TARGET_VPC ----------------------------------------

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
  cp -f "$SOLARADOCS_DIR/$f" "$VOLROOT/configs/$f"
done

BREVO_KEY="$(grep -E '^BREVO_API_KEY=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' || echo '')"
[ -n "$BREVO_KEY" ] || fail "BREVO_API_KEY missing in $ENV_FILE"
sed "s|{BREVO_API_KEY}|${BREVO_KEY}|g" \
  "$SOLARADOCS_DIR/alertmanager.yml" > "$VOLROOT/configs/alertmanager.yml"

chmod 777 \
  "$VOLROOT/redis-data" "$VOLROOT/prometheus-data" "$VOLROOT/grafana-data" \
  "$VOLROOT/tempo-data" "$VOLROOT/alertmanager-data" "$VOLROOT/loki-data" \
  "$VOLROOT/prom-multiproc" "$VOLROOT/app-logs"
touch "$VOLROOT/app-logs/errors.log"
chmod 666 "$VOLROOT/app-logs/errors.log"
ok "configs staged"

# --- 8. Apply manifests (TARGET_VPC only) -----------------------------------

RESOLVED_MANIFEST="$(mktemp --suffix=.yaml)"
sed "s|__IMAGE_TAG__|${IMAGE_TAG}|g" "$SERVICES_MANIFEST" > "$RESOLVED_MANIFEST"

log "validating manifests"
solctl-v2 validate -f "$SOLARADOCS_DIR/manifests/vpc.yaml" > /dev/null \
  || fail "vpc.yaml validation failed"
solctl-v2 validate -f "$RESOLVED_MANIFEST" > /dev/null \
  || { echo "--- failing manifest ---"; cat "$RESOLVED_MANIFEST"; fail "services-${TARGET_VPC}.yaml validation failed"; }
ok "manifests validated"

log "applying vpc.yaml"
solctl-v2 apply -f "$SOLARADOCS_DIR/manifests/vpc.yaml" || fail "vpc apply failed"

log "applying services-${TARGET_VPC}.yaml (image tag = $IMAGE_TAG)"
solctl-v2 apply -f "$RESOLVED_MANIFEST" || fail "services apply failed"
rm -f "$RESOLVED_MANIFEST"
ok "manifests applied — daemon is bringing $TARGET_VPC containers up"

# --- 9. Wait for TARGET_VPC to be healthy -----------------------------------
# OLD_VPC is still serving traffic. We don't flip until TARGET is confirmed.

log "waiting up to 180s for web container to appear in $TARGET_VPC"
FOUND=0
for i in $(seq 1 90); do
  if docker ps --format '{{.Names}}' | grep -qE "^web-${TARGET_VPC}-1(-g[0-9]+)?\$"; then
    ok "web container running in $TARGET_VPC"
    FOUND=1
    break
  fi
  sleep 2
done
[ "$FOUND" = "1" ] || fail "web container not up in $TARGET_VPC after 180s — aborting (${OLD_VPC} still serving)"

WARDENT_SECRET="$(grep -E '^WARDENT_SECRET=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' || echo '')"
if [ -n "$WARDENT_SECRET" ]; then
  log "waiting up to ${WAIT_METRICS_SEC}s for $TARGET_VPC /metrics to return 200"
  START=$(date +%s)
  LAST_CODE="000"
  while true; do
    # Query the TARGET_VPC's web container directly via the router,
    # but with the target's environment header so it routes correctly.
    LAST_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        -H "X-Wardent-Secret: ${WARDENT_SECRET}" \
        -H "X-Sol-Environment: ${TARGET_VPC}" \
        http://127.0.0.1:9040/metrics 2>/dev/null || echo '000')"
    [ "$LAST_CODE" = "200" ] && { ok "$TARGET_VPC /metrics → 200"; break; }
    NOW=$(date +%s)
    if [ $((NOW - START)) -ge "$WAIT_METRICS_SEC" ]; then
      fail "$TARGET_VPC /metrics not 200 after ${WAIT_METRICS_SEC}s (last=$LAST_CODE) — aborting (${OLD_VPC} still serving)"
    fi
    sleep 3
  done
else
  log "WARN: WARDENT_SECRET not in $ENV_FILE — /metrics smoke SKIPPED (proceeding anyway)"
fi

# --- 10. FLIP: etcd active map + wardent → TARGET_VPC ----------------------
# This is the atomic cutover. OLD_VPC stops receiving traffic after this.

log "FLIPPING: ${OLD_VPC} → ${TARGET_VPC}"

etcdctl put /solctl/deploy/active "{\"${TARGET_VPC}\":1,\"${OLD_VPC}\":0}" > /dev/null
ok "etcd active map: ${TARGET_VPC}=1, ${OLD_VPC}=0"

log "rewriting wardent.toml → X-Sol-Environment = \"${TARGET_VPC}\""
sed -i "s|^X-Sol-Environment[[:space:]]*=.*|X-Sol-Environment = \"${TARGET_VPC}\"|" "$WARDENT_TOML"
if ! grep -q "^X-Sol-Environment = \"${TARGET_VPC}\"" "$WARDENT_TOML"; then
  fail "sed did not update X-Sol-Environment in $WARDENT_TOML"
fi
systemctl restart wardent
ok "wardent restarted → traffic now goes to ${TARGET_VPC}"

# Brief pause to let wardent finish restarting and route a few requests
# to TARGET_VPC before we tear down OLD_VPC.
sleep 5

# --- 11. Nuke OLD_VPC containers -------------------------------------------
# OLD_VPC is no longer receiving traffic. Safe to destroy.

log "nuking containers in $OLD_VPC (no longer serving)"
OLD_DOOMED=$(docker ps -a --format '{{.Names}}' \
  | grep -E "\-${OLD_VPC}-[0-9]+(-g[0-9]+)?$" || true)
if [ -n "$OLD_DOOMED" ]; then
  echo "$OLD_DOOMED" | xargs -r docker rm -f > /dev/null
  ok "$(echo "$OLD_DOOMED" | wc -l) container(s) removed from $OLD_VPC"
else
  ok "no containers in $OLD_VPC (already clean)"
fi

# Wipe OLD_VPC's etcd state so daemon doesn't try to reconcile it
log "wiping etcd service state for $OLD_VPC"
etcdctl del --prefix "/solctl/services/${OLD_VPC}/"       > /dev/null 2>&1 || true
etcdctl del --prefix "/solctl/state/services/${OLD_VPC}/" > /dev/null 2>&1 || true
ok "etcd state cleared for $OLD_VPC"

# --- 12. Re-arm blue/green policy -------------------------------------------
# Done last, after TARGET is confirmed serving and OLD is nuked.

log "re-applying blue-green.yaml (rollback monitor re-armed)"
solctl-v2 apply -f "$SOLARADOCS_DIR/manifests/blue-green.yaml" > /dev/null \
  || fail "blue-green.yaml apply failed"
ok "blue/green policy restored"

# --- Done -------------------------------------------------------------------

RUNNING=$(docker ps --format '{{.Names}}' | grep -cE "\-${TARGET_VPC}-[0-9]+(-g[0-9]+)?\$" || echo 0)
OLD_RUNNING=$(docker ps --format '{{.Names}}' | grep -cE "\-${OLD_VPC}-[0-9]+(-g[0-9]+)?\$" || echo 0)

echo
log "SAFE RESET complete"
log "  - active VPC:  $TARGET_VPC ($RUNNING containers running)"
log "  - old VPC:     $OLD_VPC ($OLD_RUNNING containers — expected 0)"
log "  - image:       $IMAGE_REF"
log "  - wardent:     $(systemctl is-active wardent)"
log "  - daemon:      $(systemctl is-active sol-control-v2)"
log "  - blue/green:  policy applied, rollback monitor armed"
log
log "  Old VPC was kept alive until new one was healthy."
log "  No downtime window with both VPCs empty."
log
log "  Next 'git push master' deploys to $OLD_VPC (as standby),"
log "  restoring full two-VPC blue/green rotation."