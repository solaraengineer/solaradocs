#!/usr/bin/env bash
# deploy/v2/reset.sh — deploy to ONE blue/green VPC fresh, guarantee the
# other has zero containers. Invoked over SSH by .github/workflows/reset.yml
# AFTER the source has been rsynced to /home/ubuntu/solaradocs/.
#
# Blue/green stays in place — same two VPCs, same active map, same
# rollback monitor. This just skips the surge-then-drain dance and
# forces the OTHER vpc to be empty.
#
# What it does:
#   1. Removes the blue/green policy from etcd TEMPORARILY. This keeps the
#      rollback monitor idle during the destructive window (otherwise it
#      might see containers going down mid-tear-down and try to flip to a
#      VPC that has no containers yet).
#   2. Wipes etcd service state (desired + actual) for BOTH VPCs so the
#      daemon stops any in-flight reconciliation.
#   3. Rewrites /solctl/deploy/active so TARGET_VPC = 1, other = 0.
#   4. Tears down containers in BOTH VPCs.
#   5. Builds + pushes the solaradocs image tagged with GIT_SHA.
#   6. Stages configs under /var/sol-ctl/volumes/${TARGET_VPC}/.
#   7. Applies vpc.yaml + services-${TARGET_VPC}.yaml only. The other
#      VPC's services are NOT applied → daemon leaves it empty.
#   8. Sed's wardent.toml's X-Sol-Environment to TARGET_VPC + restarts
#      wardent. (Same edit the daemon does inside `promote`, but done
#      here directly since we're bypassing the promote machinery.)
#   9. Waits up to 60s for the web container to appear + up to 60s for
#      router :9040 /metrics to return 200. Doesn't block on full health.
#  10. RE-APPLIES blue-green.yaml so the rollback monitor is armed again.
#      (Deliberately done LAST — after target is confirmed serving — so
#      the monitor doesn't see startup errors and immediately flip.)
#
# End state:
#   - TARGET_VPC has fresh containers of the just-built image, actively
#     serving traffic (wardent points at it).
#   - The OTHER vpc has ZERO containers (bridge exists but empty).
#   - Blue/green policy is applied in etcd, rollback monitor is running.
#   - Next `git push master` → regular deploy.sh will deploy to the OTHER
#     vpc as standby (per /solctl/deploy/active), then promote, restoring
#     the two-VPC rotation.
#
# CAVEAT: while the other vpc is empty, an auto-rollback (if the monitor
# triggers on the active vpc's alerts) would flip to an empty vpc = brief
# outage until you re-deploy. Reset is a "single-vpc mode" — the safety
# net requires two populated vpcs.
#
# Required env:
#   GIT_SHA          — 7-char git SHA
#   TARGET_VPC       — sd-blue or sd-green (which VPC becomes the sole active)
#
# Optional env:
#   SOLARADOCS_DIR   — default /home/ubuntu/solaradocs
#   REGISTRY_PORT    — default 5000
#   WARDENT_TOML     — default /etc/wardent.toml
#   SKIP_BUILD       — if set, reuse existing image at localhost:5000/solaradocs:$GIT_SHA
#   WAIT_METRICS_SEC — default 60 (max wait for /metrics=200)
#
# Exit codes: 0 OK, 1 reset failure, 2 preflight failure.

set -euo pipefail

SOLARADOCS_DIR="${SOLARADOCS_DIR:-/home/ubuntu/solaradocs}"
REGISTRY_PORT="${REGISTRY_PORT:-5000}"
REGISTRY_NAME="${REGISTRY_NAME:-sol-prod-registry}"
WARDENT_TOML="${WARDENT_TOML:-/etc/wardent.toml}"
WAIT_METRICS_SEC="${WAIT_METRICS_SEC:-60}"

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
  sd-blue)  OTHER_VPC=sd-green ;;
  sd-green) OTHER_VPC=sd-blue  ;;
  *) fail "TARGET_VPC must be sd-blue or sd-green (got: $TARGET_VPC)" ;;
esac

SERVICES_MANIFEST="$SOLARADOCS_DIR/manifests/services-${TARGET_VPC}.yaml"
[ -f "$SERVICES_MANIFEST" ] || fail "$SERVICES_MANIFEST missing"

ENV_FILE="/var/sol-ctl/${TARGET_VPC}/.env"
[ -f "$ENV_FILE" ] || fail "$ENV_FILE missing — operator must place per-VPC env file once"

[ -f "$WARDENT_TOML" ] || fail "$WARDENT_TOML missing — override with WARDENT_TOML=/path"
grep -q '^X-Sol-Environment' "$WARDENT_TOML" \
  || fail "$WARDENT_TOML has no 'X-Sol-Environment' line to sed. Add [headers] X-Sol-Environment = \"...\""

if [ -z "${GIT_SHA:-}" ]; then
  GIT_SHA="$(cd "$SOLARADOCS_DIR" && git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d-%H%M%S)"
fi
IMAGE_TAG="$GIT_SHA"
IMAGE_REF="localhost:${REGISTRY_PORT}/solaradocs:${IMAGE_TAG}"

log "TARGET_VPC=$TARGET_VPC   OTHER_VPC=$OTHER_VPC (will be empty)"
log "IMAGE_REF=$IMAGE_REF   WARDENT_TOML=$WARDENT_TOML"

# --- 1. Daemon up -----------------------------------------------------------

if ! systemctl is-active --quiet sol-control-v2; then
  log "starting sol-control-v2"
  systemctl start sol-control-v2
  sleep 3
fi
systemctl is-active --quiet sol-control-v2 || fail "sol-control-v2 failed to start"
ok "sol-control-v2 active"

# --- 2. Wipe etcd service state + blue/green policy -------------------------
#
# ORDER MATTERS: wipe etcd BEFORE docker rm. If we rm'd containers first,
# the daemon's health monitor would immediately try to self-heal (since
# desired state still says "want them"). Deleting the desired keys first
# means the daemon sees "nothing wanted" and stays out of our way.

log "wiping etcd service state (desired + actual) + parking blue/green policy"
etcdctl del --prefix /solctl/services/       > /dev/null 2>&1 || true
etcdctl del --prefix /solctl/state/services/ > /dev/null 2>&1 || true
etcdctl del --prefix /solctl/bluegreen/      > /dev/null 2>&1 || true   # re-applied at step 10
etcdctl del /solctl/deploy/flipping          > /dev/null 2>&1 || true
ok "etcd services cleared, blue/green policy parked"

# Set the active map so target is 1 / other is 0. Do this now so router
# lookups from the moment containers come up target the right VPC.
etcdctl put /solctl/deploy/active "{\"${TARGET_VPC}\":1,\"${OTHER_VPC}\":0}" > /dev/null
ok "active map set: ${TARGET_VPC}=1, ${OTHER_VPC}=0"

# --- 3. NUKE all containers in BOTH VPCs -----------------------------------
#
# Brute docker rm. Fast, non-graceful. The etcd wipe above already told
# the daemon these shouldn't exist, so no fight.

log "nuking containers in BOTH VPCs (sd-blue + sd-green)"
DOOMED=$(docker ps -a --format '{{.Names}}' \
  | grep -E '\-(sd-blue|sd-green)-[0-9]+(-g[0-9]+)?$' || true)
if [ -n "$DOOMED" ]; then
  echo "$DOOMED" | xargs -r docker rm -f > /dev/null
  ok "$(echo "$DOOMED" | wc -l) container(s) removed"
else
  ok "no soldocs containers were running (already clean)"
fi

# --- 4. Registry -----------------------------------------------------------

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

# --- 5. Build + push (skippable) -------------------------------------------

if [ -n "${SKIP_BUILD:-}" ]; then
  log "SKIP_BUILD set — assuming $IMAGE_REF is already in the registry"
else
  log "building $IMAGE_REF"
  docker build -q -t "$IMAGE_REF" "$SOLARADOCS_DIR" > /dev/null
  log "pushing $IMAGE_REF"
  docker push -q "$IMAGE_REF" > /dev/null
  ok "image pushed"
fi

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

# --- 7. Apply manifests (target VPC only) ----------------------------------

RESOLVED_MANIFEST="$(mktemp --suffix=.yaml)"
sed "s|__IMAGE_TAG__|${IMAGE_TAG}|g" "$SERVICES_MANIFEST" > "$RESOLVED_MANIFEST"

log "validating manifests"
solctl-v2 validate -f "$SOLARADOCS_DIR/manifests/vpc.yaml" > /dev/null \
  || fail "vpc.yaml validation failed"
solctl-v2 validate -f "$RESOLVED_MANIFEST" > /dev/null \
  || { echo "--- failing manifest ---"; cat "$RESOLVED_MANIFEST"; fail "services-${TARGET_VPC}.yaml validation failed"; }
ok "manifests validated"

log "applying vpc.yaml (both sd-blue and sd-green bridges)"
solctl-v2 apply -f "$SOLARADOCS_DIR/manifests/vpc.yaml" || fail "vpc apply failed"

log "applying services-${TARGET_VPC}.yaml (image tag = $IMAGE_TAG)"
solctl-v2 apply -f "$RESOLVED_MANIFEST" || fail "services apply failed"
rm -f "$RESOLVED_MANIFEST"
ok "manifests applied — daemon is bringing containers up"

# NOTE: blue-green.yaml is intentionally NOT applied here. It's re-applied
# at step 10 (after /metrics is 200), so the rollback monitor doesn't see
# startup errors during the target's bring-up window and immediately flip
# to the (now empty) other vpc.

# --- 8. Point wardent at TARGET_VPC ----------------------------------------

log "rewriting wardent.toml → X-Sol-Environment = \"${TARGET_VPC}\""
sed -i "s|^X-Sol-Environment[[:space:]]*=.*|X-Sol-Environment = \"${TARGET_VPC}\"|" "$WARDENT_TOML"
if ! grep -q "^X-Sol-Environment = \"${TARGET_VPC}\"" "$WARDENT_TOML"; then
  fail "sed did not update X-Sol-Environment in $WARDENT_TOML (check the file's format)"
fi
systemctl restart wardent
ok "wardent restarted, now sending X-Sol-Environment=${TARGET_VPC}"

# --- 9. Quick liveness — web container appears, /metrics 200 --------------

log "waiting up to 60s for web container to appear"
FOUND=0
for i in $(seq 1 30); do
  if docker ps --format '{{.Names}}' | grep -qE "^web-${TARGET_VPC}-1(-g[0-9]+)?\$"; then
    ok "web container running"
    FOUND=1
    break
  fi
  sleep 2
done
[ "$FOUND" = "1" ] || log "WARN: web container not up after 60s (may still be pulling — check 'sudo solctl-v2 status')"

WARDENT_SECRET="$(grep -E '^WARDENT_SECRET=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' || echo '')"
if [ -n "$WARDENT_SECRET" ]; then
  log "waiting up to ${WAIT_METRICS_SEC}s for router /metrics to return 200"
  START=$(date +%s)
  LAST_CODE="000"
  while true; do
    LAST_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        -H "X-Wardent-Secret: ${WARDENT_SECRET}" \
        -H "X-Sol-Environment: ${TARGET_VPC}" \
        http://127.0.0.1:9040/metrics 2>/dev/null || echo '000')"
    [ "$LAST_CODE" = "200" ] && { ok "router /metrics → 200"; break; }
    NOW=$(date +%s)
    if [ $((NOW - START)) -ge "$WAIT_METRICS_SEC" ]; then
      log "WARN: /metrics not 200 after ${WAIT_METRICS_SEC}s (last=$LAST_CODE)"
      log "      check: sudo solctl-v2 status  /  sudo journalctl -u sol-control-v2 -n 40"
      break
    fi
    sleep 3
  done
else
  log "WARN: WARDENT_SECRET not in $ENV_FILE — /metrics smoke SKIPPED"
fi

# --- 10. Re-apply blue-green policy → rollback monitor re-armed ----------
#
# Done last, after target is confirmed serving. If we'd applied it before
# /metrics=200, the monitor might have seen startup transient errors and
# tried to flip to the (empty) other vpc.

log "re-applying blue-green.yaml (rollback monitor re-armed)"
solctl-v2 apply -f "$SOLARADOCS_DIR/manifests/blue-green.yaml" > /dev/null \
  || fail "blue-green.yaml apply failed"
ok "blue/green policy restored"

# --- Done -----------------------------------------------------------------

RUNNING=$(docker ps --format '{{.Names}}' | grep -cE "\-${TARGET_VPC}-[0-9]+(-g[0-9]+)?\$" || echo 0)
OTHER_RUNNING=$(docker ps --format '{{.Names}}' | grep -cE "\-${OTHER_VPC}-[0-9]+(-g[0-9]+)?\$" || echo 0)

echo
log "RESET complete"
log "  - active VPC:  $TARGET_VPC ($RUNNING/12 running)"
log "  - other VPC:   $OTHER_VPC ($OTHER_RUNNING containers — expected 0)"
log "  - image:       $IMAGE_REF"
log "  - wardent:     $(systemctl is-active wardent)"
log "  - daemon:      $(systemctl is-active sol-control-v2)"
log "  - blue/green:  policy applied, rollback monitor armed"
log
log "  CAVEAT: rollback flip would go to an empty vpc = brief outage."
log "  Next 'git push master' deploys to $OTHER_VPC (as standby per active"
log "  map), populating it and restoring the full two-vpc rotation."
