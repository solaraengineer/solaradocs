#!/usr/bin/env bash
# deploy/v2/deploy.sh — server-side v2 deploy. Invoked over SSH by
# .github/workflows/deploy-v2.yml AFTER the source has been rsynced to
# /home/ubuntu/solaradocs/.
#
# Sequence:
#   1. Ensure sol-control-v2 systemd unit is active (assumes binaries
#      are already installed via sol-ctl repo's `make install-v2`).
#   2. Ensure local registry:2 container running on :5000.
#   3. Build solaradocs image from /home/ubuntu/solaradocs/, tag as
#      localhost:5000/solaradocs:<GIT_SHA>, push.
#   4. Stage configs under /var/sol-ctl/volumes/soldocs/configs/:
#      copy prometheus.yml / alert-rules.yml / loki-config.yaml /
#      promtail-config.yaml / tempo.yaml / otel-collector-config.yaml.
#      For alertmanager.yml: substitute ${BREVO_API_KEY} from the env file.
#   5. Ensure app-logs/errors.log exists (promtail reads it).
#   6. sed-substitute __IMAGE_TAG__ in manifests/services.yaml → <GIT_SHA>,
#      write to a tmp file (manifest stays repo-pure).
#   7. solctl-v2 validate -f, then apply -f.
#   8. Poll solctl-v2 status until all services Healthy (10 min max).
#   9. Smoke: curl router :9040 with secret + soldocs env, expect 200.
#
# Exit codes: 0 OK, 1 deploy failure, 2 preflight failure.
#
# Required env (set by the GitHub Actions workflow OR command-line):
#   GIT_SHA          — 7-char git SHA of the deployed commit
#
# Optional env:
#   SOLARADOCS_DIR   — default /home/ubuntu/solaradocs
#   VPC              — default soldocs
#   REGISTRY_PORT    — default 5000
#   HEALTHY_TIMEOUT  — default 600 (10 min)

set -euo pipefail

SOLARADOCS_DIR="${SOLARADOCS_DIR:-/home/ubuntu/solaradocs}"
REGISTRY_PORT="${REGISTRY_PORT:-5000}"
REGISTRY_NAME="${REGISTRY_NAME:-sol-prod-registry}"
HEALTHY_TIMEOUT="${HEALTHY_TIMEOUT:-600}"

log()  { printf '\033[1;34m[v2-deploy]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[v2-deploy]   OK\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[v2-deploy] FAIL\033[0m %s\n' "$*" >&2; exit 1; }

# 0a. Preconditions (host-level)
[ "$(id -u)" -eq 0 ] || fail "must be run as root"
[ -d "$SOLARADOCS_DIR" ] || fail "$SOLARADOCS_DIR not found (rsync source first)"
[ -f "$SOLARADOCS_DIR/Dockerfile" ] || fail "$SOLARADOCS_DIR/Dockerfile missing"
[ -f "$SOLARADOCS_DIR/manifests/vpc.yaml" ] || fail "manifests/vpc.yaml missing"
[ -f "$SOLARADOCS_DIR/manifests/blue-green.yaml" ] || fail "manifests/blue-green.yaml missing"
command -v solctl-v2 >/dev/null || fail "solctl-v2 not installed (run 'sudo make install-v2' from sol-ctl repo)"

# 0b. Pick TARGET vpc — read /solctl/deploy/active to find the standby
# (value == 0). Per the design doc: the key MUST exist (operator seeds
# it once before first deploy); if both values are 0, this is a fresh
# bootstrap and we default to sd-blue.
ACTIVE_JSON="$(etcdctl get /solctl/deploy/active --print-value-only 2>/dev/null || echo '')"
if [ -z "$ACTIVE_JSON" ]; then
  fail "/solctl/deploy/active is missing in etcd. Operator must seed it once: \
etcdctl put /solctl/deploy/active '{\"sd-blue\":0,\"sd-green\":0}'"
fi
VPC="$(echo "$ACTIVE_JSON" | python3 -c '
import json, sys
d = json.load(sys.stdin)
# Standby = the one with value 0. If both 0, bootstrap to sd-blue.
zeros = [k for k, v in d.items() if v == 0]
ones  = [k for k, v in d.items() if v == 1]
if not zeros:
    print("__NONE__")
elif len(ones) == 0:
    # fresh bootstrap: both zero → pick sd-blue if present, else first
    print("sd-blue" if "sd-blue" in d else zeros[0])
else:
    print(zeros[0])
')"
if [ "$VPC" = "__NONE__" ]; then
  fail "/solctl/deploy/active has no standby VPC (no zeros). Refusing to deploy onto active."
fi
log "target VPC (standby): $VPC"

SERVICES_MANIFEST="$SOLARADOCS_DIR/manifests/services-${VPC}.yaml"
[ -f "$SERVICES_MANIFEST" ] || fail "$SERVICES_MANIFEST missing — manifests must include services-<vpc>.yaml for each VPC"

ENV_FILE="/var/sol-ctl/${VPC}/.env"
VOLROOT="/var/sol-ctl/volumes/${VPC}"
[ -f "$ENV_FILE" ] || fail "$ENV_FILE missing — operator must place per-VPC env file once before first deploy"

if [ -z "${GIT_SHA:-}" ]; then
  GIT_SHA="$(cd "$SOLARADOCS_DIR" && git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d-%H%M%S)"
fi
IMAGE_TAG="$GIT_SHA"
IMAGE_REF="localhost:${REGISTRY_PORT}/solaradocs:${IMAGE_TAG}"

log "GIT_SHA=$GIT_SHA   IMAGE_REF=$IMAGE_REF"

# 1. Daemon up
if ! systemctl is-active --quiet sol-control-v2; then
  log "starting sol-control-v2 (was inactive)"
  systemctl start sol-control-v2
  sleep 3
fi
systemctl is-active --quiet sol-control-v2 || fail "sol-control-v2 failed to start; check 'journalctl -u sol-control-v2'"
ok "sol-control-v2 active"

# 2. Local registry
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

# 3. Build + push solaradocs image
log "building $IMAGE_REF (may take ~2-3 min on cache hit, ~5 on cold)"
docker build -q -t "$IMAGE_REF" "$SOLARADOCS_DIR" > /dev/null
log "pushing $IMAGE_REF"
docker push -q "$IMAGE_REF" > /dev/null
ok "image pushed"

# 4. Stage configs under /var/sol-ctl/volumes/soldocs/configs/.
log "staging configs from $SOLARADOCS_DIR → $VOLROOT/"
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

# Substitute BREVO_API_KEY into alertmanager.yml since v2 doesn't override
# the image ENTRYPOINT (compose's sed-wrapper approach isn't available).
BREVO_KEY="$(grep -E '^BREVO_API_KEY=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' || echo '')"
if [ -z "$BREVO_KEY" ]; then
  fail "BREVO_API_KEY not set in $ENV_FILE — alertmanager would fail to send email alerts"
fi
sed "s|{BREVO_API_KEY}|${BREVO_KEY}|g" \
  "$SOLARADOCS_DIR/alertmanager.yml" > "$VOLROOT/configs/alertmanager.yml"

# Free permissions for non-root container users (loki=10001, grafana=472, etc).
chmod 777 \
  "$VOLROOT/redis-data" \
  "$VOLROOT/prometheus-data" \
  "$VOLROOT/grafana-data" \
  "$VOLROOT/tempo-data" \
  "$VOLROOT/alertmanager-data" \
  "$VOLROOT/loki-data" \
  "$VOLROOT/prom-multiproc" \
  "$VOLROOT/app-logs"

# promtail tails errors.log; ensure it exists.
touch "$VOLROOT/app-logs/errors.log"
chmod 666 "$VOLROOT/app-logs/errors.log"
ok "configs staged"

# 5. Substitute __IMAGE_TAG__ in services-${VPC}.yaml → actual tag.
RESOLVED_MANIFEST="$(mktemp --suffix=.yaml)"
sed "s|__IMAGE_TAG__|${IMAGE_TAG}|g" "$SERVICES_MANIFEST" > "$RESOLVED_MANIFEST"

# 6. Validate (no etcd touch).
log "validating manifests"
solctl-v2 validate -f "$SOLARADOCS_DIR/manifests/vpc.yaml" > /dev/null \
  || fail "vpc.yaml failed validation"
solctl-v2 validate -f "$SOLARADOCS_DIR/manifests/blue-green.yaml" > /dev/null \
  || fail "blue-green.yaml failed validation"
solctl-v2 validate -f "$RESOLVED_MANIFEST" > /dev/null \
  || { echo "--- failing manifest ---"; cat "$RESOLVED_MANIFEST"; fail "services-${VPC}.yaml failed validation"; }
ok "manifests validated"

# 7. Apply (VPCs first, then blue/green route, then services for STANDBY only).
log "applying vpc.yaml (both sd-blue and sd-green)"
solctl-v2 apply -f "$SOLARADOCS_DIR/manifests/vpc.yaml" || fail "vpc apply failed"
sleep 2

log "applying blue-green.yaml (route policy)"
solctl-v2 apply -f "$SOLARADOCS_DIR/manifests/blue-green.yaml" || fail "blue-green apply failed"

log "applying services-${VPC}.yaml (image tag = $IMAGE_TAG)"
solctl-v2 apply -f "$RESOLVED_MANIFEST" || fail "services apply failed"
rm -f "$RESOLVED_MANIFEST"
ok "manifests applied"

# 8. Wait for all services in the STANDBY VPC to be Healthy. Vpc-scoped
#    etcd keys (Phase 14.E) make this a clean lookup:
#    /solctl/state/services/${VPC}/${svc}
log "waiting for HealthStatus=Healthy on standby (${VPC}) services (up to ${HEALTHY_TIMEOUT}s)"
HEALTH_SERVICES=(redis tempo otel-collector web prometheus grafana
                 alertmanager node-exporter redis-exporter loki promtail)
START="$(date +%s)"
for svc in "${HEALTH_SERVICES[@]}"; do
  while true; do
    if etcdctl get "/solctl/state/services/${VPC}/${svc}" --print-value-only 2>/dev/null \
       | grep -q '"kind":"healthy"'; then
      break
    fi
    NOW="$(date +%s)"
    if [ $((NOW - START)) -gt "$HEALTHY_TIMEOUT" ]; then
      log "--- solctl-v2 status snapshot ---"
      solctl-v2 status || true
      log "--- last 40 lines of daemon log ---"
      journalctl -u sol-control-v2 -n 40 --no-pager || true
      fail "service '${VPC}/${svc}' did not become Healthy within ${HEALTHY_TIMEOUT}s — \
NOT flipping; active VPC keeps serving"
    fi
    sleep 2
  done
  ok "${VPC}/${svc} Healthy"
done

if ! docker ps --format '{{.Names}}' | grep -qE "^celery-${VPC}-1(-g[0-9]+)?\$"; then
  fail "celery container is not Running in ${VPC}"
fi
ok "${VPC}/celery Running (no probe by design)"

# 9. PROMOTE: flip ${VPC} from standby → active. solctl-v2 promote runs
# the full atomic flip machinery in sol-control-v2 (etcd lease lock,
# docker start standby + sed wardent + restart wardent + docker stop
# old active + CAS active map). If promote fails the old VPC keeps
# serving — half-down is safer than half-up.
log "promoting ${VPC} to active (flip)"
if ! solctl-v2 promote "${VPC}"; then
  log "--- last 40 lines of daemon log ---"
  journalctl -u sol-control-v2 -n 40 --no-pager || true
  fail "promote ${VPC} failed — old active still serving (run 'solctl-v2 status' to inspect)"
fi
ok "${VPC} is now active"

# 10. Smoke: router accepts traffic AFTER the flip (new active should serve).
log "post-flip smoke: router :9040"
WARDENT_SECRET="$(grep -E '^WARDENT_SECRET=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' || echo '')"
if [ -z "$WARDENT_SECRET" ]; then
  log "WARNING: WARDENT_SECRET not in env file — router smoke SKIPPED"
else
  # The v2 router does literal env-name → vpc lookup (src/v2/router.rs).
  # Wardent's X-Sol-Environment was just sed-rewritten by promote to the
  # new active VPC, so the smoke must use the same value, not "production".
  CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
          -H "X-Wardent-Secret: ${WARDENT_SECRET}" \
          -H "X-Sol-Environment: ${VPC}" \
          http://127.0.0.1:9040/metrics)"
  if [ "$CODE" != "200" ]; then
    fail "router smoke: /metrics returned HTTP ${CODE} (expected 200) — \
flip went through but new active isn't serving cleanly. Consider 'solctl-v2 rollback'."
  fi
  ok "router /metrics → 200 (active = ${VPC})"
fi

# Done.
echo
log "v2 deploy OK (blue/green flipped active = ${VPC})"
log "  - image:       $IMAGE_REF"
log "  - manifests:   ${SERVICES_MANIFEST}"
log "  - daemon:      $(systemctl is-active sol-control-v2)"
log "  - services:    $(docker ps --format '{{.Names}}' | grep -cE "\-${VPC}-[0-9]+(-g[0-9]+)?\$")/12 running"
log
log "  Rollback if anything looks wrong:  sudo solctl-v2 rollback"
log "  Watch monitor logs:                sudo journalctl -u sol-control-v2 -f"