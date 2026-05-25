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
VPC="${VPC:-soldocs}"
REGISTRY_PORT="${REGISTRY_PORT:-5000}"
REGISTRY_NAME="${REGISTRY_NAME:-sol-prod-registry}"
HEALTHY_TIMEOUT="${HEALTHY_TIMEOUT:-600}"
ENV_FILE="/var/sol-ctl/${VPC}/.env"
VOLROOT="/var/sol-ctl/volumes/${VPC}"

if [ -z "${GIT_SHA:-}" ]; then
  GIT_SHA="$(cd "$SOLARADOCS_DIR" && git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d-%H%M%S)"
fi
IMAGE_TAG="$GIT_SHA"
IMAGE_REF="localhost:${REGISTRY_PORT}/solaradocs:${IMAGE_TAG}"

log()  { printf '\033[1;34m[v2-deploy]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[v2-deploy]   OK\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[v2-deploy] FAIL\033[0m %s\n' "$*" >&2; exit 1; }

log "GIT_SHA=$GIT_SHA   IMAGE_REF=$IMAGE_REF"

# 0. Preconditions
[ "$(id -u)" -eq 0 ] || fail "must be run as root"
[ -d "$SOLARADOCS_DIR" ] || fail "$SOLARADOCS_DIR not found (rsync source first)"
[ -f "$SOLARADOCS_DIR/Dockerfile" ] || fail "$SOLARADOCS_DIR/Dockerfile missing"
[ -f "$SOLARADOCS_DIR/manifests/services.yaml" ] || fail "manifests/ missing in rsynced source"
[ -f "$ENV_FILE" ] || fail "$ENV_FILE missing — operator must place prod env file once before first deploy (see CUTOVER.md §1.4)"
command -v solctl-v2 >/dev/null || fail "solctl-v2 not installed (run 'sudo make install-v2' from sol-ctl repo)"

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

# 5. Substitute __IMAGE_TAG__ in services.yaml → actual tag.
RESOLVED_MANIFEST="$(mktemp --suffix=.yaml)"
sed "s|__IMAGE_TAG__|${IMAGE_TAG}|g" \
  "$SOLARADOCS_DIR/manifests/services.yaml" > "$RESOLVED_MANIFEST"

# 6. Validate (no etcd touch).
log "validating manifests"
solctl-v2 validate -f "$SOLARADOCS_DIR/manifests/vpc.yaml" > /dev/null \
  || fail "vpc.yaml failed validation"
solctl-v2 validate -f "$RESOLVED_MANIFEST" > /dev/null \
  || { echo "--- failing manifest ---"; cat "$RESOLVED_MANIFEST"; fail "services.yaml failed validation"; }
ok "manifests validated"

# 7. Apply.
log "applying vpc.yaml"
solctl-v2 apply -f "$SOLARADOCS_DIR/manifests/vpc.yaml" || fail "vpc apply failed"
sleep 2

log "applying services.yaml (image tag = $IMAGE_TAG)"
solctl-v2 apply -f "$RESOLVED_MANIFEST" || fail "services apply failed"
rm -f "$RESOLVED_MANIFEST"
ok "manifests applied"

# 8. Wait for all services Healthy (except celery which has no probe).
log "waiting for HealthStatus=Healthy in etcd state (up to ${HEALTHY_TIMEOUT}s)"
HEALTH_SERVICES=(redis tempo otel-collector web prometheus grafana
                 alertmanager node-exporter redis-exporter loki promtail)
START="$(date +%s)"
for svc in "${HEALTH_SERVICES[@]}"; do
  while true; do
    if etcdctl get "/solctl/state/services/${svc}" --print-value-only 2>/dev/null \
       | grep -q '"kind":"healthy"'; then
      break
    fi
    NOW="$(date +%s)"
    if [ $((NOW - START)) -gt "$HEALTHY_TIMEOUT" ]; then
      log "--- solctl-v2 status snapshot ---"
      solctl-v2 status || true
      log "--- last 40 lines of daemon log ---"
      journalctl -u sol-control-v2 -n 40 --no-pager || true
      fail "service '${svc}' did not become Healthy within ${HEALTHY_TIMEOUT}s"
    fi
    sleep 2
  done
  ok "${svc} Healthy"
done

# Celery has no probe — just confirm container is Running.
if ! docker ps --format '{{.Names}}' | grep -qE "^celery-${VPC}-1(-g[0-9]+)?\$"; then
  fail "celery container is not Running"
fi
ok "celery Running (no probe by design)"

# 9. Smoke: router accepts traffic.
log "smoking router :9040"
WARDENT_SECRET="$(grep -E '^WARDENT_SECRET=' "$ENV_FILE" | cut -d= -f2- | tr -d '"' || echo '')"
if [ -z "$WARDENT_SECRET" ]; then
  log "WARNING: WARDENT_SECRET not in env file — router smoke SKIPPED"
else
  CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
          -H "X-Wardent-Secret: ${WARDENT_SECRET}" \
          -H "X-Sol-Environment: ${VPC}" \
          http://127.0.0.1:9040/metrics)"
  if [ "$CODE" != "200" ]; then
    fail "router smoke: /metrics returned HTTP ${CODE} (expected 200)"
  fi
  ok "router /metrics → 200"
fi

# Done.
echo
log "v2 deploy OK"
log "  - image:       $IMAGE_REF"
log "  - manifest:    $SOLARADOCS_DIR/manifests/{vpc,services}.yaml"
log "  - daemon:      $(systemctl is-active sol-control-v2)"
log "  - services:    $(docker ps --format '{{.Names}}' | grep -cE "\-${VPC}-[0-9]+(-g[0-9]+)?\$")/12 running"
log
log "  Grafana:       http://127.0.0.1:3000  (admin/$(grep '^GRAFANA_PASSWORD=' "$ENV_FILE" | cut -d= -f2- | head -c4)...)"
log "  Prom:          http://127.0.0.1:9090"
log "  Alertmanager:  http://127.0.0.1:9093"