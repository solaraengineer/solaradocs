#!/bin/sh
# docker-entrypoint.sh — runs on container start.
#
# Why this exists: Django migrations historically shipped in a release that
# started a new web container, but the container's CMD was gunicorn only, so
# the new schema was never applied and the first request against a model
# touching an unmigrated table 500'd (see Oct 2026 UserApiToken rollout).
#
# Policy: run `migrate --noinput` best-effort, then always exec gunicorn.
# A broken/failed migration must NOT prevent the app from starting — a
# half-rolled-out migration that errors would otherwise take down prod
# until operator intervention. We log the failure loudly instead.
#
# Only the ACTIVE blue/green side serves traffic, and this script runs in
# both — DB is shared, so letting whichever container boots first apply
# migrations is fine. Django's migrate is idempotent + locks the migrations
# table, so concurrent starts are safe.

set -eu

echo "[entrypoint] running: python manage.py migrate --noinput"
if python manage.py migrate --noinput; then
  echo "[entrypoint] migrate OK"
else
  rc=$?
  echo "[entrypoint] WARNING: migrate exited with code ${rc} — starting gunicorn anyway" >&2
fi

echo "[entrypoint] exec gunicorn"
exec "$@"
