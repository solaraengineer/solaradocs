# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Django 4.2 project, settings module `logic.settings`. Use the venv at `.venv/`.

```bash
.venv/bin/python manage.py runserver
.venv/bin/python manage.py migrate
.venv/bin/python manage.py makemigrations solaradocs
.venv/bin/python manage.py test                              # uses logic.test_settings
.venv/bin/python manage.py test solaradocs.tests.ClassName.test_name
celery -A logic worker --loglevel=info                       # separate process
docker compose up -d                                         # full prod-like stack
```

`docker-compose.yml` brings up the whole observability stack alongside the web/celery containers: Redis, OTel collector, Tempo, Prometheus, Alertmanager, Grafana, Loki, Promtail, node-exporter, redis-exporter. Only ports on `127.0.0.1` are exposed — production traffic comes in through wardent/nginx, not directly.

## Architecture

Confusing-but-intentional layout: there are **two** top-level Python packages.

- **`logic/`** — the Django *project* (settings, urls, wsgi/asgi, celery app). `DJANGO_SETTINGS_MODULE=logic.settings`. `INSTALLED_APPS` registers only one local app: `solaradocs`.
- **`solaradocs/`** — the single Django *app* that contains essentially all business logic. Note: `solaradocs/views.py` is ~274KB and `solaradocs/tests.py` is ~111KB — both files are intentionally monolithic, so use grep/Read with line offsets rather than trying to load them whole.

Important files inside the `solaradocs` app:
- `models.py` — `AUTH_USER_MODEL = 'solaradocs.User'`, so the custom User lives here
- `views.py` / `views_admin.py` / `views_emails.py` / `views_import.py` — views are split by concern but the main `views.py` carries the bulk
- `urls.py` — URL routing (~9KB, central registry)
- `adapters.py` — `CustomSocialAccountAdapter` for django-allauth Google OAuth
- `google_import.py` — Google Docs/Drive import flow (OAuth scopes for `documents.readonly` + `drive.readonly` are configured in settings)
- `r2_backups.py` — Cloudflare R2 backups via boto3 (S3-compatible). `settings.R2_CLIENT` is a module-level boto3 client.
- `middleware.py` — `WardentSecretMiddleware`: validates a shared secret header. Requests that don't come through the wardent reverse proxy are rejected. **Keep this enabled in production**; when running outside Docker you need the secret set or local requests will fail.
- `tracing.py` — OpenTelemetry setup (Tempo as the OTLP backend)
- `signals.py` — Django signal handlers
- `tests.py` — single big test module

## Edge / reverse proxy

This Django app is the backend behind **wardent** (`../wardent/` — a Rust reverse proxy in the sibling Desktop project). The chain is:

```
client → Cloudflare → nginx → wardent → gunicorn (this app)
```

`WardentSecretMiddleware` enforces that requests came through wardent. If you change the shared secret, update both sides.

## Config & external services

Settings are env-driven via python-dotenv (loads `.env` at import time in `logic/settings.py`). Required-ish env vars:

- `DJANGO_SECRET_KEY`, `JWT_SECRET_KEY`, `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` (base64-encoded PEMs)
- `DB_MAIN` — full database URL (parsed by `dj-database-url`)
- `REDIS_URL` — used as Django cache, Celery broker, Celery result backend, and Channels layer
- `STRIPE_SECRET_KEY` + `STRIPE_WEBHOOK_SECRET` + `STRIPE_*_PRICE_ID` for the three subscription tiers
- `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET`
- `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` / `R2_BUCKET_NAME` / `R2_ENDPOINT_URL`
- `BREVO_API_KEY` (SMTP via smtp-relay.brevo.com — also injected into alertmanager.yml at container start)
- `ADMIN_PANEL_PATH` — obscured prefix for the Django admin URL (default `crypticA7X`). Override per-environment.

## Conventions

- Logging: errors from `solaradocs.views` go both to `errors.log` and to `ADMINS` via email. Don't change the logger name without updating `logic/settings.py`.
- Migrations live under `solaradocs/migrations/`. Always `makemigrations solaradocs` (not bare).
- Cookies are `SAMESITE=Lax` and only `Secure` when `DEBUG=False` — so local dev over HTTP works.
- The `terraform/` directory provisions the EC2 host; it's not part of the Django runtime.
- **Duplicated views**: `home`, `profile`, `dashboard`, `delete_project`, `stripe_webhook` (and others) are each defined *twice* in `views.py`. Python keeps the last one, but the dead copies are still grep hits — when editing, prefer `replace_all=true` to keep both copies in sync, or grep for `^def name` first and edit the higher-line-number one.
- **No base.html**: every template is standalone (own DOCTYPE, own CSS). Site-wide UI like the past-due banner uses a context processor (`solaradocs.context_processors.past_due_banner`) + `{% include "partials/past_due_banner.html" %}` placed just inside `<body>` of each main template.

## Stripe + billing

- Webhook handler `stripe_webhook` writes `InvoicePayment` rows on `invoice.paid` (status=paid), `invoice.payment_failed` (status=failed), and `charge.refunded` (looks up by `charge.invoice`; gracefully no-ops on one-off charges with no invoice). `update_or_create(stripe_invoice_id=...)` makes replays idempotent.
- `_tier_from_price_id(price_id)` (top of `views.py`) maps `STRIPE_*_PRICE_ID` settings → tier name; reuse it, don't inline the dict.
- Env vars are baked into containers at `docker create` time → if a user runs `addenv` *after* `assign`, the existing container is stale. `solctl rebuild` (in the sibling sol-ctl project) is the analogue; here, the equivalent is recreating via `assign` again or having the user re-checkout.
- Billing portal: `/billing-portal/` → `views.billing_portal_session` creates a Stripe Billing Portal session and 302s the user there. Used by the "Update payment method" button on `profile.html` and the past-due banner.

## Test infrastructure

- `logic/test_settings.py` strips `WardentSecretMiddleware` from `MIDDLEWARE` (the reverse proxy isn't in front of the test client, so otherwise every request 403s). Don't add it back.
- **Python 3.14 quirk**: Django's `template_rendered` signal trips when copying `Context` (`super().__copy__` returns a `super` object that can't take `.dicts = ...`). Tests that render templates via `self.client.get()` will crash. Workaround: use `RequestFactory` + call view functions directly. See `BillingHistoryTests` / `QuickWinsTests` for the pattern.
- Run subsets: `.venv/bin/python manage.py test solaradocs.tests.<ClassName> --settings=logic.test_settings`
