# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Django 4.2 project, settings module `logic.settings`. Use the venv at `.venv/`.

```bash
.venv/bin/python manage.py runserver
.venv/bin/python manage.py migrate
.venv/bin/python manage.py makemigrations solaradocs
.venv/bin/python manage.py test --settings=logic.test_settings
.venv/bin/python manage.py test solaradocs.tests.ClassName.test_name --settings=logic.test_settings
celery -A logic worker --loglevel=info
docker compose up -d
```

`docker-compose.yml` brings up the full observability stack alongside web/celery: Redis, OTel collector, Tempo, Prometheus, Alertmanager, Grafana, Loki, Promtail, node-exporter, redis-exporter. Only ports on `127.0.0.1` are exposed — production traffic comes in through wardent, not directly.

## Architecture

Confusing-but-intentional layout: there are **two** top-level Python packages.

- **`logic/`** — the Django *project* (settings, urls, wsgi/asgi, celery app). `DJANGO_SETTINGS_MODULE=logic.settings`. `INSTALLED_APPS` registers only `solaradocs`.
- **`solaradocs/`** — the single Django *app* with essentially all business logic. `views.py` and `tests.py` are intentionally monolithic — use grep/Read with offsets.

Important files:
- `models.py` — `AUTH_USER_MODEL = 'solaradocs.User'`; also `InvoicePayment` for billing rows
- `views.py` / `views_admin.py` / `views_emails.py` / `views_import.py`
- `context_processors.py` — `past_due_banner` exposes `show_past_due_banner` for the site-wide banner
- `templatetags/billing_extras.py` — `cents_to_dollars` filter
- `adapters.py` — `CustomSocialAccountAdapter` for django-allauth Google OAuth
- `r2_backups.py` — Cloudflare R2 backups via boto3
- `middleware.py` — `WardentSecretMiddleware`: validates a shared secret header. Required in production; **dropped in `logic/test_settings.py`** so the test client can hit views.
- `signals.py`, `tracing.py`

## Edge / reverse proxy

This Django app is the backend behind **wardent** (`../wardent/` — sibling Rust reverse proxy). The chain is:

```
client → Cloudflare → wardent → gunicorn (this app)
```

`WardentSecretMiddleware` enforces requests came through wardent.

## Stripe + billing

- Webhook handler `stripe_webhook` writes `InvoicePayment` rows on `invoice.paid` (status=paid), `invoice.payment_failed` (status=failed), and `charge.refunded` (looks up by `charge.invoice`; gracefully no-ops on one-off charges with no invoice). `update_or_create(stripe_invoice_id=...)` makes replays idempotent.
- `_tier_from_price_id(price_id)` (top of `views.py`) maps `STRIPE_*_PRICE_ID` settings → tier name; reuse it, don't inline the dict.
- Env vars are baked into containers at `docker create` time → if a user runs `addenv` after `assign`, the existing container is stale. `solctl rebuild` (in the sibling sol-ctl project) is the analogue.
- Billing portal: `/billing-portal/` → `views.billing_portal_session` creates a Stripe Billing Portal session and 302s the user there. Used by the "Update payment method" button on `profile.html` and the past-due banner. POST only — both call sites use forms with `{% csrf_token %}`.

## Config & external services

Settings are env-driven via python-dotenv. Required env vars:
- `DJANGO_SECRET_KEY`, `JWT_SECRET_KEY`, `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` (base64-encoded PEMs)
- `DB_MAIN` — parsed by `dj-database-url`
- `REDIS_URL`
- `STRIPE_SECRET_KEY` + `STRIPE_WEBHOOK_SECRET` + `STRIPE_*_PRICE_ID`
- `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET`
- `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` / `R2_BUCKET_NAME` / `R2_ENDPOINT_URL`
- `BREVO_API_KEY`
- `ADMIN_PANEL_PATH` (obscured admin prefix; default `crypticA7X`)
- `WARDENT_SECRET` (validated by `WardentSecretMiddleware`)

## Conventions

- Logging: errors from `solaradocs.views` go both to `errors.log` and to `ADMINS` via email.
- Migrations live under `solaradocs/migrations/`. Always `makemigrations solaradocs`.
- Cookies are `SAMESITE=Lax` and only `Secure` when `DEBUG=False`.
- The `terraform/` directory provisions the EC2 host; not part of the Django runtime.
- **No base.html**: every template is standalone (own DOCTYPE, own CSS). Site-wide UI like the past-due banner uses a context processor + `{% include "partials/past_due_banner.html" %}` placed just inside `<body>` of each main template.
- **Watch for duplicated view defs**: `views.py` has historically had every view defined twice (Python keeps the last one). If you see `^def name` appearing twice, dedupe.

## Test infrastructure

- `logic/test_settings.py` strips `WardentSecretMiddleware` from `MIDDLEWARE` (the reverse proxy isn't in front of the test client, so otherwise every request 403s). **Don't add it back.**
- **Python 3.14 quirk**: Django's `template_rendered` signal trips when copying `Context` (`super().__copy__` returns a `super` object that can't take `.dicts = ...`). Tests that render templates via `self.client.get()` will crash. Workaround: use `RequestFactory` + call view functions directly. See `BillingHistoryTests` / `QuickWinsTests` for the pattern.
- Run subsets: `.venv/bin/python manage.py test solaradocs.tests.<ClassName> --settings=logic.test_settings`
