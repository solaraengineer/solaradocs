"""Local dev settings — inherits prod settings but drops the Wardent
middleware and points at local Redis so `manage.py runserver` works
without wardent + the mesh in front.

Run with:
    DISABLE_TRACING=1 REDIS_URL='redis://127.0.0.1:6379/0' \\
        .venv/bin/python manage.py runserver --settings=logic.dev_settings
"""
import os

# Force overrides BEFORE importing prod settings, since some values are
# captured at import time.
os.environ.setdefault('DISABLE_TRACING', '1')
os.environ.setdefault('REDIS_URL', 'redis://127.0.0.1:6379/0')

from .settings import *  # noqa: F401,F403

# Strip WardentSecretMiddleware — locally there's no wardent injecting
# the X-Wardent-Secret header, so every request would 403 without this.
MIDDLEWARE = [m for m in MIDDLEWARE if 'WardentSecretMiddleware' not in m]

# Recompute cache with the local REDIS_URL (settings.py captured the
# prod value at import time above).
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': os.environ['REDIS_URL'],
    }
}

DEBUG = True
ALLOWED_HOSTS = ['*']
