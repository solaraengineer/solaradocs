import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'logic.settings')

prom_dir = os.environ.get('PROMETHEUS_MULTIPROC_DIR')
if prom_dir:
    os.makedirs(prom_dir, exist_ok=True)

# Tracing dials otel-collector:4317, which only resolves inside the sol-ctl mesh.
# Locally, skip it. In prod set DISABLE_TRACING=0 (or unset).
if os.environ.get('DISABLE_TRACING', '').lower() not in ('1', 'true', 'yes'):
    from solaradocs.tracing import init_tracing
    init_tracing()

application = get_wsgi_application()