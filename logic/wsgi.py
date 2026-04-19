import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'logic.settings')

prom_dir = os.environ.get('PROMETHEUS_MULTIPROC_DIR')
if prom_dir:
    os.makedirs(prom_dir, exist_ok=True)

from solaradocs.tracing import init_tracing
init_tracing()

application = get_wsgi_application()