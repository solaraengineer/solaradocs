import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'logic.settings')

from tracing import init_tracing
init_tracing()

application = get_wsgi_application()