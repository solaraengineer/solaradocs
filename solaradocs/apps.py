from django.apps import AppConfig


class SolaradocsConfig(AppConfig):
    default_auto_field = 'django.db.models.AutoField'
    name = 'solaradocs'

    def ready(self):
        from . import signals  # noqa: F401
