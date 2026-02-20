from django.apps import AppConfig


class SolaradocsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'solaradocs'

    def ready(self):
        import solaradocs.signals