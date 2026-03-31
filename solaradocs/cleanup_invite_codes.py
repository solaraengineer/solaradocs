from django.core.management.base import BaseCommand
from django.utils import timezone
from solaradocs.models import InviteCode

class Command(BaseCommand):
    def handle(self, *args, **options):
        deleted, _ = InviteCode.objects.filter(
            expires_at__isnull=False,
            expires_at__lt=timezone.now()
        ).delete()
        self.stdout.write(f"Deleted {deleted} expired invite codes")