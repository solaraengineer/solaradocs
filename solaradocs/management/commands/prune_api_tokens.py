from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from solaradocs.models import UserApiToken


class Command(BaseCommand):
    help = 'Delete API tokens that have been expired or revoked for more than N days (default 90).'

    def add_arguments(self, parser):
        parser.add_argument('--days', type=int, default=90)
        parser.add_argument('--dry-run', action='store_true')

    def handle(self, *args, **opts):
        cutoff = timezone.now() - timedelta(days=opts['days'])
        qs = UserApiToken.objects.filter(expires_at__lt=cutoff) | UserApiToken.objects.filter(revoked_at__lt=cutoff)
        qs = qs.distinct()
        count = qs.count()
        self.stdout.write(f'{count} tokens eligible for deletion (expired/revoked before {cutoff.isoformat()})')
        if not opts['dry_run'] and count:
            qs.delete()
            self.stdout.write(self.style.SUCCESS(f'Deleted {count} tokens.'))
        elif opts['dry_run']:
            self.stdout.write('(dry run — no changes)')
