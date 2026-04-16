import django
import os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'logic.settings')
django.setup()

from solaradocs.models import User, Project

for user in User.objects.all():
    tier = (user.Tier or 'free').lower()
    Project.objects.filter(owner=user).exclude(tier=tier).update(tier=tier)

print("done")