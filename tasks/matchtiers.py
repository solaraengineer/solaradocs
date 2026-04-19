import sys
sys.path.insert(0, '/app')

import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'logic.settings')

import django
django.setup()

from solaradocs.models import User, Project

for user in User.objects.all():
    tier = (user.Tier or 'free').lower()
    mismatched = Project.objects.filter(owner=user).exclude(tier=tier)
    count = mismatched.count()
    if count > 0:
        mismatched.update(tier=tier)
        print(f"{user.username}: updated {count} project(s) to {tier}")

print("done")