from django.db import migrations


# Replace every entry here with the "professional rewrites" from the master plan.
# Each entry: {version, title, description, version_type ('major'|'minor'|'patch')}.
# Order matters: entries created later in this list become the newest changelog
# row (Changelog.Meta.ordering = ['-created_at']). Leave the list empty to keep
# this migration as a no-op until you paste the content.
NEW_ENTRIES = [
    # {
    #     'version': '1.2.0',
    #     'title': 'Self-serve billing portal',
    #     'description': 'Update your card, download invoices, and resume past-due subscriptions without contacting support.',
    #     'version_type': 'minor',
    # },
    # ...
]


def rewrite(apps, schema_editor):
    Changelog = apps.get_model('solaradocs', 'Changelog')
    if not NEW_ENTRIES:
        # Nothing to write yet — leave existing entries untouched so partial
        # runs of this migration don't wipe the changelog by accident.
        return
    Changelog.objects.all().delete()
    Changelog.objects.bulk_create([
        Changelog(
            version=e['version'],
            title=e['title'],
            description=e['description'],
            version_type=e.get('version_type', 'minor'),
        )
        for e in NEW_ENTRIES
    ])


def reverse_noop(apps, schema_editor):
    # Destructive forward; intentionally non-reversible. Roll back by editing
    # NEW_ENTRIES in a follow-up migration.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ('solaradocs', '0015_invoicepayment'),
    ]

    operations = [
        migrations.RunPython(rewrite, reverse_noop),
    ]
