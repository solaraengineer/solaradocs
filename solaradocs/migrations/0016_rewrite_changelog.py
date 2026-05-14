import datetime
from django.utils import timezone
from django.db import migrations


# Professional rewrites of the changelog (enterprise-style comms).
# Order: oldest first — the entry created last gets the most recent created_at,
# which matches Changelog.Meta.ordering = ['-created_at'].
NEW_ENTRIES = [
    {
        'version': '1.0.1', 'version_type': 'patch',
        'title': 'Editor rendering and toolbar fixes',
        'description': 'Addressed multiple rendering and toolbar visibility regressions in the document editor.',
        'created_at': datetime.datetime(2026, 2, 15, 11, 55, tzinfo=timezone.utc),
    },
    {
        'version': '1.0.2', 'version_type': 'patch',
        'title': 'Mobile and desktop editing parity',
        'description': 'Document viewing and editing are now fully supported on mobile devices. Full document titles surface on hover and within the active editor.',
        'created_at': datetime.datetime(2026, 2, 20, 22, 29, tzinfo=timezone.utc),
    },
    {
        'version': '1.0.3', 'version_type': 'minor',
        'title': 'Self-service password reset and revised rate limits',
        'description': 'Introduced a self-service password reset workflow accessible from the sign-in screen and raised per-route rate limits for authenticated traffic.',
        'created_at': datetime.datetime(2026, 2, 20, 23, 47, tzinfo=timezone.utc),
    },
    {
        'version': '1.0.4', 'version_type': 'minor',
        'title': 'Branded error pages',
        'description': 'Replaced default browser error responses with branded SolaraDocs pages for status codes 400, 403, 404, 408, 413, 429, 500, 502, and 503.',
        'created_at': datetime.datetime(2026, 2, 21, 22, 5, tzinfo=timezone.utc),
    },
    {
        'version': '1.0.5', 'version_type': 'major',
        'title': 'Incident: Stripe checkout disruption',
        'description': 'An ongoing incident is affecting Stripe checkout for new and existing subscribers. Charges processed during this window are being automatically refunded while engineering investigates.',
        'created_at': datetime.datetime(2026, 2, 21, 23, 32, tzinfo=timezone.utc),
    },
    {
        'version': '1.0.5', 'version_type': 'major',
        'title': 'Resolved: Stripe checkout restored',
        'description': 'Subscription processing has been restored. Stripe webhook handling was updated for the latest API version; full operational status is confirmed.',
        'created_at': datetime.datetime(2026, 2, 21, 23, 44, tzinfo=timezone.utc),
    },
    {
        'version': '1.0.6', 'version_type': 'minor',
        'title': 'Incident: Viewer role degraded',
        'description': 'An incident is preventing users with the Viewer role from loading document content. Engineering is actively developing a remediation.',
        'created_at': datetime.datetime(2026, 2, 22, 1, 11, tzinfo=timezone.utc),
    },
    {
        'version': '1.0.6', 'version_type': 'minor',
        'title': 'Resolved: Viewer role with per-document access controls',
        'description': 'Viewer access has been restored alongside per-document permissions. Project owners can scope Viewer visibility to specific documents from the dashboard, with selections surfaced on the Collaborations page.',
        'created_at': datetime.datetime(2026, 2, 22, 16, 10, tzinfo=timezone.utc),
    },
    {
        'version': '1.0.7', 'version_type': 'major',
        'title': 'Hotfix: collaborator save reliability',
        'description': 'Resolved a long-running defect that prevented contributors from persisting edits. The underlying cause has been remediated and additional safeguards added to prevent regression.',
        'created_at': datetime.datetime(2026, 3, 23, 22, 0, tzinfo=timezone.utc),
    },
    {
        'version': '1.0.8', 'version_type': 'minor',
        'title': 'Invite codes and refreshed dashboard',
        'description': 'Introduced single-use invite codes for streamlined collaborator onboarding with pre-assigned roles. The dashboard layout has been refreshed in parallel.',
        'created_at': datetime.datetime(2026, 3, 27, 16, 30, tzinfo=timezone.utc),
    },
    {
        'version': '1.0.9', 'version_type': 'minor',
        'title': 'Inline diffs for pending changes and backups',
        'description': 'Pending-change review and backup restoration now surface an inline diff that isolates modified lines, enabling clearer auditing of approvals and reverts.',
        'created_at': datetime.datetime(2026, 4, 1, 16, 23, tzinfo=timezone.utc),
    },
    {
        'version': '1.1.0', 'version_type': 'minor',
        'title': 'Redesigned audit log experience',
        'description': 'The audit log surface has been redesigned with built-in search, a clearer row layout, and consistent access from both the dashboard and the editor.',
        'created_at': datetime.datetime(2026, 4, 1, 23, 2, tzinfo=timezone.utc),
    },
    {
        'version': '1.1.1', 'version_type': 'minor',
        'title': 'In-place project renaming',
        'description': 'Project owners can now rename projects in place from the dashboard.',
        'created_at': datetime.datetime(2026, 4, 4, 22, 23, tzinfo=timezone.utc),
    },
    {
        'version': '1.1.2', 'version_type': 'major',
        'title': 'Google Docs import',
        'description': 'Introduced Google Docs import. From the editor, select "Import docs", choose a destination team, and selected documents are mirrored into SolaraDocs within seconds.',
        'created_at': datetime.datetime(2026, 4, 12, 16, 57, tzinfo=timezone.utc),
    },
    {
        'version': '1.1.3', 'version_type': 'minor',
        'title': 'Rejection feedback and editor resubmission',
        'description': 'Reviewers are now required to provide written justification when rejecting a pending change. Editors receive the feedback and can resume from their declined draft to submit a revised version.',
        'created_at': datetime.datetime(2026, 4, 23, 12, 54, tzinfo=timezone.utc),
    },
]


def rewrite(apps, schema_editor):
    Changelog = apps.get_model('solaradocs', 'Changelog')
    if not NEW_ENTRIES:
        return
    Changelog.objects.all().delete()
    for entry in NEW_ENTRIES:
        obj = Changelog.objects.create(
            version=entry['version'],
            title=entry['title'],
            description=entry['description'],
            version_type=entry.get('version_type', 'minor'),
        )
        if 'created_at' in entry:
            # auto_now_add overrode the value at insert time — fix it up.
            Changelog.objects.filter(id=obj.id).update(created_at=entry['created_at'])


def reverse_noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ('solaradocs', '0015_invoicepayment'),
    ]

    operations = [
        migrations.RunPython(rewrite, reverse_noop),
    ]
