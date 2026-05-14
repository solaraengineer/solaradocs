-- Rewrites the solaradocs_changelog table with enterprise-style copy of every
-- historical entry, preserving original dates and version_types. Wrap in a
-- transaction so a partial failure leaves the table untouched.
--
-- Run via:  psql "$DB_MAIN" -f changelog_rewrite.sql
-- Or:       cat changelog_rewrite.sql | psql "$DB_MAIN"

BEGIN;

TRUNCATE TABLE solaradocs_changelog RESTART IDENTITY;

INSERT INTO solaradocs_changelog (version, version_type, title, description, created_at) VALUES
('1.0.1', 'patch', 'Editor rendering and toolbar fixes',
 'Addressed multiple rendering and toolbar visibility regressions in the document editor.',
 '2026-02-15 11:55:00+00'),

('1.0.2', 'patch', 'Mobile and desktop editing parity',
 'Document viewing and editing are now fully supported on mobile devices. Full document titles surface on hover and within the active editor.',
 '2026-02-20 22:29:00+00'),

('1.0.3', 'minor', 'Self-service password reset and revised rate limits',
 'Introduced a self-service password reset workflow accessible from the sign-in screen and raised per-route rate limits for authenticated traffic.',
 '2026-02-20 23:47:00+00'),

('1.0.4', 'minor', 'Branded error pages',
 'Replaced default browser error responses with branded SolaraDocs pages for status codes 400, 403, 404, 408, 413, 429, 500, 502, and 503.',
 '2026-02-21 22:05:00+00'),

('1.0.5', 'major', 'Incident: Stripe checkout disruption',
 'An ongoing incident is affecting Stripe checkout for new and existing subscribers. Charges processed during this window are being automatically refunded while engineering investigates.',
 '2026-02-21 23:32:00+00'),

('1.0.5', 'major', 'Resolved: Stripe checkout restored',
 'Subscription processing has been restored. Stripe webhook handling was updated for the latest API version; full operational status is confirmed.',
 '2026-02-21 23:44:00+00'),

('1.0.6', 'minor', 'Incident: Viewer role degraded',
 'An incident is preventing users with the Viewer role from loading document content. Engineering is actively developing a remediation.',
 '2026-02-22 01:11:00+00'),

('1.0.6', 'minor', 'Resolved: Viewer role with per-document access controls',
 'Viewer access has been restored alongside per-document permissions. Project owners can scope Viewer visibility to specific documents from the dashboard, with selections surfaced on the Collaborations page.',
 '2026-02-22 16:10:00+00'),

('1.0.7', 'major', 'Hotfix: collaborator save reliability',
 'Resolved a long-running defect that prevented contributors from persisting edits. The underlying cause has been remediated and additional safeguards added to prevent regression.',
 '2026-03-23 22:00:00+00'),

('1.0.8', 'minor', 'Invite codes and refreshed dashboard',
 'Introduced single-use invite codes for streamlined collaborator onboarding with pre-assigned roles. The dashboard layout has been refreshed in parallel.',
 '2026-03-27 16:30:00+00'),

('1.0.9', 'minor', 'Inline diffs for pending changes and backups',
 'Pending-change review and backup restoration now surface an inline diff that isolates modified lines, enabling clearer auditing of approvals and reverts.',
 '2026-04-01 16:23:00+00'),

('1.1.0', 'minor', 'Redesigned audit log experience',
 'The audit log surface has been redesigned with built-in search, a clearer row layout, and consistent access from both the dashboard and the editor.',
 '2026-04-01 23:02:00+00'),

('1.1.1', 'minor', 'In-place project renaming',
 'Project owners can now rename projects in place from the dashboard.',
 '2026-04-04 22:23:00+00'),

('1.1.2', 'major', 'Google Docs import',
 'Introduced Google Docs import. From the editor, select "Import docs", choose a destination team, and selected documents are mirrored into SolaraDocs within seconds.',
 '2026-04-12 16:57:00+00'),

('1.1.3', 'minor', 'Rejection feedback and editor resubmission',
 'Reviewers are now required to provide written justification when rejecting a pending change. Editors receive the feedback and can resume from their declined draft to submit a revised version.',
 '2026-04-23 12:54:00+00');

-- Quick sanity check
SELECT version, version_type, title, created_at
FROM solaradocs_changelog
ORDER BY created_at DESC;

COMMIT;
