import json
from unittest.mock import patch, MagicMock
from datetime import timedelta

from django.test import TestCase, RequestFactory, override_settings
from django.http import HttpResponse
from django.core.cache import cache
from django.utils import timezone

from solaradocs.models import (
    User, Project, Documents, Teams, TeamMember, Contributor,
    Pending, PendingAction, Audit, Backup, Changelog,
    ViewerDocumentAccess, InviteCode, PromoCodes, InvoicePayment,
    TIER_LIMITS as MODEL_TIER_LIMITS,
)


MOCK_AUTH = patch('solaradocs.views.verify_auth_token', return_value={'user_id': 1})


@override_settings(
    RATELIMIT_ENABLE=False,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class BaseTestCase(TestCase):
    """Shared fixtures and helpers."""

    def setUp(self):
        cache.clear()
        self.owner = User.objects.create_user(
            username='testowner', email='owner@test.com', password='pass123456',
        )
        self.project = Project.objects.create(
            owner=self.owner, project_name='TestProject', tier='team',
            backups_enabled=True,
        )
        self.public_team = Teams.objects.create(
            project=self.project, team_name='Public',
        )
        self.doc = Documents.objects.create(
            project=self.project, document_name='Test Doc',
            content='<p>Initial content</p>', team_assigned=self.public_team,
        )

    # ---- helpers ----
    def _post(self, url, data=None, user=None):
        u = user or self.owner
        self.client.force_login(u)
        with patch('solaradocs.views.verify_auth_token', return_value={'user_id': u.id}):
            return self.client.post(
                url, json.dumps(data or {}),
                content_type='application/json',
                HTTP_AUTHORIZATION='Bearer test-token',
            )

    def _get(self, url, user=None):
        self.client.force_login(user or self.owner)
        return self.client.get(url)

    def _make_contributor(self, username, role='EDITOR', project=None):
        p = project or self.project
        u = User.objects.create_user(username=username, email=f'{username}@test.com', password='pass123456')
        Contributor.objects.create(project=p, username=username, role=role)
        return u

    def _make_team_member(self, user, team=None, role='EDITOR', can_direct_save=False):
        t = team or self.public_team
        return TeamMember.objects.create(team=t, user=user, role=role, can_direct_save=can_direct_save)


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------
class ModelTests(TestCase):
    def test_user_defaults(self):
        u = User.objects.create_user(username='u1', password='test123456')
        self.assertEqual(u.Tier, 'free')
        self.assertEqual(u.subscription_status, 'none')
        self.assertFalse(u.promo)
        self.assertEqual(u.retries_left, 0)

    def test_project_str(self):
        u = User.objects.create_user(username='u2', password='test123456')
        p = Project.objects.create(owner=u, project_name='My Project')
        self.assertEqual(str(p), 'My Project')

    def test_document_google_doc_id_nullable(self):
        u = User.objects.create_user(username='u3', password='test123456')
        p = Project.objects.create(owner=u, project_name='P')
        t = Teams.objects.create(project=p, team_name='Public')
        d = Documents.objects.create(project=p, document_name='D', team_assigned=t)
        self.assertIsNone(d.google_doc_id)

    def test_document_google_doc_id_set(self):
        u = User.objects.create_user(username='u4', password='test123456')
        p = Project.objects.create(owner=u, project_name='P')
        t = Teams.objects.create(project=p, team_name='T')
        d = Documents.objects.create(
            project=p, document_name='D', team_assigned=t,
            google_doc_id='abc123',
        )
        self.assertEqual(d.google_doc_id, 'abc123')

    def test_team_member_unique_together(self):
        u = User.objects.create_user(username='u5', password='test123456')
        p = Project.objects.create(owner=u, project_name='P')
        t = Teams.objects.create(project=p, team_name='T')
        TeamMember.objects.create(team=t, user=u, role='EDITOR')
        with self.assertRaises(Exception):
            TeamMember.objects.create(team=t, user=u, role='ADMIN')

    def test_contributor_unique_together(self):
        u = User.objects.create_user(username='u6', password='test123456')
        p = Project.objects.create(owner=u, project_name='P')
        Contributor.objects.create(project=p, username='bob')
        with self.assertRaises(Exception):
            Contributor.objects.create(project=p, username='bob')

    def test_invite_code_expired(self):
        u = User.objects.create_user(username='u7', password='test123456')
        p = Project.objects.create(owner=u, project_name='P')
        ic = InviteCode.objects.create(
            project=p, code='ABC123',
            expires_at=timezone.now() - timedelta(hours=1),
        )
        self.assertTrue(ic.is_expired())

    def test_invite_code_not_expired(self):
        u = User.objects.create_user(username='u8', password='test123456')
        p = Project.objects.create(owner=u, project_name='P')
        ic = InviteCode.objects.create(
            project=p, code='DEF456',
            expires_at=timezone.now() + timedelta(hours=1),
        )
        self.assertFalse(ic.is_expired())

    def test_invite_code_no_expiry(self):
        u = User.objects.create_user(username='u9', password='test123456')
        p = Project.objects.create(owner=u, project_name='P')
        ic = InviteCode.objects.create(project=p, code='GHI789', expires_at=None)
        self.assertFalse(ic.is_expired())

    def test_model_tier_limits_keys(self):
        for tier in ('free', 'personal', 'team', 'enterprise'):
            self.assertIn(tier, MODEL_TIER_LIMITS)
            cfg = MODEL_TIER_LIMITS[tier]
            for key in ('projects', 'documents', 'teams', 'members', 'collaborations', 'backups', 'audit', 'pending'):
                self.assertIn(key, cfg)

    def test_viewer_document_access_unique(self):
        u = User.objects.create_user(username='u10', password='test123456')
        p = Project.objects.create(owner=u, project_name='P')
        t = Teams.objects.create(project=p, team_name='T')
        d = Documents.objects.create(project=p, document_name='D', team_assigned=t)
        ViewerDocumentAccess.objects.create(project=p, document=d)
        with self.assertRaises(Exception):
            ViewerDocumentAccess.objects.create(project=p, document=d)

    def test_backup_ordering(self):
        u = User.objects.create_user(username='u11', password='test123456')
        p = Project.objects.create(owner=u, project_name='P')
        t = Teams.objects.create(project=p, team_name='T')
        d = Documents.objects.create(project=p, document_name='D', team_assigned=t)
        b1 = Backup.objects.create(project=p, document=d, r2_key='k1', version=1)
        b2 = Backup.objects.create(project=p, document=d, r2_key='k2', version=2)
        backups = list(Backup.objects.filter(project=p))
        self.assertEqual(backups[0].id, b2.id)

    def test_pending_action_ordering(self):
        u = User.objects.create_user(username='u12', password='test123456')
        p = Project.objects.create(owner=u, project_name='P')
        t = Teams.objects.create(project=p, team_name='T')
        d = Documents.objects.create(project=p, document_name='D', team_assigned=t)
        pa1 = PendingAction.objects.create(
            project=p, document=d, pending_user=u, actioned_by=u,
            action='accept', document_name='D',
        )
        pa2 = PendingAction.objects.create(
            project=p, document=d, pending_user=u, actioned_by=u,
            action='reject', document_name='D',
        )
        actions = list(PendingAction.objects.filter(project=p))
        self.assertEqual(actions[0].id, pa2.id)


# ---------------------------------------------------------------------------
# Auth / Login / Register
# ---------------------------------------------------------------------------
@override_settings(RATELIMIT_ENABLE=False)
class AuthTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='authuser', email='auth@test.com', password='pass123456',
        )

    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_login_get_renders(self, mock_render):
        r = self.client.get('/login/')
        self.assertEqual(r.status_code, 200)
        mock_render.assert_called_once()
        self.assertEqual(mock_render.call_args[0][1], 'login.html')

    def test_login_success(self):
        r = self.client.post('/login/', {
            'username': 'authuser', 'password': 'pass123456',
        })
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data['success'])
        self.assertIn('token', data)
        self.assertEqual(data['redirect'], '/dashboard/')

    def test_login_bad_password(self):
        r = self.client.post('/login/', {
            'username': 'authuser', 'password': 'wrong',
        })
        self.assertEqual(r.status_code, 401)

    def test_login_invalid_username_chars(self):
        r = self.client.post('/login/', {
            'username': 'bad user<script>', 'password': 'pass123456',
        })
        self.assertEqual(r.status_code, 401)

    def test_login_redirect_if_authenticated(self):
        self.client.force_login(self.user)
        r = self.client.get('/login/')
        self.assertEqual(r.status_code, 302)

    @patch('solaradocs.views.send_welcome_email')
    def test_register_success(self, mock_email):
        r = self.client.post('/register/', {
            'username': 'newuser', 'email': 'new@test.com',
            'password': 'pass123456', 'password_confirm': 'pass123456',
        })
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data['success'])
        self.assertTrue(User.objects.filter(username='newuser').exists())

    def test_register_short_password(self):
        r = self.client.post('/register/', {
            'username': 'newuser2', 'email': 'new2@test.com',
            'password': '12345', 'password_confirm': '12345',
        })
        self.assertEqual(r.status_code, 400)

    def test_register_duplicate_username(self):
        r = self.client.post('/register/', {
            'username': 'authuser', 'email': 'other@test.com',
            'password': 'pass123456', 'password_confirm': 'pass123456',
        })
        self.assertEqual(r.status_code, 400)
        self.assertIn('Username taken', r.json()['error'])

    def test_register_duplicate_email(self):
        r = self.client.post('/register/', {
            'username': 'other', 'email': 'auth@test.com',
            'password': 'pass123456', 'password_confirm': 'pass123456',
        })
        self.assertEqual(r.status_code, 400)
        self.assertIn('Email taken', r.json()['error'])

    def test_register_invalid_email(self):
        r = self.client.post('/register/', {
            'username': 'xyz', 'email': 'notanemail',
            'password': 'pass123456', 'password_confirm': 'pass123456',
        })
        self.assertEqual(r.status_code, 400)

    def test_register_short_username(self):
        r = self.client.post('/register/', {
            'username': 'ab', 'email': 'ab@test.com',
            'password': 'pass123456', 'password_confirm': 'pass123456',
        })
        self.assertEqual(r.status_code, 400)

    def test_logout(self):
        self.client.force_login(self.user)
        r = self.client.post('/logout/')
        self.assertEqual(r.status_code, 302)

    def test_get_oauth_token(self):
        self.client.force_login(self.user)
        r = self.client.get('/gen/token')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['success'])
        self.assertIn('token', r.json())

    def test_get_oauth_token_unauthenticated(self):
        r = self.client.get('/gen/token')
        self.assertEqual(r.status_code, 401)


# ---------------------------------------------------------------------------
# require_auth_token Decorator
# ---------------------------------------------------------------------------
@override_settings(RATELIMIT_ENABLE=False)
class AuthDecoratorTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='decuser', email='dec@test.com', password='pass123456',
        )
        self.project = Project.objects.create(
            owner=self.user, project_name='P', tier='free',
        )

    def test_get_without_login_redirects(self):
        r = self.client.get(f'/project/{self.project.id}/')
        self.assertEqual(r.status_code, 302)

    def test_post_without_token_returns_401(self):
        self.client.force_login(self.user)
        r = self.client.post(
            '/deleteproject/',
            json.dumps({'project_id': self.project.id}),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 401)

    def test_post_with_invalid_token(self):
        self.client.force_login(self.user)
        with patch('solaradocs.views.verify_auth_token', return_value='invalid'):
            r = self.client.post(
                '/deleteproject/',
                json.dumps({'project_id': self.project.id}),
                content_type='application/json',
                HTTP_AUTHORIZATION='Bearer bad-token',
            )
        self.assertEqual(r.status_code, 401)


# ---------------------------------------------------------------------------
# Project Setup + Management
# ---------------------------------------------------------------------------
class ProjectSetupTests(BaseTestCase):
    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_setup_get(self, mock_render):
        r = self._get('/setup/')
        self.assertEqual(r.status_code, 200)

    def test_setup_create_project(self):
        self.client.force_login(self.owner)
        with patch('solaradocs.views.verify_auth_token', return_value={'user_id': self.owner.id}):
            r = self.client.post('/setup/', {
                'project_name': 'New Project',
                'backups': 'false',
            }, HTTP_AUTHORIZATION='Bearer test-token')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['success'])
        self.assertTrue(Project.objects.filter(project_name='New Project').exists())

    def test_setup_creates_public_team_and_doc(self):
        self.client.force_login(self.owner)
        with patch('solaradocs.views.verify_auth_token', return_value={'user_id': self.owner.id}):
            self.client.post('/setup/', {
                'project_name': 'Proj2',
                'backups': 'false',
            }, HTTP_AUTHORIZATION='Bearer test-token')
        p = Project.objects.get(project_name='Proj2')
        self.assertTrue(Teams.objects.filter(project=p, team_name='Public').exists())
        self.assertTrue(Documents.objects.filter(project=p, document_name='Getting Started').exists())

    def test_setup_invalid_name(self):
        self.client.force_login(self.owner)
        with patch('solaradocs.views.verify_auth_token', return_value={'user_id': self.owner.id}):
            r = self.client.post('/setup/', {
                'project_name': '<script>',
                'backups': 'false',
            }, HTTP_AUTHORIZATION='Bearer test-token')
        self.assertEqual(r.status_code, 400)

    def test_setup_tier_project_limit(self):
        self.owner.Tier = 'free'
        self.owner.save()
        # views.py free tier allows 2 projects; owner already has 1 from BaseTestCase
        Project.objects.create(owner=self.owner, project_name='Extra', tier='free')
        self.client.force_login(self.owner)
        with patch('solaradocs.views.verify_auth_token', return_value={'user_id': self.owner.id}):
            r = self.client.post('/setup/', {
                'project_name': 'Third',
                'backups': 'false',
            }, HTTP_AUTHORIZATION='Bearer test-token')
        self.assertEqual(r.status_code, 403)

    def test_delete_project_owner(self):
        r = self._post(
            '/deleteproject/',
            {'project_id': self.project.id, 'confirm_name': self.project.project_name},
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['success'])
        self.assertFalse(Project.objects.filter(id=self.project.id).exists())

    def test_delete_project_non_owner(self):
        other = User.objects.create_user(username='other', password='pass123456')
        r = self._post('/deleteproject/', {'project_id': self.project.id}, user=other)
        self.assertEqual(r.status_code, 403)

    def test_delete_project_not_found(self):
        r = self._post('/deleteproject/', {'project_id': 99999})
        self.assertEqual(r.status_code, 404)

    def test_rename_project_owner(self):
        r = self._post(
            f'/api/project/{self.project.id}/rename',
            {'project_name': 'Renamed'},
        )
        self.assertEqual(r.status_code, 200)
        self.project.refresh_from_db()
        self.assertEqual(self.project.project_name, 'Renamed')

    def test_rename_project_non_owner(self):
        other = User.objects.create_user(username='other2', password='pass123456')
        r = self._post(
            f'/api/project/{self.project.id}/rename',
            {'project_name': 'Nope'},
            user=other,
        )
        self.assertEqual(r.status_code, 403)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
class DashboardTests(BaseTestCase):
    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_dashboard_authenticated(self, mock_render):
        r = self._get('/dashboard/')
        self.assertEqual(r.status_code, 200)

    def test_dashboard_unauthenticated(self):
        r = self.client.get('/dashboard/')
        self.assertEqual(r.status_code, 302)


# ---------------------------------------------------------------------------
# Document CRUD
# ---------------------------------------------------------------------------
class DocumentCRUDTests(BaseTestCase):
    def test_get_documents_owner(self):
        r = self._get(f'/api/project/{self.project.id}/documents')
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data['success'])
        self.assertEqual(len(data['documents']), 1)
        self.assertEqual(data['documents'][0]['document_name'], 'Test Doc')

    def test_get_documents_contributor_sees_public(self):
        contrib = self._make_contributor('contribuser', role='EDITOR')
        r = self._get(f'/api/project/{self.project.id}/documents', user=contrib)
        self.assertEqual(r.status_code, 200)
        docs = r.json()['documents']
        self.assertTrue(len(docs) >= 1)

    def test_get_documents_non_member_denied(self):
        stranger = User.objects.create_user(username='stranger', password='pass123456')
        r = self._get(f'/api/project/{self.project.id}/documents', user=stranger)
        self.assertEqual(r.status_code, 403)

    def test_get_single_document_owner(self):
        r = self._get(f'/api/project/{self.project.id}/documents/{self.doc.id}')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['document']['id'], self.doc.id)

    def test_get_single_document_not_found(self):
        r = self._get(f'/api/project/{self.project.id}/documents/99999')
        self.assertEqual(r.status_code, 404)

    def test_add_document_owner(self):
        r = self._post(
            f'/api/project/{self.project.id}/documents/add',
            {'document_name': 'New Doc', 'team_id': self.public_team.id},
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data['success'])
        self.assertEqual(data['document']['document_name'], 'New Doc')

    def test_add_document_missing_name(self):
        r = self._post(
            f'/api/project/{self.project.id}/documents/add',
            {'document_name': '', 'team_id': self.public_team.id},
        )
        self.assertEqual(r.status_code, 400)

    def test_add_document_invalid_team(self):
        r = self._post(
            f'/api/project/{self.project.id}/documents/add',
            {'document_name': 'X', 'team_id': 99999},
        )
        self.assertEqual(r.status_code, 404)

    def test_add_document_tier_limit(self):
        self.project.tier = 'free'
        self.project.save()
        # views.py free tier: documents=5; we already have 1, add 4 more to fill
        for i in range(4):
            Documents.objects.create(
                project=self.project, document_name=f'D{i}',
                team_assigned=self.public_team,
            )
        r = self._post(
            f'/api/project/{self.project.id}/documents/add',
            {'document_name': 'Overflow', 'team_id': self.public_team.id},
        )
        self.assertEqual(r.status_code, 403)

    def test_add_document_project_admin_contributor(self):
        admin = self._make_contributor('admincontrib', role='ADMIN')
        r = self._post(
            f'/api/project/{self.project.id}/documents/add',
            {'document_name': 'Admin Doc', 'team_id': self.public_team.id},
            user=admin,
        )
        self.assertEqual(r.status_code, 200)

    def test_add_document_team_admin(self):
        priv_team = Teams.objects.create(project=self.project, team_name='Private')
        editor = self._make_contributor('teamadmin1', role='EDITOR')
        self._make_team_member(editor, team=priv_team, role='ADMIN')
        r = self._post(
            f'/api/project/{self.project.id}/documents/add',
            {'document_name': 'Team Doc', 'team_id': priv_team.id},
            user=editor,
        )
        self.assertEqual(r.status_code, 200)

    def test_add_document_viewer_denied(self):
        viewer = self._make_contributor('viewer1', role='VIEWER')
        r = self._post(
            f'/api/project/{self.project.id}/documents/add',
            {'document_name': 'No', 'team_id': self.public_team.id},
            user=viewer,
        )
        self.assertEqual(r.status_code, 403)

    @patch('solaradocs.views.backup_document_to_r2')
    def test_save_document_owner_direct(self, mock_backup):
        r = self._post(
            f'/api/project/{self.project.id}/documents/{self.doc.id}/save',
            {'content': '<p>Updated</p>'},
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['success'])
        self.doc.refresh_from_db()
        self.assertEqual(self.doc.content, '<p>Updated</p>')

    @patch('solaradocs.views.backup_document_to_r2')
    def test_save_document_no_change(self, mock_backup):
        r = self._post(
            f'/api/project/{self.project.id}/documents/{self.doc.id}/save',
            {'content': self.doc.content},
        )
        self.assertEqual(r.status_code, 200)
        self.assertIn('No changes', r.json().get('message', ''))

    def test_save_document_missing_content(self):
        r = self._post(
            f'/api/project/{self.project.id}/documents/{self.doc.id}/save',
            {},
        )
        self.assertEqual(r.status_code, 400)

    @patch('solaradocs.views.backup_document_to_r2')
    def test_save_document_editor_on_public_direct(self, mock_backup):
        editor = self._make_contributor('editor1', role='EDITOR')
        r = self._post(
            f'/api/project/{self.project.id}/documents/{self.doc.id}/save',
            {'content': '<p>Editor edit</p>'},
            user=editor,
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['success'])
        self.assertNotIn('pending', r.json())

    def test_save_document_viewer_denied(self):
        viewer = self._make_contributor('viewer2', role='VIEWER')
        r = self._post(
            f'/api/project/{self.project.id}/documents/{self.doc.id}/save',
            {'content': '<p>Nope</p>'},
            user=viewer,
        )
        self.assertEqual(r.status_code, 403)

    @patch('solaradocs.views.backup_document_to_r2')
    def test_save_document_pending_flow(self, mock_backup):
        """Editor without can_direct_save on a team tier project creates pending."""
        priv_team = Teams.objects.create(project=self.project, team_name='Private')
        priv_doc = Documents.objects.create(
            project=self.project, document_name='Priv Doc',
            content='original', team_assigned=priv_team,
        )
        editor = self._make_contributor('peditor', role='EDITOR')
        self._make_team_member(editor, team=priv_team, role='EDITOR', can_direct_save=False)
        r = self._post(
            f'/api/project/{self.project.id}/documents/{priv_doc.id}/save',
            {'content': '<p>Proposed change</p>', 'note': 'Please review'},
            user=editor,
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json().get('pending'))
        self.assertTrue(Pending.objects.filter(document=priv_doc, user=editor).exists())

    @patch('solaradocs.views.backup_document_to_r2')
    def test_save_document_pending_requires_note(self, mock_backup):
        priv_team = Teams.objects.create(project=self.project, team_name='NoteTeam')
        priv_doc = Documents.objects.create(
            project=self.project, document_name='NoteDoc',
            content='orig', team_assigned=priv_team,
        )
        editor = self._make_contributor('neditor', role='EDITOR')
        self._make_team_member(editor, team=priv_team, role='EDITOR', can_direct_save=False)
        r = self._post(
            f'/api/project/{self.project.id}/documents/{priv_doc.id}/save',
            {'content': '<p>Change</p>'},
            user=editor,
        )
        self.assertEqual(r.status_code, 400)
        self.assertTrue(r.json().get('requires_note'))

    def test_rename_document_owner(self):
        r = self._post(
            f'/api/project/{self.project.id}/documents/{self.doc.id}/rename',
            {'document_name': 'Renamed Doc'},
        )
        self.assertEqual(r.status_code, 200)
        self.doc.refresh_from_db()
        self.assertEqual(self.doc.document_name, 'Renamed Doc')

    def test_rename_document_too_long(self):
        r = self._post(
            f'/api/project/{self.project.id}/documents/{self.doc.id}/rename',
            {'document_name': 'X' * 256},
        )
        self.assertEqual(r.status_code, 400)

    def test_delete_document_owner(self):
        r = self._post(
            f'/api/project/{self.project.id}/documents/{self.doc.id}/delete',
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Documents.objects.filter(id=self.doc.id).exists())

    def test_delete_document_non_admin_denied(self):
        editor = self._make_contributor('deleditor', role='EDITOR')
        r = self._post(
            f'/api/project/{self.project.id}/documents/{self.doc.id}/delete',
            user=editor,
        )
        self.assertEqual(r.status_code, 403)

    def test_delete_document_project_admin_allowed(self):
        admin = self._make_contributor('deladmin', role='ADMIN')
        r = self._post(
            f'/api/project/{self.project.id}/documents/{self.doc.id}/delete',
            user=admin,
        )
        self.assertEqual(r.status_code, 200)


# ---------------------------------------------------------------------------
# Team Management
# ---------------------------------------------------------------------------
class TeamTests(BaseTestCase):
    def test_get_teams_owner(self):
        r = self._get(f'/api/project/{self.project.id}/teams')
        self.assertEqual(r.status_code, 200)
        teams = r.json()['teams']
        self.assertTrue(len(teams) >= 1)

    def test_get_teams_contributor(self):
        contrib = self._make_contributor('teamcontrib', role='EDITOR')
        self._make_team_member(contrib, role='EDITOR')
        r = self._get(f'/api/project/{self.project.id}/teams', user=contrib)
        self.assertEqual(r.status_code, 200)

    def test_get_teams_non_member(self):
        stranger = User.objects.create_user(username='teamstranger', password='pass123456')
        r = self._get(f'/api/project/{self.project.id}/teams', user=stranger)
        self.assertEqual(r.status_code, 403)

    def test_create_team_owner(self):
        r = self._post(
            f'/api/project/{self.project.id}/teams/add',
            {'team_name': 'Engineering'},
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['team']['team_name'], 'Engineering')

    def test_create_team_non_owner(self):
        contrib = self._make_contributor('teamcreator', role='ADMIN')
        r = self._post(
            f'/api/project/{self.project.id}/teams/add',
            {'team_name': 'Nope'},
            user=contrib,
        )
        self.assertEqual(r.status_code, 403)

    def test_create_team_duplicate_name(self):
        r = self._post(
            f'/api/project/{self.project.id}/teams/add',
            {'team_name': 'Public'},
        )
        self.assertEqual(r.status_code, 400)

    def test_create_team_invalid_chars(self):
        r = self._post(
            f'/api/project/{self.project.id}/teams/add',
            {'team_name': '<script>'},
        )
        self.assertEqual(r.status_code, 400)

    def test_create_team_tier_limit(self):
        self.project.tier = 'free'
        self.project.save()
        # views.py free: teams=2; already have Public
        Teams.objects.create(project=self.project, team_name='Second')
        r = self._post(
            f'/api/project/{self.project.id}/teams/add',
            {'team_name': 'Third'},
        )
        self.assertEqual(r.status_code, 403)

    def test_update_team_name(self):
        team = Teams.objects.create(project=self.project, team_name='OldName')
        r = self._post(
            f'/api/project/{self.project.id}/teams/{team.id}/update',
            {'team_name': 'NewName'},
        )
        self.assertEqual(r.status_code, 200)
        team.refresh_from_db()
        self.assertEqual(team.team_name, 'NewName')

    def test_delete_team_owner(self):
        team = Teams.objects.create(project=self.project, team_name='ToDelete')
        r = self._post(f'/api/project/{self.project.id}/teams/{team.id}/delete')
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Teams.objects.filter(id=team.id).exists())

    def test_delete_team_not_found(self):
        r = self._post(f'/api/project/{self.project.id}/teams/99999/delete')
        self.assertEqual(r.status_code, 404)

    def test_add_team_member(self):
        contrib = self._make_contributor('tmember', role='EDITOR')
        team = Teams.objects.create(project=self.project, team_name='Dev')
        r = self._post(
            f'/api/project/{self.project.id}/teams/{team.id}/members/add',
            {'username': 'tmember', 'role': 'EDITOR'},
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(TeamMember.objects.filter(team=team, user=contrib).exists())

    def test_add_team_member_not_contributor(self):
        User.objects.create_user(username='notcontrib', password='pass123456')
        team = Teams.objects.create(project=self.project, team_name='Dev2')
        r = self._post(
            f'/api/project/{self.project.id}/teams/{team.id}/members/add',
            {'username': 'notcontrib', 'role': 'EDITOR'},
        )
        self.assertEqual(r.status_code, 400)

    def test_add_team_member_duplicate(self):
        contrib = self._make_contributor('dupmember', role='EDITOR')
        team = Teams.objects.create(project=self.project, team_name='Dev3')
        TeamMember.objects.create(team=team, user=contrib, role='EDITOR')
        r = self._post(
            f'/api/project/{self.project.id}/teams/{team.id}/members/add',
            {'username': 'dupmember', 'role': 'EDITOR'},
        )
        self.assertEqual(r.status_code, 400)

    def test_remove_team_member(self):
        contrib = self._make_contributor('rmember', role='EDITOR')
        team = Teams.objects.create(project=self.project, team_name='Dev4')
        TeamMember.objects.create(team=team, user=contrib, role='EDITOR')
        r = self._post(
            f'/api/project/{self.project.id}/teams/{team.id}/members/remove',
            {'username': 'rmember'},
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(TeamMember.objects.filter(team=team, user=contrib).exists())

    def test_update_team_member_role(self):
        contrib = self._make_contributor('rolemember', role='EDITOR')
        team = Teams.objects.create(project=self.project, team_name='Dev5')
        TeamMember.objects.create(team=team, user=contrib, role='EDITOR')
        r = self._post(
            f'/api/project/{self.project.id}/teams/{team.id}/members/role',
            {'username': 'rolemember', 'role': 'ADMIN'},
        )
        self.assertEqual(r.status_code, 200)
        m = TeamMember.objects.get(team=team, user=contrib)
        self.assertEqual(m.role, 'ADMIN')

    def test_update_team_member_review(self):
        contrib = self._make_contributor('reviewmember', role='EDITOR')
        team = Teams.objects.create(project=self.project, team_name='Dev6')
        TeamMember.objects.create(team=team, user=contrib, role='EDITOR')
        r = self._post(
            f'/api/project/{self.project.id}/teams/{team.id}/members/review',
            {'username': 'reviewmember', 'can_direct_save': True},
        )
        self.assertEqual(r.status_code, 200)
        m = TeamMember.objects.get(team=team, user=contrib)
        self.assertTrue(m.can_direct_save)


# ---------------------------------------------------------------------------
# Collaborators
# ---------------------------------------------------------------------------
class CollaboratorTests(BaseTestCase):
    def test_add_people_owner(self):
        User.objects.create_user(username='newperson', email='np@test.com', password='pass123456')
        r = self._post('/addpeople/', {
            'project_id': self.project.id,
            'usernames': 'newperson',
            'role': 'EDITOR',
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['added_count'], 1)

    def test_add_people_non_owner(self):
        other = User.objects.create_user(username='notowner', password='pass123456')
        r = self._post('/addpeople/', {
            'project_id': self.project.id,
            'usernames': 'notowner',
        }, user=other)
        self.assertEqual(r.status_code, 403)

    def test_add_people_user_not_found(self):
        r = self._post('/addpeople/', {
            'project_id': self.project.id,
            'usernames': 'nonexistent',
        })
        self.assertEqual(r.status_code, 404)

    def test_add_people_skip_existing(self):
        self._make_contributor('existing1', role='VIEWER')
        r = self._post('/addpeople/', {
            'project_id': self.project.id,
            'usernames': 'existing1',
            'role': 'EDITOR',
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['added_count'], 0)

    def test_change_roles_owner(self):
        contrib = self._make_contributor('rolechange', role='VIEWER')
        c = Contributor.objects.get(username='rolechange', project=self.project)
        r = self._post('/changeroles/', {
            'project_id': self.project.id,
            'contributor_id': c.id,
            'role': 'ADMIN',
        })
        self.assertEqual(r.status_code, 200)
        c.refresh_from_db()
        self.assertEqual(c.role, 'ADMIN')

    def test_change_roles_admin_cant_promote_to_admin(self):
        admin = self._make_contributor('adminrole', role='ADMIN')
        target = self._make_contributor('targetrole', role='VIEWER')
        c = Contributor.objects.get(username='targetrole', project=self.project)
        r = self._post('/changeroles/', {
            'project_id': self.project.id,
            'contributor_id': c.id,
            'role': 'ADMIN',
        }, user=admin)
        self.assertEqual(r.status_code, 403)

    def test_change_roles_admin_cant_change_other_admin(self):
        admin1 = self._make_contributor('admin1', role='ADMIN')
        self._make_contributor('admin2', role='ADMIN')
        c = Contributor.objects.get(username='admin2', project=self.project)
        r = self._post('/changeroles/', {
            'project_id': self.project.id,
            'contributor_id': c.id,
            'role': 'VIEWER',
        }, user=admin1)
        self.assertEqual(r.status_code, 403)

    def test_change_roles_invalid_role(self):
        self._make_contributor('badrole', role='VIEWER')
        c = Contributor.objects.get(username='badrole', project=self.project)
        r = self._post('/changeroles/', {
            'project_id': self.project.id,
            'contributor_id': c.id,
            'role': 'SUPERADMIN',
        })
        self.assertEqual(r.status_code, 400)

    def test_delete_contributor(self):
        self._make_contributor('todelete', role='VIEWER')
        c = Contributor.objects.get(username='todelete', project=self.project)
        r = self._post('/deleteuser/', {
            'project_id': self.project.id,
            'contributor_id': c.id,
        })
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Contributor.objects.filter(id=c.id).exists())

    def test_delete_contributor_non_owner(self):
        other = User.objects.create_user(username='notown', password='pass123456')
        self._make_contributor('delc', role='VIEWER')
        c = Contributor.objects.get(username='delc', project=self.project)
        r = self._post('/deleteuser/', {
            'project_id': self.project.id,
            'contributor_id': c.id,
        }, user=other)
        self.assertEqual(r.status_code, 403)

    def test_get_collaborators_owner(self):
        self._make_contributor('gcollaborator', role='EDITOR')
        r = self._get(f'/api/project/{self.project.id}/collaborators')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(len(r.json()['collaborators']) >= 1)

    def test_get_collaborators_admin(self):
        admin = self._make_contributor('gcadmin', role='ADMIN')
        r = self._get(f'/api/project/{self.project.id}/collaborators', user=admin)
        self.assertEqual(r.status_code, 200)

    def test_get_collaborators_non_admin_denied(self):
        editor = self._make_contributor('gceditor', role='EDITOR')
        r = self._get(f'/api/project/{self.project.id}/collaborators', user=editor)
        self.assertEqual(r.status_code, 403)


# ---------------------------------------------------------------------------
# Pending Edits
# ---------------------------------------------------------------------------
class PendingEditsTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.priv_team = Teams.objects.create(project=self.project, team_name='PrivTeam')
        self.priv_doc = Documents.objects.create(
            project=self.project, document_name='PrivDoc',
            content='<p>Original</p>', team_assigned=self.priv_team,
        )
        self.pending_editor = self._make_contributor('peditor2', role='EDITOR')
        self._make_team_member(
            self.pending_editor, team=self.priv_team,
            role='EDITOR', can_direct_save=False,
        )
        self.pending = Pending.objects.create(
            project=self.project, team=self.priv_team, document=self.priv_doc,
            user=self.pending_editor, submitted_content='<p>Proposed</p>',
            note='Check this',
        )

    @patch('solaradocs.views.backup_document_to_r2')
    def test_handle_pending_accept(self, mock_backup):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id,
            'action': 'accept',
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['action'], 'accept')
        self.priv_doc.refresh_from_db()
        self.assertEqual(self.priv_doc.content, '<p>Proposed</p>')
        self.assertFalse(Pending.objects.filter(id=self.pending.id).exists())
        self.assertTrue(PendingAction.objects.filter(
            project=self.project, action='accept',
        ).exists())

    def test_handle_pending_reject(self):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id,
            'action': 'reject',
            'reject_comment': 'Not aligned with the spec',
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['action'], 'reject')
        self.priv_doc.refresh_from_db()
        self.assertEqual(self.priv_doc.content, '<p>Original</p>')

    def test_handle_pending_invalid_action(self):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id,
            'action': 'maybe',
        })
        self.assertEqual(r.status_code, 400)

    def test_handle_pending_not_found(self):
        r = self._post('/handlepending/', {
            'pending_id': 99999,
            'action': 'accept',
        })
        self.assertEqual(r.status_code, 404)

    def test_handle_pending_team_admin(self):
        team_admin = self._make_contributor('tadmin', role='EDITOR')
        self._make_team_member(team_admin, team=self.priv_team, role='ADMIN')
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id,
            'action': 'reject',
            'reject_comment': 'Team admin rejection',
        }, user=team_admin)
        self.assertEqual(r.status_code, 200)

    def test_handle_pending_unauthorized(self):
        nobody = self._make_contributor('nobody', role='VIEWER')
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id,
            'action': 'accept',
        }, user=nobody)
        self.assertEqual(r.status_code, 403)

    def test_get_pending_edits_owner(self):
        r = self._get(f'/api/project/{self.project.id}/pending')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(len(r.json()['pending']) >= 1)

    def test_get_pending_edits_free_tier(self):
        self.project.tier = 'free'
        self.project.save()
        r = self._get(f'/api/project/{self.project.id}/pending')
        self.assertEqual(r.status_code, 403)

    def test_pending_diff(self):
        r = self._get(
            f'/api/project/{self.project.id}/pending/{self.pending.id}/diff',
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertIn('diff_html', data)
        self.assertEqual(data['document_name'], 'PrivDoc')


# ---------------------------------------------------------------------------
# Reject Comment (reviewer feedback on declined pending edits)
# ---------------------------------------------------------------------------
class RejectCommentTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.priv_team = Teams.objects.create(project=self.project, team_name='RCTeam')
        self.priv_doc = Documents.objects.create(
            project=self.project, document_name='RCDoc',
            content='<p>Original</p>', team_assigned=self.priv_team,
        )
        self.editor = self._make_contributor('rceditor', role='EDITOR')
        self._make_team_member(
            self.editor, team=self.priv_team,
            role='EDITOR', can_direct_save=False,
        )
        self.pending = Pending.objects.create(
            project=self.project, team=self.priv_team, document=self.priv_doc,
            user=self.editor, submitted_content='<p>Proposed</p>', note='Check',
        )

    # ---- reject validation ----
    def test_reject_missing_comment_returns_400(self):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'reject',
        })
        self.assertEqual(r.status_code, 400)
        self.assertIn("reason", r.json()['error'].lower())
        self.assertTrue(Pending.objects.filter(id=self.pending.id).exists())
        self.assertFalse(PendingAction.objects.filter(action='reject').exists())

    def test_reject_empty_comment_returns_400(self):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'reject',
            'reject_comment': '',
        })
        self.assertEqual(r.status_code, 400)
        self.assertTrue(Pending.objects.filter(id=self.pending.id).exists())

    def test_reject_whitespace_only_comment_returns_400(self):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'reject',
            'reject_comment': '   \t \n  ',
        })
        self.assertEqual(r.status_code, 400)
        self.assertTrue(Pending.objects.filter(id=self.pending.id).exists())

    def test_reject_non_string_comment_returns_400(self):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'reject',
            'reject_comment': 123,
        })
        self.assertEqual(r.status_code, 400)

    def test_reject_comment_over_255_chars_returns_400(self):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'reject',
            'reject_comment': 'x' * 256,
        })
        self.assertEqual(r.status_code, 400)

    def test_reject_comment_exactly_255_chars_allowed(self):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'reject',
            'reject_comment': 'x' * 255,
        })
        self.assertEqual(r.status_code, 200)
        pa = PendingAction.objects.get(action='reject')
        self.assertEqual(len(pa.reject_comment), 255)

    # ---- reject success path ----
    def test_reject_with_valid_comment_saves_it(self):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'reject',
            'reject_comment': 'Bad formatting',
        })
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['action'], 'reject')
        pa = PendingAction.objects.get(action='reject', pending_user=self.editor)
        self.assertEqual(pa.reject_comment, 'Bad formatting')
        self.assertFalse(Pending.objects.filter(id=self.pending.id).exists())

    def test_reject_strips_whitespace_around_comment(self):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'reject',
            'reject_comment': '  Needs more detail  \n',
        })
        self.assertEqual(r.status_code, 200)
        pa = PendingAction.objects.get(action='reject')
        self.assertEqual(pa.reject_comment, 'Needs more detail')

    def test_reject_preserves_original_document_content(self):
        self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'reject',
            'reject_comment': 'Incorrect data',
        })
        self.priv_doc.refresh_from_db()
        self.assertEqual(self.priv_doc.content, '<p>Original</p>')

    # ---- accept should not require or store comment ----
    @patch('solaradocs.views.backup_document_to_r2')
    def test_accept_does_not_require_comment(self, _mock):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'accept',
        })
        self.assertEqual(r.status_code, 200)
        pa = PendingAction.objects.get(action='accept')
        self.assertEqual(pa.reject_comment, '')

    @patch('solaradocs.views.backup_document_to_r2')
    def test_accept_ignores_comment_if_sent(self, _mock):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'accept',
            'reject_comment': 'should be ignored',
        })
        self.assertEqual(r.status_code, 200)
        pa = PendingAction.objects.get(action='accept')
        self.assertEqual(pa.reject_comment, '')

    # ---- get_pending_actions exposes reject_comment ----
    def test_get_pending_actions_includes_reject_comment(self):
        self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'reject',
            'reject_comment': 'Out of scope',
        })
        r = self._get(f'/api/project/{self.project.id}/pending-actions')
        self.assertEqual(r.status_code, 200)
        actions = r.json()['pending_actions']
        reject_entries = [a for a in actions if a['action'] == 'reject']
        self.assertTrue(len(reject_entries) >= 1)
        self.assertEqual(reject_entries[0]['reject_comment'], 'Out of scope')

    # ---- authorization is still enforced before comment validation ----
    def test_unauthorized_user_cannot_reject_even_with_comment(self):
        nobody = self._make_contributor('rcnobody', role='VIEWER')
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'reject',
            'reject_comment': 'nope',
        }, user=nobody)
        self.assertEqual(r.status_code, 403)
        self.assertTrue(Pending.objects.filter(id=self.pending.id).exists())

    # ---- rejected_content is captured on reject so editor can resubmit ----
    def test_reject_populates_rejected_content(self):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'reject',
            'reject_comment': 'Please revise',
        })
        self.assertEqual(r.status_code, 200)
        pa = PendingAction.objects.get(action='reject')
        self.assertEqual(pa.rejected_content, '<p>Proposed</p>')

    @patch('solaradocs.views.backup_document_to_r2')
    def test_accept_leaves_rejected_content_blank(self, _mock):
        r = self._post('/handlepending/', {
            'pending_id': self.pending.id, 'action': 'accept',
        })
        self.assertEqual(r.status_code, 200)
        pa = PendingAction.objects.get(action='accept')
        self.assertEqual(pa.rejected_content, '')


# ---------------------------------------------------------------------------
# My Rejection Feedback (editor-facing view of their declined edits)
# ---------------------------------------------------------------------------
class MyRejectionFeedbackTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.editor = self._make_contributor('mrfeditor', role='EDITOR')
        self.other_editor = self._make_contributor('mrfother', role='EDITOR')

    def _make_rejection(self, user, comment='Bad formatting', doc_name='Doc'):
        return PendingAction.objects.create(
            project=self.project, document=self.doc,
            pending_user=user, actioned_by=self.owner,
            action='reject', document_name=doc_name,
            reject_comment=comment,
        )

    def _make_acceptance(self, user, doc_name='Doc'):
        return PendingAction.objects.create(
            project=self.project, document=self.doc,
            pending_user=user, actioned_by=self.owner,
            action='accept', document_name=doc_name,
        )

    def test_returns_own_rejections_with_comment(self):
        self._make_rejection(self.editor, comment='Bad formatting', doc_name='MyDoc')
        r = self._get('/api/my-rejection-feedback', user=self.editor)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data['success'])
        self.assertEqual(len(data['rejections']), 1)
        item = data['rejections'][0]
        self.assertEqual(item['reject_comment'], 'Bad formatting')
        self.assertEqual(item['document_name'], 'MyDoc')
        self.assertEqual(item['actioned_by'], self.owner.username)
        self.assertEqual(item['project_name'], self.project.project_name)

    def test_empty_list_when_no_rejections(self):
        r = self._get('/api/my-rejection-feedback', user=self.editor)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['rejections'], [])

    def test_excludes_other_users_rejections(self):
        self._make_rejection(self.other_editor, comment='Not yours')
        r = self._get('/api/my-rejection-feedback', user=self.editor)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['rejections'], [])

    def test_excludes_accepted_actions(self):
        self._make_acceptance(self.editor)
        r = self._get('/api/my-rejection-feedback', user=self.editor)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['rejections'], [])

    def test_mixed_actions_returns_only_rejections(self):
        self._make_rejection(self.editor, comment='Reject 1', doc_name='D1')
        self._make_acceptance(self.editor, doc_name='D2')
        self._make_rejection(self.editor, comment='Reject 2', doc_name='D3')
        r = self._get('/api/my-rejection-feedback', user=self.editor)
        data = r.json()
        self.assertEqual(len(data['rejections']), 2)
        self.assertEqual({d['document_name'] for d in data['rejections']}, {'D1', 'D3'})

    def test_ordered_newest_first(self):
        old = self._make_rejection(self.editor, comment='Old', doc_name='Old')
        PendingAction.objects.filter(id=old.id).update(
            created_at=timezone.now() - timedelta(days=5),
        )
        self._make_rejection(self.editor, comment='New', doc_name='New')
        r = self._get('/api/my-rejection-feedback', user=self.editor)
        names = [item['document_name'] for item in r.json()['rejections']]
        self.assertEqual(names, ['New', 'Old'])

    def test_caps_at_20_results(self):
        for i in range(25):
            self._make_rejection(self.editor, comment=f'R{i}', doc_name=f'D{i}')
        r = self._get('/api/my-rejection-feedback', user=self.editor)
        self.assertEqual(len(r.json()['rejections']), 20)

    def test_includes_rejected_content_and_document_id(self):
        pa = PendingAction.objects.create(
            project=self.project, document=self.doc,
            pending_user=self.editor, actioned_by=self.owner,
            action='reject', document_name='Doc',
            reject_comment='Bad', rejected_content='<p>Old try</p>',
        )
        r = self._get('/api/my-rejection-feedback', user=self.editor)
        item = r.json()['rejections'][0]
        self.assertEqual(item['id'], pa.id)
        self.assertEqual(item['rejected_content'], '<p>Old try</p>')
        self.assertEqual(item['document_id'], self.doc.id)
        self.assertTrue(item['can_resubmit'])

    def test_can_resubmit_false_when_document_deleted(self):
        PendingAction.objects.create(
            project=self.project, document=None,
            pending_user=self.editor, actioned_by=self.owner,
            action='reject', document_name='GoneDoc',
            reject_comment='N/A', rejected_content='<p>orphan</p>',
        )
        r = self._get('/api/my-rejection-feedback', user=self.editor)
        item = r.json()['rejections'][0]
        self.assertFalse(item['can_resubmit'])
        self.assertIsNone(item['document_id'])


# ---------------------------------------------------------------------------
# Resubmit Pending (editor re-submits an edited version of a rejected edit)
# ---------------------------------------------------------------------------
class ResubmitPendingTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.priv_team = Teams.objects.create(project=self.project, team_name='RSTeam')
        self.priv_doc = Documents.objects.create(
            project=self.project, document_name='RSDoc',
            content='<p>Original</p>', team_assigned=self.priv_team,
        )
        self.editor = self._make_contributor('rseditor', role='EDITOR')
        self._make_team_member(
            self.editor, team=self.priv_team,
            role='EDITOR', can_direct_save=False,
        )
        self.rejection = PendingAction.objects.create(
            project=self.project, document=self.priv_doc,
            pending_user=self.editor, actioned_by=self.owner,
            action='reject', document_name='RSDoc',
            reject_comment='Fix formatting',
            rejected_content='<p>First try</p>',
        )

    def test_resubmit_creates_new_pending_with_content(self):
        r = self._post('/resubmit-pending/', {
            'pending_action_id': self.rejection.id,
            'content': '<p>Edited try</p>',
            'note': 'Fixed the formatting',
        }, user=self.editor)
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data['success'])
        new = Pending.objects.get(id=data['pending_id'])
        self.assertEqual(new.submitted_content, '<p>Edited try</p>')
        self.assertEqual(new.note, 'Fixed the formatting')
        self.assertEqual(new.user_id, self.editor.id)
        self.assertEqual(new.document_id, self.priv_doc.id)
        self.assertEqual(new.team_id, self.priv_team.id)
        self.assertEqual(new.project_id, self.project.id)

    def test_resubmit_does_not_modify_original_pending_action(self):
        original_reject_comment = self.rejection.reject_comment
        original_rejected_content = self.rejection.rejected_content
        original_action = self.rejection.action
        original_created_at = self.rejection.created_at

        r = self._post('/resubmit-pending/', {
            'pending_action_id': self.rejection.id,
            'content': '<p>New try</p>',
            'note': 'Redo',
        }, user=self.editor)
        self.assertEqual(r.status_code, 200)

        self.rejection.refresh_from_db()
        self.assertEqual(self.rejection.reject_comment, original_reject_comment)
        self.assertEqual(self.rejection.rejected_content, original_rejected_content)
        self.assertEqual(self.rejection.action, original_action)
        self.assertEqual(self.rejection.created_at, original_created_at)
        self.assertTrue(PendingAction.objects.filter(id=self.rejection.id).exists())

    def test_resubmit_blocked_for_other_user(self):
        intruder = self._make_contributor('rsintruder', role='EDITOR')
        r = self._post('/resubmit-pending/', {
            'pending_action_id': self.rejection.id,
            'content': '<p>Hijack</p>',
            'note': 'not mine',
        }, user=intruder)
        self.assertEqual(r.status_code, 403)
        self.assertFalse(Pending.objects.filter(submitted_content='<p>Hijack</p>').exists())

    def test_resubmit_blocked_for_accepted_action(self):
        acceptance = PendingAction.objects.create(
            project=self.project, document=self.priv_doc,
            pending_user=self.editor, actioned_by=self.owner,
            action='accept', document_name='RSDoc',
        )
        r = self._post('/resubmit-pending/', {
            'pending_action_id': acceptance.id,
            'content': '<p>Nope</p>',
            'note': 'should fail',
        }, user=self.editor)
        self.assertEqual(r.status_code, 400)
        self.assertFalse(Pending.objects.filter(submitted_content='<p>Nope</p>').exists())

    def test_resubmit_not_found(self):
        r = self._post('/resubmit-pending/', {
            'pending_action_id': 99999,
            'content': '<p>x</p>',
            'note': 'x',
        }, user=self.editor)
        self.assertEqual(r.status_code, 404)

    def test_resubmit_requires_note(self):
        r = self._post('/resubmit-pending/', {
            'pending_action_id': self.rejection.id,
            'content': '<p>x</p>',
            'note': '   ',
        }, user=self.editor)
        self.assertEqual(r.status_code, 400)

    def test_resubmit_rejects_missing_content(self):
        r = self._post('/resubmit-pending/', {
            'pending_action_id': self.rejection.id,
            'note': 'redo',
        }, user=self.editor)
        self.assertEqual(r.status_code, 400)

    def test_resubmit_rejects_note_over_500_chars(self):
        r = self._post('/resubmit-pending/', {
            'pending_action_id': self.rejection.id,
            'content': '<p>x</p>',
            'note': 'x' * 501,
        }, user=self.editor)
        self.assertEqual(r.status_code, 400)

    def test_resubmit_document_deleted_returns_404(self):
        orphan = PendingAction.objects.create(
            project=self.project, document=None,
            pending_user=self.editor, actioned_by=self.owner,
            action='reject', document_name='Gone',
            reject_comment='x', rejected_content='<p>gone</p>',
        )
        r = self._post('/resubmit-pending/', {
            'pending_action_id': orphan.id,
            'content': '<p>x</p>',
            'note': 'redo',
        }, user=self.editor)
        self.assertEqual(r.status_code, 404)

    def test_resubmit_invalid_pending_action_id(self):
        r = self._post('/resubmit-pending/', {
            'pending_action_id': 'abc',
            'content': '<p>x</p>',
            'note': 'redo',
        }, user=self.editor)
        self.assertEqual(r.status_code, 400)


# ---------------------------------------------------------------------------
# Audits
# ---------------------------------------------------------------------------
class AuditTests(BaseTestCase):
    def test_get_audits_team_tier(self):
        Audit.objects.create(
            project=self.project, document=self.doc,
            user=self.owner, action='edit',
        )
        r = self._get(f'/api/project/{self.project.id}/audits')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(len(r.json()['audits']) >= 1)

    def test_get_audits_free_tier_denied(self):
        self.project.tier = 'free'
        self.project.save()
        r = self._get(f'/api/project/{self.project.id}/audits')
        self.assertEqual(r.status_code, 403)

    def test_get_pending_actions(self):
        PendingAction.objects.create(
            project=self.project, document=self.doc,
            pending_user=self.owner, actioned_by=self.owner,
            action='accept', document_name='Test Doc',
        )
        r = self._get(f'/api/project/{self.project.id}/pending-actions')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(len(r.json()['pending_actions']) >= 1)


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------
class BackupTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.backup = Backup.objects.create(
            project=self.project, document=self.doc,
            r2_key='test/key.json', version=1, size_bytes=100,
        )

    def test_list_backups_owner(self):
        r = self._get(f'/api/project/{self.project.id}/backups')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(len(r.json()['backups']) >= 1)

    def test_list_backups_free_tier(self):
        self.project.tier = 'free'
        self.project.save()
        r = self._get(f'/api/project/{self.project.id}/backups')
        self.assertEqual(r.status_code, 403)

    def test_list_backups_disabled(self):
        self.project.backups_enabled = False
        self.project.save()
        r = self._get(f'/api/project/{self.project.id}/backups')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json().get('disabled'))

    def test_list_backups_team_admin(self):
        team_admin = self._make_contributor('backupadmin', role='EDITOR')
        self._make_team_member(team_admin, role='ADMIN')
        r = self._get(f'/api/project/{self.project.id}/backups', user=team_admin)
        self.assertEqual(r.status_code, 200)

    def test_list_backups_no_access(self):
        viewer = self._make_contributor('backupviewer', role='VIEWER')
        r = self._get(f'/api/project/{self.project.id}/backups', user=viewer)
        self.assertEqual(r.status_code, 403)

    def test_toggle_backups_on(self):
        self.project.backups_enabled = False
        self.project.save()
        r = self._post(
            f'/api/project/{self.project.id}/toggle-backups',
            {'enabled': True},
        )
        self.assertEqual(r.status_code, 200)
        self.project.refresh_from_db()
        self.assertTrue(self.project.backups_enabled)

    def test_toggle_backups_off(self):
        r = self._post(
            f'/api/project/{self.project.id}/toggle-backups',
            {'enabled': False},
        )
        self.assertEqual(r.status_code, 200)
        self.project.refresh_from_db()
        self.assertFalse(self.project.backups_enabled)

    def test_toggle_backups_non_owner(self):
        other = self._make_contributor('toggleother', role='ADMIN')
        r = self._post(
            f'/api/project/{self.project.id}/toggle-backups',
            {'enabled': False},
            user=other,
        )
        self.assertEqual(r.status_code, 403)

    @patch('solaradocs.views.restore_document_from_backup')
    def test_revert_backup_owner(self, mock_restore):
        r = self._post(
            f'/api/project/{self.project.id}/backups/{self.backup.id}/revert',
        )
        self.assertEqual(r.status_code, 200)
        mock_restore.assert_called_once_with(self.backup.id)

    @patch('solaradocs.views.settings')
    def test_backup_diff(self, mock_settings):
        mock_r2 = MagicMock()
        mock_r2.get_object.return_value = {
            'Body': MagicMock(
                read=MagicMock(return_value=json.dumps({'content': 'old backup content'}).encode())
            ),
        }
        mock_settings.R2_CLIENT = mock_r2
        mock_settings.R2_BUCKET_NAME = 'test-bucket'
        r = self._get(
            f'/api/project/{self.project.id}/backups/{self.backup.id}/diff',
        )
        self.assertEqual(r.status_code, 200)
        self.assertIn('diff_html', r.json())


# ---------------------------------------------------------------------------
# Viewer Access
# ---------------------------------------------------------------------------
class ViewerAccessTests(BaseTestCase):
    def test_get_viewer_access_owner(self):
        r = self._get(f'/api/project/{self.project.id}/viewer-access')
        self.assertEqual(r.status_code, 200)
        self.assertIn('document_ids', r.json())

    def test_get_viewer_access_non_owner(self):
        other = self._make_contributor('vieweraccess', role='ADMIN')
        r = self._get(f'/api/project/{self.project.id}/viewer-access', user=other)
        self.assertEqual(r.status_code, 403)

    def test_save_viewer_access(self):
        r = self._post(
            f'/api/project/{self.project.id}/viewer-access/save',
            {'document_ids': [self.doc.id]},
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['count'], 1)
        self.assertTrue(
            ViewerDocumentAccess.objects.filter(
                project=self.project, document=self.doc
            ).exists()
        )

    def test_save_viewer_access_invalid_doc(self):
        r = self._post(
            f'/api/project/{self.project.id}/viewer-access/save',
            {'document_ids': [99999]},
        )
        self.assertEqual(r.status_code, 400)

    def test_save_viewer_access_replaces(self):
        ViewerDocumentAccess.objects.create(project=self.project, document=self.doc)
        doc2 = Documents.objects.create(
            project=self.project, document_name='Doc2',
            team_assigned=self.public_team,
        )
        r = self._post(
            f'/api/project/{self.project.id}/viewer-access/save',
            {'document_ids': [doc2.id]},
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(
            ViewerDocumentAccess.objects.filter(document=self.doc).exists()
        )
        self.assertTrue(
            ViewerDocumentAccess.objects.filter(document=doc2).exists()
        )

    def test_get_viewer_documents(self):
        viewer = self._make_contributor('viewerdocs', role='VIEWER')
        ViewerDocumentAccess.objects.create(project=self.project, document=self.doc)
        r = self._get(
            f'/api/project/{self.project.id}/viewer-documents',
            user=viewer,
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()['documents']), 1)

    def test_get_viewer_documents_non_viewer(self):
        editor = self._make_contributor('editordocs', role='EDITOR')
        r = self._get(
            f'/api/project/{self.project.id}/viewer-documents',
            user=editor,
        )
        self.assertEqual(r.status_code, 403)

    def test_get_viewer_document_content(self):
        viewer = self._make_contributor('viewercontent', role='VIEWER')
        ViewerDocumentAccess.objects.create(project=self.project, document=self.doc)
        r = self._get(
            f'/api/project/{self.project.id}/viewer-document/{self.doc.id}/content',
            user=viewer,
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['document']['id'], self.doc.id)

    def test_get_viewer_document_content_no_access(self):
        viewer = self._make_contributor('viewernoacc', role='VIEWER')
        r = self._get(
            f'/api/project/{self.project.id}/viewer-document/{self.doc.id}/content',
            user=viewer,
        )
        self.assertEqual(r.status_code, 403)


# ---------------------------------------------------------------------------
# Invite Codes
# ---------------------------------------------------------------------------
class InviteCodeTests(BaseTestCase):
    def test_generate_invite_code(self):
        r = self._post(
            f'/api/project/{self.project.id}/invite-code/generate',
            {'role': 'EDITOR', 'expiry': '24h'},
        )
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data['success'])
        self.assertEqual(len(data['code']), 6)
        self.assertEqual(data['role'], 'EDITOR')

    def test_generate_invite_code_non_owner(self):
        other = self._make_contributor('invother', role='ADMIN')
        r = self._post(
            f'/api/project/{self.project.id}/invite-code/generate',
            {'role': 'EDITOR', 'expiry': 'never'},
            user=other,
        )
        self.assertEqual(r.status_code, 403)

    def test_generate_invite_code_invalid_role(self):
        r = self._post(
            f'/api/project/{self.project.id}/invite-code/generate',
            {'role': 'SUPERUSER', 'expiry': 'never'},
        )
        self.assertEqual(r.status_code, 400)

    def test_generate_invite_code_invalid_expiry(self):
        r = self._post(
            f'/api/project/{self.project.id}/invite-code/generate',
            {'role': 'EDITOR', 'expiry': '999h'},
        )
        self.assertEqual(r.status_code, 400)

    def test_list_invite_codes(self):
        InviteCode.objects.create(
            project=self.project, code='ABC123', role='EDITOR',
        )
        r = self._get(f'/api/project/{self.project.id}/invite-codes')
        self.assertEqual(r.status_code, 200)
        self.assertTrue(len(r.json()['invite_codes']) >= 1)

    def test_list_invite_codes_cleans_expired(self):
        InviteCode.objects.create(
            project=self.project, code='EXP123', role='EDITOR',
            expires_at=timezone.now() - timedelta(hours=1),
        )
        r = self._get(f'/api/project/{self.project.id}/invite-codes')
        self.assertEqual(r.status_code, 200)
        codes = [c['code'] for c in r.json()['invite_codes']]
        self.assertNotIn('EXP123', codes)
        self.assertFalse(InviteCode.objects.filter(code='EXP123').exists())

    def test_delete_invite_code(self):
        ic = InviteCode.objects.create(
            project=self.project, code='DEL123', role='EDITOR',
        )
        r = self._post(
            f'/api/project/{self.project.id}/invite-code/{ic.id}/delete',
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(InviteCode.objects.filter(id=ic.id).exists())

    def test_redeem_invite_code(self):
        ic = InviteCode.objects.create(
            project=self.project, code='RED123', role='EDITOR',
        )
        redeemer = User.objects.create_user(
            username='redeemer', password='pass123456',
        )
        r = self._post(
            '/api/invite-code/redeem',
            {'code': 'RED123'},
            user=redeemer,
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(
            Contributor.objects.filter(
                project=self.project, username='redeemer', role='EDITOR',
            ).exists()
        )

    def test_redeem_invite_code_owner_rejected(self):
        ic = InviteCode.objects.create(
            project=self.project, code='OWN123', role='EDITOR',
        )
        r = self._post('/api/invite-code/redeem', {'code': 'OWN123'})
        self.assertEqual(r.status_code, 400)

    def test_redeem_invite_code_already_collaborator(self):
        ic = InviteCode.objects.create(
            project=self.project, code='DUP123', role='EDITOR',
        )
        existing = self._make_contributor('dupredeem', role='VIEWER')
        r = self._post(
            '/api/invite-code/redeem',
            {'code': 'DUP123'},
            user=existing,
        )
        self.assertEqual(r.status_code, 409)

    def test_redeem_expired_code(self):
        InviteCode.objects.create(
            project=self.project, code='EXR123', role='EDITOR',
            expires_at=timezone.now() - timedelta(hours=1),
        )
        redeemer = User.objects.create_user(
            username='lateredeemer', password='pass123456',
        )
        r = self._post(
            '/api/invite-code/redeem',
            {'code': 'EXR123'},
            user=redeemer,
        )
        self.assertEqual(r.status_code, 410)

    def test_redeem_invalid_code(self):
        redeemer = User.objects.create_user(
            username='badredeemer', password='pass123456',
        )
        r = self._post(
            '/api/invite-code/redeem',
            {'code': 'ZZZZZZ'},
            user=redeemer,
        )
        self.assertEqual(r.status_code, 404)


# ---------------------------------------------------------------------------
# Promo Codes
# ---------------------------------------------------------------------------
class PromoCodeTests(BaseTestCase):
    def test_redeem_promo_success(self):
        PromoCodes.objects.create(code='PROMO123', tier='personal', left_uses=10)
        self.client.force_login(self.owner)
        r = self.client.post(
            '/redeem-promo/',
            json.dumps({'code': 'PROMO123'}),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['tier'], 'personal')
        self.owner.refresh_from_db()
        self.assertEqual(self.owner.Tier, 'personal')
        self.assertTrue(self.owner.promo)

    def test_redeem_promo_already_used(self):
        PromoCodes.objects.create(code='PROMO2', tier='personal', left_uses=10)
        self.owner.promo = True
        self.owner.save()
        self.client.force_login(self.owner)
        r = self.client.post(
            '/redeem-promo/',
            json.dumps({'code': 'PROMO2'}),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 400)

    def test_redeem_promo_no_uses_left(self):
        PromoCodes.objects.create(code='PROMO3', tier='personal', left_uses=0)
        self.client.force_login(self.owner)
        r = self.client.post(
            '/redeem-promo/',
            json.dumps({'code': 'PROMO3'}),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 400)

    def test_redeem_promo_expired(self):
        PromoCodes.objects.create(
            code='PROMO4', tier='personal', left_uses=10,
            expires_at=timezone.now() - timedelta(days=1),
        )
        self.client.force_login(self.owner)
        r = self.client.post(
            '/redeem-promo/',
            json.dumps({'code': 'PROMO4'}),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 400)

    def test_redeem_promo_invalid_code(self):
        self.client.force_login(self.owner)
        r = self.client.post(
            '/redeem-promo/',
            json.dumps({'code': 'NOPE'}),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 404)


# ---------------------------------------------------------------------------
# Password Reset
# ---------------------------------------------------------------------------
@override_settings(
    RATELIMIT_ENABLE=False,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class PasswordResetTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username='resetuser', email='reset@test.com', password='pass123456',
        )

    @patch('solaradocs.views.send_password_reset_email')
    def test_password_reset_send(self, mock_email):
        r = self.client.post(
            '/password-reset/send',
            json.dumps({'email': 'reset@test.com'}),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['success'])

    @patch('solaradocs.views.send_password_reset_email')
    def test_password_reset_send_unknown_email(self, mock_email):
        r = self.client.post(
            '/password-reset/send',
            json.dumps({'email': 'nobody@test.com'}),
            content_type='application/json',
        )
        # returns success even for unknown emails (security)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['success'])

    @patch('solaradocs.views.send_password_reset_email')
    def test_password_reset_full_flow(self, mock_email):
        # Step 1: Send code
        self.client.post(
            '/password-reset/send',
            json.dumps({'email': 'reset@test.com'}),
            content_type='application/json',
        )
        code = cache.get('pw_reset_code:reset@test.com')
        self.assertIsNotNone(code)

        # Step 2: Verify code
        r = self.client.post(
            '/password-reset/verify',
            json.dumps({'email': 'reset@test.com', 'code': code}),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 200)
        token = r.json()['token']
        self.assertIsNotNone(token)

        # Step 3: Confirm reset
        r = self.client.post(
            '/password-reset/confirm',
            json.dumps({
                'email': 'reset@test.com',
                'token': token,
                'new_password': 'newpass789',
            }),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['success'])

        # Verify new password works
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpass789'))

    def test_password_reset_verify_wrong_code(self):
        cache.set('pw_reset_code:reset@test.com', '123456', timeout=900)
        cache.set('pw_reset_attempts:reset@test.com', 0, timeout=900)
        r = self.client.post(
            '/password-reset/verify',
            json.dumps({'email': 'reset@test.com', 'code': '000000'}),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 400)

    def test_password_reset_verify_too_many_attempts(self):
        cache.set('pw_reset_code:reset@test.com', '123456', timeout=900)
        cache.set('pw_reset_attempts:reset@test.com', 5, timeout=900)
        r = self.client.post(
            '/password-reset/verify',
            json.dumps({'email': 'reset@test.com', 'code': '123456'}),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn('Too many attempts', r.json()['error'])

    def test_password_reset_confirm_bad_token(self):
        r = self.client.post(
            '/password-reset/confirm',
            json.dumps({
                'email': 'reset@test.com',
                'token': 'bad-token',
                'new_password': 'newpass789',
            }),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 400)

    def test_password_reset_confirm_short_password(self):
        cache.set('pw_reset_token:reset@test.com', 'valid-token', timeout=600)
        r = self.client.post(
            '/password-reset/confirm',
            json.dumps({
                'email': 'reset@test.com',
                'token': 'valid-token',
                'new_password': '123',
            }),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 400)


# ---------------------------------------------------------------------------
# Change Password
# ---------------------------------------------------------------------------
@override_settings(RATELIMIT_ENABLE=False)
class ChangePasswordTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='pwuser', email='pw@test.com', password='oldpass123',
        )

    def test_change_password_success(self):
        self.client.force_login(self.user)
        r = self.client.post(
            '/change-password/',
            json.dumps({
                'current_password': 'oldpass123',
                'new_password': 'newpass456',
            }),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpass456'))

    def test_change_password_wrong_current(self):
        self.client.force_login(self.user)
        r = self.client.post(
            '/change-password/',
            json.dumps({
                'current_password': 'wrong',
                'new_password': 'newpass456',
            }),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 400)

    def test_change_password_too_short(self):
        self.client.force_login(self.user)
        r = self.client.post(
            '/change-password/',
            json.dumps({
                'current_password': 'oldpass123',
                'new_password': '123',
            }),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 400)


# ---------------------------------------------------------------------------
# Google Import Views
# ---------------------------------------------------------------------------
class GoogleImportViewTests(BaseTestCase):
    def test_check_google_auth_authenticated(self):
        with patch('solaradocs.views_import.get_google_credentials', return_value=MagicMock()):
            r = self._get(f'/api/project/{self.project.id}/google/check-auth')
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data['authenticated'])
        self.assertIsNone(data['reauth_url'])

    def test_check_google_auth_not_authenticated(self):
        with patch('solaradocs.views_import.get_google_credentials', return_value=None):
            r = self._get(f'/api/project/{self.project.id}/google/check-auth')
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertFalse(data['authenticated'])
        self.assertIsNotNone(data['reauth_url'])

    def test_check_google_auth_non_admin(self):
        viewer = self._make_contributor('gviewer', role='VIEWER')
        with patch('solaradocs.views_import.get_google_credentials', return_value=None):
            r = self._get(
                f'/api/project/{self.project.id}/google/check-auth',
                user=viewer,
            )
        self.assertEqual(r.status_code, 403)

    def test_list_google_docs(self):
        mock_docs = [
            {'id': 'doc1', 'name': 'My Doc', 'modifiedTime': '2024-01-01T00:00:00Z'},
        ]
        with patch('solaradocs.views_import.list_user_google_docs', return_value=mock_docs):
            r = self._get(f'/api/project/{self.project.id}/google/docs')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.json()['docs']), 1)
        self.assertEqual(r.json()['docs'][0]['id'], 'doc1')

    def test_list_google_docs_failure(self):
        with patch('solaradocs.views_import.list_user_google_docs', return_value=None):
            r = self._get(f'/api/project/{self.project.id}/google/docs')
        self.assertEqual(r.status_code, 401)

    @patch('solaradocs.views_import.import_google_docs_task')
    def test_start_import(self, mock_task):
        r = self._post(
            f'/api/project/{self.project.id}/google/import',
            {
                'doc_ids': ['doc1', 'doc2'],
                'doc_titles': {'doc1': 'First', 'doc2': 'Second'},
                'team_id': self.public_team.id,
            },
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.json()['job_started'])
        mock_task.delay.assert_called_once()

    def test_start_import_no_docs(self):
        r = self._post(
            f'/api/project/{self.project.id}/google/import',
            {'doc_ids': [], 'team_id': self.public_team.id},
        )
        self.assertEqual(r.status_code, 400)

    def test_start_import_too_many_docs(self):
        r = self._post(
            f'/api/project/{self.project.id}/google/import',
            {
                'doc_ids': [f'doc{i}' for i in range(51)],
                'team_id': self.public_team.id,
            },
        )
        self.assertEqual(r.status_code, 400)

    def test_start_import_invalid_team(self):
        r = self._post(
            f'/api/project/{self.project.id}/google/import',
            {'doc_ids': ['doc1'], 'team_id': 99999},
        )
        self.assertEqual(r.status_code, 404)

    @patch('solaradocs.views_import.import_google_docs_task')
    def test_start_import_tier_limit(self, mock_task):
        self.project.tier = 'free'
        self.project.save()
        # models.py free tier: documents=5; we have 1 doc already from setUp
        for i in range(2, 6):
            Documents.objects.create(
                project=self.project, document_name=f'D{i}',
                team_assigned=self.public_team,
            )
        r = self._post(
            f'/api/project/{self.project.id}/google/import',
            {'doc_ids': ['doc1'], 'team_id': self.public_team.id},
        )
        self.assertEqual(r.status_code, 403)

    @patch('solaradocs.views_import.get_import_job_status')
    def test_import_status(self, mock_status):
        mock_status.return_value = {
            'docs': [
                {'doc_id': 'd1', 'title': 'Doc1', 'state': 'done', 'reason': ''},
            ],
            'all_done': True,
            'has_failures': False,
        }
        r = self._get(f'/api/project/{self.project.id}/google/import/status')
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data['has_job'])
        self.assertTrue(data['all_done'])

    @patch('solaradocs.views_import.get_import_job_status')
    def test_import_status_no_job(self, mock_status):
        mock_status.return_value = None
        r = self._get(f'/api/project/{self.project.id}/google/import/status')
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json()['has_job'])

    @patch('solaradocs.views_import.import_google_docs_task')
    @patch('solaradocs.views_import.get_import_job')
    @patch('solaradocs.views_import.get_import_state')
    def test_retry_import(self, mock_state, mock_job, mock_task):
        mock_job.return_value = [
            {'id': 'd1', 'title': 'Doc1'},
            {'id': 'd2', 'title': 'Doc2'},
        ]
        mock_state.side_effect = [('failed', 'err'), ('done', '')]
        r = self._post(
            f'/api/project/{self.project.id}/google/import/retry',
            {'team_id': self.public_team.id},
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['retrying'], 1)
        mock_task.delay.assert_called_once()


# ---------------------------------------------------------------------------
# Google Import Celery Task
# ---------------------------------------------------------------------------
@override_settings(
    RATELIMIT_ENABLE=False,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class GoogleImportTaskTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username='importuser', email='import@test.com', password='pass123456',
        )
        self.project = Project.objects.create(
            owner=self.user, project_name='ImportProject', tier='team',
        )
        self.team = Teams.objects.create(project=self.project, team_name='Public')

    @patch('solaradocs.google_import.fetch_google_doc_text')
    @patch('solaradocs.google_import.get_google_credentials')
    def test_import_single_doc(self, mock_creds, mock_fetch):
        mock_creds.return_value = MagicMock()
        mock_fetch.return_value = ('My Google Doc', 'Hello from Google Docs')

        from solaradocs.google_import import import_google_docs_task
        import_google_docs_task(
            self.user.id, self.project.id, self.team.id, ['gdoc123'],
        )

        doc = Documents.objects.get(google_doc_id='gdoc123')
        self.assertEqual(doc.document_name, 'My Google Doc')
        self.assertEqual(doc.content, 'Hello from Google Docs')
        self.assertEqual(doc.project_id, self.project.id)
        self.assertEqual(doc.team_assigned_id, self.team.id)

    @patch('solaradocs.google_import.fetch_google_doc_text')
    @patch('solaradocs.google_import.get_google_credentials')
    def test_import_idempotency(self, mock_creds, mock_fetch):
        mock_creds.return_value = MagicMock()
        mock_fetch.return_value = ('Doc Title', 'Content v2')

        # Pre-existing doc with same google_doc_id
        Documents.objects.create(
            project=self.project, document_name='Old Title',
            content='Content v1', team_assigned=self.team,
            google_doc_id='gdocdup',
        )

        from solaradocs.google_import import import_google_docs_task
        import_google_docs_task(
            self.user.id, self.project.id, self.team.id, ['gdocdup'],
        )

        docs = Documents.objects.filter(google_doc_id='gdocdup')
        self.assertEqual(docs.count(), 1)
        self.assertEqual(docs.first().content, 'Content v2')

    @patch('solaradocs.google_import.fetch_google_doc_text')
    @patch('solaradocs.google_import.get_google_credentials')
    def test_import_multiple_docs(self, mock_creds, mock_fetch):
        mock_creds.return_value = MagicMock()
        mock_fetch.side_effect = [
            ('Doc A', 'Content A'),
            ('Doc B', 'Content B'),
        ]

        from solaradocs.google_import import import_google_docs_task
        import_google_docs_task(
            self.user.id, self.project.id, self.team.id,
            ['gdocA', 'gdocB'],
        )

        self.assertTrue(Documents.objects.filter(google_doc_id='gdocA').exists())
        self.assertTrue(Documents.objects.filter(google_doc_id='gdocB').exists())

    @patch('solaradocs.google_import.get_google_credentials')
    def test_import_no_credentials(self, mock_creds):
        mock_creds.return_value = None

        from solaradocs.google_import import (
            import_google_docs_task, get_import_state,
        )
        import_google_docs_task(
            self.user.id, self.project.id, self.team.id, ['gdocfail'],
        )

        state, reason = get_import_state(self.project.id, 'gdocfail')
        self.assertEqual(state, 'failed')
        self.assertIn('authentication', reason)

    @patch('solaradocs.google_import.fetch_google_doc_text')
    @patch('solaradocs.google_import.get_google_credentials')
    def test_import_fetch_failure(self, mock_creds, mock_fetch):
        mock_creds.return_value = MagicMock()
        mock_fetch.return_value = None

        from solaradocs.google_import import (
            import_google_docs_task, get_import_state,
        )
        import_google_docs_task(
            self.user.id, self.project.id, self.team.id, ['gdocnull'],
        )

        state, reason = get_import_state(self.project.id, 'gdocnull')
        self.assertEqual(state, 'failed')

    @patch('solaradocs.google_import.fetch_google_doc_text')
    @patch('solaradocs.google_import.get_google_credentials')
    def test_import_tier_limit_stops_remaining(self, mock_creds, mock_fetch):
        mock_creds.return_value = MagicMock()
        mock_fetch.return_value = ('Title', 'Content')

        # Set to free tier (models.py: documents=5) and fill up
        self.project.tier = 'free'
        self.project.save()
        for i in range(1, 6):
            Documents.objects.create(
                project=self.project, document_name=f'Existing{i}',
                team_assigned=self.team,
            )

        from solaradocs.google_import import (
            import_google_docs_task, get_import_state,
        )
        import_google_docs_task(
            self.user.id, self.project.id, self.team.id,
            ['gdoclimit1', 'gdoclimit2'],
        )

        state1, reason1 = get_import_state(self.project.id, 'gdoclimit1')
        state2, reason2 = get_import_state(self.project.id, 'gdoclimit2')
        self.assertEqual(state1, 'failed')
        self.assertIn('limit', reason1)
        self.assertEqual(state2, 'failed')

    @patch('solaradocs.google_import.fetch_google_doc_text')
    @patch('solaradocs.google_import.get_google_credentials')
    def test_import_creates_audit_for_team_tier(self, mock_creds, mock_fetch):
        mock_creds.return_value = MagicMock()
        mock_fetch.return_value = ('Audit Doc', 'Content')

        from solaradocs.google_import import import_google_docs_task
        import_google_docs_task(
            self.user.id, self.project.id, self.team.id, ['gdocaudit'],
        )

        self.assertTrue(
            Audit.objects.filter(
                project=self.project, action='import',
            ).exists()
        )

    def test_import_user_not_found(self):
        from solaradocs.google_import import import_google_docs_task
        import_google_docs_task(99999, self.project.id, self.team.id, ['gdocx'])
        # should not raise, just log and return


# ---------------------------------------------------------------------------
# Google Import Helpers
# ---------------------------------------------------------------------------
@override_settings(
    RATELIMIT_ENABLE=False,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class GoogleImportHelperTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_set_and_get_import_state(self):
        from solaradocs.google_import import set_import_state, get_import_state
        set_import_state(1, 'doc1', 'in-progress')
        state, reason = get_import_state(1, 'doc1')
        self.assertEqual(state, 'in-progress')
        self.assertEqual(reason, '')

    def test_set_and_get_import_state_with_reason(self):
        from solaradocs.google_import import set_import_state, get_import_state
        set_import_state(1, 'doc2', 'failed', reason='API error')
        state, reason = get_import_state(1, 'doc2')
        self.assertEqual(state, 'failed')
        self.assertEqual(reason, 'API error')

    def test_get_import_state_missing(self):
        from solaradocs.google_import import get_import_state
        state, reason = get_import_state(999, 'missing')
        self.assertIsNone(state)

    def test_set_and_get_import_job(self):
        from solaradocs.google_import import set_import_job, get_import_job
        entries = [{'id': 'd1', 'title': 'Doc1'}, {'id': 'd2', 'title': 'Doc2'}]
        set_import_job(1, entries)
        result = get_import_job(1)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['id'], 'd1')

    def test_get_import_job_missing(self):
        from solaradocs.google_import import get_import_job
        self.assertIsNone(get_import_job(999))

    def test_get_import_job_status(self):
        from solaradocs.google_import import (
            set_import_state, set_import_job, get_import_job_status,
        )
        set_import_job(1, [
            {'id': 'd1', 'title': 'A'},
            {'id': 'd2', 'title': 'B'},
        ])
        set_import_state(1, 'd1', 'done')
        set_import_state(1, 'd2', 'failed', reason='err')

        status = get_import_job_status(1)
        self.assertFalse(status['all_done'])
        self.assertTrue(status['has_failures'])
        self.assertEqual(len(status['docs']), 2)

    def test_get_import_job_status_all_done(self):
        from solaradocs.google_import import (
            set_import_state, set_import_job, get_import_job_status,
        )
        set_import_job(2, [{'id': 'd1', 'title': 'A'}])
        set_import_state(2, 'd1', 'done')

        status = get_import_job_status(2)
        self.assertTrue(status['all_done'])
        self.assertFalse(status['has_failures'])

    def test_get_import_job_status_no_job(self):
        from solaradocs.google_import import get_import_job_status
        self.assertIsNone(get_import_job_status(999))

    def test_sanitize_imported_text(self):
        from solaradocs.google_import import sanitize_imported_text
        self.assertEqual(sanitize_imported_text(''), '')
        self.assertEqual(sanitize_imported_text(None), '')
        self.assertEqual(sanitize_imported_text('Hello\x00World'), 'HelloWorld')

    def test_sanitize_imported_text_truncates(self):
        from solaradocs.google_import import sanitize_imported_text
        long_text = 'x' * 6_000_000
        result = sanitize_imported_text(long_text)
        self.assertEqual(len(result), 5_000_000)

    def test_fetch_google_doc_text(self):
        from solaradocs.google_import import fetch_google_doc_text
        mock_creds = MagicMock()
        mock_doc = {
            'title': 'Test Doc',
            'body': {
                'content': [
                    {
                        'paragraph': {
                            'elements': [
                                {'textRun': {'content': 'Hello '}},
                                {'textRun': {'content': 'World'}},
                            ]
                        }
                    }
                ]
            },
        }
        with patch('solaradocs.google_import.build') as mock_build:
            mock_service = MagicMock()
            mock_build.return_value = mock_service
            mock_service.documents.return_value.get.return_value.execute.return_value = mock_doc

            title, text = fetch_google_doc_text(mock_creds, 'docid')

        self.assertEqual(title, 'Test Doc')
        # fetch_google_doc_text now returns HTML, not plain text
        self.assertEqual(text, '<p>Hello World</p>')


# ---------------------------------------------------------------------------
# Static / Public Pages
# ---------------------------------------------------------------------------
@override_settings(
    RATELIMIT_ENABLE=False,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class PublicPageTests(TestCase):
    def setUp(self):
        cache.clear()

    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_home(self, mock_render):
        r = self.client.get('/')
        self.assertEqual(r.status_code, 200)
        mock_render.assert_called_once()
        self.assertEqual(mock_render.call_args[0][1], 'index.html')

    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_about(self, mock_render):
        r = self.client.get('/about/')
        self.assertEqual(r.status_code, 200)
        mock_render.assert_called_once()
        self.assertEqual(mock_render.call_args[0][1], 'about.html')

    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_terms(self, mock_render):
        r = self.client.get('/terms/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(mock_render.call_args[0][1], 'terms.html')

    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_privacy(self, mock_render):
        r = self.client.get('/privacy/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(mock_render.call_args[0][1], 'privacy.html')

    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_docs(self, mock_render):
        r = self.client.get('/docs/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(mock_render.call_args[0][1], 'docs.html')

    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_changelog(self, mock_render):
        Changelog.objects.create(
            version='1.0', title='Release', description='First release',
        )
        r = self.client.get('/changelog/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(mock_render.call_args[0][1], 'changelog.html')

    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_password_reset_page(self, mock_render):
        r = self.client.get('/password-reset/')
        self.assertEqual(r.status_code, 200)

    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_buy_page(self, mock_render):
        r = self.client.get('/buy/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(mock_render.call_args[0][1], 'buy.html')


# ---------------------------------------------------------------------------
# Project Detail
# ---------------------------------------------------------------------------
class ProjectDetailTests(BaseTestCase):
    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_project_detail_owner(self, mock_render):
        r = self._get(f'/project/{self.project.id}/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(mock_render.call_args[0][1], 'edit.html')
        ctx = mock_render.call_args[0][2]
        self.assertTrue(ctx['is_owner'])
        self.assertEqual(ctx['role'], 'OWNER')

    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_project_detail_contributor(self, mock_render):
        contrib = self._make_contributor('detailcontrib', role='EDITOR')
        r = self._get(f'/project/{self.project.id}/', user=contrib)
        self.assertEqual(r.status_code, 200)
        ctx = mock_render.call_args[0][2]
        self.assertFalse(ctx['is_owner'])
        self.assertEqual(ctx['role'], 'EDITOR')

    @patch('solaradocs.views.render', return_value=HttpResponse('forbidden', status=403))
    def test_project_detail_stranger(self, mock_render):
        stranger = User.objects.create_user(username='detailstranger', password='pass123456')
        r = self._get(f'/project/{self.project.id}/', user=stranger)
        self.assertEqual(r.status_code, 403)

    @patch('solaradocs.views.render', return_value=HttpResponse('not found', status=404))
    def test_project_detail_not_found(self, mock_render):
        r = self._get('/project/99999/')
        self.assertEqual(r.status_code, 404)


# ---------------------------------------------------------------------------
# Collaborations Page
# ---------------------------------------------------------------------------
class CollaborationsTests(BaseTestCase):
    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_collaborations_page(self, mock_render):
        r = self._get('/collaborations/')
        self.assertEqual(r.status_code, 200)


# ---------------------------------------------------------------------------
# Profile + Account
# ---------------------------------------------------------------------------
@override_settings(RATELIMIT_ENABLE=False)
class ProfileTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='profileuser', email='profile@test.com', password='pass123456',
        )

    @patch('solaradocs.views.render', return_value=HttpResponse('ok'))
    def test_profile_page(self, mock_render):
        self.client.force_login(self.user)
        r = self.client.get('/profile/')
        self.assertEqual(r.status_code, 200)

    def test_profile_requires_login(self):
        r = self.client.get('/profile/')
        self.assertEqual(r.status_code, 302)

    @patch('solaradocs.views.stripe')
    def test_delete_account(self, mock_stripe):
        mock_stripe.Subscription.list.return_value = MagicMock(data=[])
        self.client.force_login(self.user)
        r = self.client.post(
            '/delete-account/',
            json.dumps({}),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 200)
        self.assertFalse(User.objects.filter(username='profileuser').exists())

    @patch('solaradocs.views.stripe')
    def test_delete_account_cancels_stripe(self, mock_stripe):
        self.user.stripe_customer_id = 'cus_123'
        self.user.save()
        mock_sub = MagicMock(id='sub_123')
        mock_stripe.Subscription.list.return_value = MagicMock(data=[mock_sub])
        self.client.force_login(self.user)
        r = self.client.post(
            '/delete-account/',
            json.dumps({}),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 200)
        mock_stripe.Subscription.cancel.assert_called_with('sub_123')


# ---------------------------------------------------------------------------
# Stripe Checkout + Webhook
# ---------------------------------------------------------------------------
@override_settings(RATELIMIT_ENABLE=False)
class StripeTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='stripeuser', email='stripe@test.com', password='pass123456',
        )

    @patch('solaradocs.views.stripe')
    def test_create_checkout_session(self, mock_stripe):
        mock_stripe.Customer.create.return_value = MagicMock(id='cus_new')
        mock_stripe.Subscription.list.return_value = MagicMock(data=[])
        mock_sub = MagicMock()
        mock_sub.latest_invoice.confirmation_secret.client_secret = 'cs_secret'
        mock_sub.id = 'sub_new'
        mock_stripe.Subscription.create.return_value = mock_sub
        mock_stripe.error = __import__('stripe').error

        self.client.force_login(self.user)
        r = self.client.post('/create-checkout-session/', {'tier': 'personal'})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertEqual(data['client_secret'], 'cs_secret')
        self.assertEqual(data['subscription_id'], 'sub_new')

    @patch('solaradocs.views.stripe')
    def test_create_checkout_invalid_tier(self, mock_stripe):
        self.client.force_login(self.user)
        r = self.client.post('/create-checkout-session/', {'tier': 'diamond'})
        self.assertEqual(r.status_code, 400)

    @patch('solaradocs.views.stripe')
    def test_cancel_subscription(self, mock_stripe):
        self.user.stripe_customer_id = 'cus_cancel'
        self.user.save()
        mock_sub = MagicMock(id='sub_cancel')
        mock_stripe.Subscription.list.return_value = MagicMock(data=[mock_sub])
        mock_stripe.error = __import__('stripe').error

        self.client.force_login(self.user)
        with patch('solaradocs.views.send_cancellation_email'):
            r = self.client.post(
                '/cancel-subscription/',
                json.dumps({}),
                content_type='application/json',
            )
        self.assertEqual(r.status_code, 200)
        mock_stripe.Subscription.modify.assert_called_once()

    def test_cancel_subscription_no_customer(self):
        self.client.force_login(self.user)
        r = self.client.post(
            '/cancel-subscription/',
            json.dumps({}),
            content_type='application/json',
        )
        self.assertEqual(r.status_code, 400)


# ---------------------------------------------------------------------------
# Document Access (team-scoped visibility)
# ---------------------------------------------------------------------------
class DocumentTeamAccessTests(BaseTestCase):
    def setUp(self):
        super().setUp()
        self.private_team = Teams.objects.create(
            project=self.project, team_name='Engineering',
        )
        self.private_doc = Documents.objects.create(
            project=self.project, document_name='Private Doc',
            content='Secret', team_assigned=self.private_team,
        )

    def test_contributor_without_team_sees_only_public(self):
        editor = self._make_contributor('noteam', role='EDITOR')
        r = self._get(f'/api/project/{self.project.id}/documents', user=editor)
        self.assertEqual(r.status_code, 200)
        doc_ids = [d['id'] for d in r.json()['documents']]
        self.assertIn(self.doc.id, doc_ids)
        self.assertNotIn(self.private_doc.id, doc_ids)

    def test_team_member_sees_own_team_docs(self):
        editor = self._make_contributor('wteam', role='EDITOR')
        self._make_team_member(editor, team=self.private_team, role='EDITOR')
        r = self._get(f'/api/project/{self.project.id}/documents', user=editor)
        self.assertEqual(r.status_code, 200)
        doc_ids = [d['id'] for d in r.json()['documents']]
        self.assertIn(self.private_doc.id, doc_ids)

    def test_admin_sees_all_docs(self):
        admin = self._make_contributor('alldocs', role='ADMIN')
        r = self._get(f'/api/project/{self.project.id}/documents', user=admin)
        self.assertEqual(r.status_code, 200)
        doc_ids = [d['id'] for d in r.json()['documents']]
        self.assertIn(self.doc.id, doc_ids)
        self.assertIn(self.private_doc.id, doc_ids)

    def test_get_single_doc_non_team_member_denied(self):
        editor = self._make_contributor('noaccess', role='EDITOR')
        r = self._get(
            f'/api/project/{self.project.id}/documents/{self.private_doc.id}',
            user=editor,
        )
        self.assertEqual(r.status_code, 403)

    def test_get_single_doc_team_member_allowed(self):
        editor = self._make_contributor('hasaccess', role='EDITOR')
        self._make_team_member(editor, team=self.private_team, role='EDITOR')
        r = self._get(
            f'/api/project/{self.project.id}/documents/{self.private_doc.id}',
            user=editor,
        )
        self.assertEqual(r.status_code, 200)


# ---------------------------------------------------------------------------
# Stripe Webhook → InvoicePayment
# ---------------------------------------------------------------------------
@override_settings(
    RATELIMIT_ENABLE=False,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
    STRIPE_PERSONAL_PRICE_ID='price_personal',
    STRIPE_TEAM_PRICE_ID='price_team',
    STRIPE_ENTERPRISE_PRICE_ID='price_enterprise',
    STRIPE_WEBHOOK_SECRET='whsec_test',
)
class StripeWebhookInvoicePaymentTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username='payer', email='payer@test.com', password='pass123456',
        )
        self.user.stripe_customer_id = 'cus_123'
        self.user.Tier = 'team'
        self.user.save(update_fields=['stripe_customer_id', 'Tier'])

    def _send(self, event):
        with patch('solaradocs.views.stripe.Webhook.construct_event', return_value=event):
            return self.client.post(
                '/webhook/stripe/',
                data=json.dumps(event),
                content_type='application/json',
                HTTP_STRIPE_SIGNATURE='t=1,v1=fake',
            )

    def _sub(self, price_id='price_team', metadata_tier=None):
        sub = MagicMock()
        sub.metadata = {'tier': metadata_tier} if metadata_tier else {}
        sub.get = lambda k, d=None: {
            'items': {'data': [{'price': {'id': price_id}}]},
        }.get(k, d)
        return sub

    def test_invoice_paid_creates_record(self):
        event = {
            'type': 'invoice.paid',
            'created': 1_700_000_000,
            'data': {'object': {
                'id': 'in_pay_1',
                'customer': 'cus_123',
                'subscription': 'sub_1',
                'amount_paid': 1600,
                'amount_due': 1600,
                'hosted_invoice_url': 'https://stripe.test/invoice/in_pay_1',
                'invoice_pdf': 'https://stripe.test/invoice/in_pay_1.pdf',
                'customer_email': 'payer@test.com',
                'status_transitions': {'paid_at': 1_700_000_500},
            }},
        }
        with patch('solaradocs.views.stripe.Subscription.retrieve', return_value=self._sub('price_team')), \
             patch('solaradocs.views.stripe.Subscription.list', return_value=MagicMock(data=[MagicMock(id='sub_1')])):
            r = self._send(event)
        self.assertEqual(r.status_code, 200)

        rec = InvoicePayment.objects.get(stripe_invoice_id='in_pay_1')
        self.assertEqual(rec.status, 'paid')
        self.assertEqual(rec.amount, 1600)
        self.assertEqual(rec.tier, 'team')
        self.assertEqual(rec.username, 'payer')
        self.assertEqual(rec.email, 'payer@test.com')
        self.assertEqual(rec.pdf_url, 'https://stripe.test/invoice/in_pay_1')
        self.assertIsNotNone(rec.paid_at)

    def test_invoice_paid_rejects_javascript_url(self):
        """Defense in depth: URLField validators don't fire on update_or_create,
        so the webhook helper must scheme-check pdf_url itself."""
        event = {
            'type': 'invoice.paid',
            'created': 1_700_000_000,
            'data': {'object': {
                'id': 'in_xss',
                'customer': 'cus_123',
                'subscription': 'sub_1',
                'amount_paid': 1600,
                'hosted_invoice_url': 'javascript:alert(1)',
                'invoice_pdf': 'http://insecure.example/x.pdf',
            }},
        }
        with patch('solaradocs.views.stripe.Subscription.retrieve', return_value=self._sub('price_team')), \
             patch('solaradocs.views.stripe.Subscription.list', return_value=MagicMock(data=[])):
            self._send(event)
        rec = InvoicePayment.objects.get(stripe_invoice_id='in_xss')
        # Neither javascript: nor http:// should survive
        self.assertIsNone(rec.pdf_url)

    def test_invoice_paid_falls_back_to_pdf_url(self):
        event = {
            'type': 'invoice.paid',
            'created': 1_700_000_000,
            'data': {'object': {
                'id': 'in_pay_2',
                'customer': 'cus_123',
                'subscription': 'sub_1',
                'amount_paid': 600,
                'hosted_invoice_url': None,
                'invoice_pdf': 'https://stripe.test/in_pay_2.pdf',
            }},
        }
        with patch('solaradocs.views.stripe.Subscription.retrieve', return_value=self._sub('price_personal')), \
             patch('solaradocs.views.stripe.Subscription.list', return_value=MagicMock(data=[])):
            self._send(event)
        rec = InvoicePayment.objects.get(stripe_invoice_id='in_pay_2')
        self.assertEqual(rec.pdf_url, 'https://stripe.test/in_pay_2.pdf')
        self.assertEqual(rec.tier, 'personal')

    def test_invoice_paid_is_idempotent_on_replay(self):
        event = {
            'type': 'invoice.paid',
            'created': 1_700_000_000,
            'data': {'object': {
                'id': 'in_pay_dup',
                'customer': 'cus_123',
                'subscription': 'sub_1',
                'amount_paid': 1600,
                'hosted_invoice_url': 'u1',
            }},
        }
        with patch('solaradocs.views.stripe.Subscription.retrieve', return_value=self._sub('price_team')), \
             patch('solaradocs.views.stripe.Subscription.list', return_value=MagicMock(data=[])):
            self._send(event)
            self._send(event)
        self.assertEqual(InvoicePayment.objects.filter(stripe_invoice_id='in_pay_dup').count(), 1)

    def test_invoice_payment_failed_creates_record(self):
        event = {
            'type': 'invoice.payment_failed',
            'data': {'object': {
                'id': 'in_fail_1',
                'customer': 'cus_123',
                'subscription': 'sub_1',
                'amount_due': 1600,
                'hosted_invoice_url': 'https://stripe.test/in_fail_1',
                'customer_email': 'payer@test.com',
            }},
        }
        with patch('solaradocs.views.stripe.Subscription.retrieve', return_value=self._sub('price_team')):
            r = self._send(event)
        self.assertEqual(r.status_code, 200)
        rec = InvoicePayment.objects.get(stripe_invoice_id='in_fail_1')
        self.assertEqual(rec.status, 'failed')
        self.assertEqual(rec.amount, 1600)
        self.assertEqual(rec.tier, 'team')
        self.assertIsNone(rec.paid_at)

    def test_charge_refunded_marks_existing_invoice(self):
        InvoicePayment.objects.create(
            stripe_invoice_id='in_to_refund',
            tier='team', amount=1600, status='paid',
            email='payer@test.com', username='payer',
        )
        event = {
            'type': 'charge.refunded',
            'data': {'object': {
                'id': 'ch_1',
                'invoice': 'in_to_refund',
            }},
        }
        r = self._send(event)
        self.assertEqual(r.status_code, 200)
        rec = InvoicePayment.objects.get(stripe_invoice_id='in_to_refund')
        self.assertEqual(rec.status, 'refunded')

    def test_charge_refunded_without_invoice_is_noop(self):
        """One-off charge with no associated invoice (Stripe edge case)."""
        event = {
            'type': 'charge.refunded',
            'data': {'object': {'id': 'ch_oneoff', 'invoice': None}},
        }
        r = self._send(event)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(InvoicePayment.objects.count(), 0)

    def test_charge_refunded_unknown_invoice_is_noop(self):
        """Refund webhook references an invoice we never recorded — log + ignore."""
        event = {
            'type': 'charge.refunded',
            'data': {'object': {'id': 'ch_unknown', 'invoice': 'in_never_seen'}},
        }
        r = self._send(event)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(InvoicePayment.objects.count(), 0)


# ---------------------------------------------------------------------------
# Billing History (profile section + full-list endpoint)
# ---------------------------------------------------------------------------
@override_settings(
    RATELIMIT_ENABLE=False,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class BillingHistoryTests(TestCase):
    """Uses RequestFactory + direct view calls because Django's template-rendered
    signal trips on Python 3.14 (super().__copy__ on Context)."""

    def setUp(self):
        cache.clear()
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='alice', email='alice@test.com', password='pass123456',
        )

    def _call(self, view, path, user=None):
        from solaradocs import views as v
        req = self.factory.get(path)
        req.user = user or self.user
        # ajax_login_required also looks up the token; mock both paths
        with patch.object(v, 'verify_auth_token', return_value={'user_id': req.user.id}):
            return view(req)

    def _make_invoice(self, **kwargs):
        defaults = dict(
            stripe_invoice_id=f'in_{InvoicePayment.objects.count() + 1}',
            tier='team', amount=1600, status='paid',
            email='alice@test.com', username='alice',
            paid_at=timezone.now(),
        )
        defaults.update(kwargs)
        return InvoicePayment.objects.create(**defaults)

    def test_profile_empty_state(self):
        from solaradocs.views import profile
        r = self._call(profile, '/profile/')
        self.assertEqual(r.status_code, 200)
        body = r.content.decode()
        self.assertIn('No billing history yet.', body)
        self.assertNotIn('[View all invoices]', body)

    def test_profile_shows_at_most_5_with_view_all(self):
        from solaradocs.views import profile
        for i in range(7):
            self._make_invoice(stripe_invoice_id=f'in_paid_{i}', amount=1600)
        r = self._call(profile, '/profile/')
        body = r.content.decode()
        self.assertEqual(body.count('✓ Paid'), 5)
        self.assertIn('[View all invoices]', body)
        self.assertIn('/billing-history/', body)

    def test_profile_only_shows_own_invoices(self):
        from solaradocs.views import profile
        InvoicePayment.objects.create(
            stripe_invoice_id='in_other', tier='team', amount=9999,
            status='paid', email='bob@test.com', username='bob',
        )
        self._make_invoice(stripe_invoice_id='in_mine', amount=1600)
        body = self._call(profile, '/profile/').content.decode()
        self.assertIn('$16.00', body)
        self.assertNotIn('$99.99', body)

    def test_profile_status_classes(self):
        from solaradocs.views import profile
        self._make_invoice(stripe_invoice_id='in_p', status='paid', amount=1600)
        self._make_invoice(stripe_invoice_id='in_f', status='failed', amount=1600, paid_at=None)
        self._make_invoice(stripe_invoice_id='in_r', status='refunded', amount=1600)
        body = self._call(profile, '/profile/').content.decode()
        self.assertIn('billing-status-paid', body)
        self.assertIn('billing-status-failed', body)
        self.assertIn('billing-status-refunded', body)
        self.assertIn('Retry', body)

    def test_billing_history_endpoint_returns_all(self):
        from solaradocs.views import billing_history
        for i in range(8):
            self._make_invoice(stripe_invoice_id=f'in_full_{i}', amount=1600)
        body = self._call(billing_history, '/billing-history/').content.decode()
        self.assertEqual(body.count('✓ Paid'), 8)


# ---------------------------------------------------------------------------
# Phase 3 — Quick wins
# ---------------------------------------------------------------------------
@override_settings(
    RATELIMIT_ENABLE=False,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class QuickWinsTests(TestCase):
    def setUp(self):
        cache.clear()
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='alice', email='alice@test.com', password='pass123456',
        )

    def test_home_redirects_authenticated_user_to_dashboard(self):
        from solaradocs.views import home
        from django.contrib.auth.models import AnonymousUser
        req = self.factory.get('/')
        req.user = self.user
        r = home(req)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.url, '/dashboard/')

    def test_home_renders_for_anon(self):
        from solaradocs.views import home
        from django.contrib.auth.models import AnonymousUser
        req = self.factory.get('/')
        req.user = AnonymousUser()
        r = home(req)
        # 200 (rendered) — NOT a redirect
        self.assertEqual(r.status_code, 200)

    def test_index_template_no_longer_claims_uptime(self):
        from pathlib import Path
        body = Path(
            '/Users/solara/Desktop/solaradocs/solaradocs/templates/index.html'
        ).read_text()
        self.assertNotIn('99.9%', body)
        self.assertNotIn('>Uptime<', body)

    def test_index_template_has_new_title_and_og(self):
        from pathlib import Path
        body = Path(
            '/Users/solara/Desktop/solaradocs/solaradocs/templates/index.html'
        ).read_text()
        self.assertIn(
            'SolaraDocs - Private team docs with audit logs, flat $16/mo',
            body,
        )
        self.assertIn('og:title', body)
        self.assertIn('og:description', body)
        self.assertIn('og:image', body)

    def test_footer_year_is_2026(self):
        from pathlib import Path
        body = Path(
            '/Users/solara/Desktop/solaradocs/solaradocs/templates/index.html'
        ).read_text()
        self.assertIn('© 2026 Solara Docs', body)
        self.assertNotIn('© 2025 Solara Docs', body)

    def test_dashboard_template_hides_owner_when_self(self):
        # Sanity-check the conditional is present
        from pathlib import Path
        body = Path(
            '/Users/solara/Desktop/solaradocs/solaradocs/templates/dashboard.html'
        ).read_text()
        self.assertIn(
            '{% if project.owner_id != request.user.id %}',
            body,
        )

    def test_dashboard_template_hides_zero_collab_count(self):
        from pathlib import Path
        body = Path(
            '/Users/solara/Desktop/solaradocs/solaradocs/templates/dashboard.html'
        ).read_text()
        self.assertIn('{% if not project.contributors.count %}', body)

    def test_dashboard_template_uses_kebab_for_delete(self):
        from pathlib import Path
        body = Path(
            '/Users/solara/Desktop/solaradocs/solaradocs/templates/dashboard.html'
        ).read_text()
        # The bare btn-danger delete next to Open/Details should be gone
        self.assertNotIn(
            'onclick="deleteProject({{ project.id }})"',
            body,
        )
        # And the kebab + typed-confirm scaffolding should be in place
        self.assertIn('class="kebab-btn"', body)
        self.assertIn('id="typedConfirmOverlay"', body)
        self.assertIn('showTypedConfirm', body)

    def test_editor_toolbar_buttons_have_titles(self):
        from pathlib import Path
        body = Path(
            '/Users/solara/Desktop/solaradocs/solaradocs/templates/edit.html'
        ).read_text()
        for btn_id in [
            'boldBtn', 'italicBtn', 'underlineBtn', 'strikeBtn',
            'bulletListBtn', 'orderedListBtn', 'quoteBtn', 'codeBtn',
            'codeBlockBtn', 'linkBtn', 'imageBtn', 'undoBtn', 'redoBtn',
            'clearBtn', 'printBtn',
        ]:
            self.assertRegex(
                body,
                rf'id="{btn_id}"[^>]*\btitle="',
                msg=f'toolbar button {btn_id} is missing a title= attribute',
            )


# ---------------------------------------------------------------------------
# Phase 4 — Delete safety (typed confirmation on backend)
# ---------------------------------------------------------------------------
@override_settings(
    RATELIMIT_ENABLE=False,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class DeleteProjectTypedConfirmTests(TestCase):
    def setUp(self):
        cache.clear()
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='owner', email='owner@test.com', password='pass123456',
        )
        self.project = Project.objects.create(
            owner=self.user, project_name='MyProject', tier='team',
        )

    def _post(self, payload):
        from solaradocs import views as v
        req = self.factory.post(
            '/deleteproject/',
            data=json.dumps(payload),
            content_type='application/json',
            HTTP_AUTHORIZATION='Bearer t',
        )
        req.user = self.user
        with patch.object(v, 'verify_auth_token', return_value={'user_id': self.user.id}):
            return v.delete_project(req)

    def test_delete_without_confirm_name_fails(self):
        r = self._post({'project_id': self.project.id})
        self.assertEqual(r.status_code, 400)
        self.assertIn(b'exact project name', r.content)
        self.assertTrue(Project.objects.filter(id=self.project.id).exists())

    def test_delete_with_wrong_confirm_name_fails(self):
        r = self._post({'project_id': self.project.id, 'confirm_name': 'WrongName'})
        self.assertEqual(r.status_code, 400)
        self.assertTrue(Project.objects.filter(id=self.project.id).exists())

    def test_delete_case_sensitive(self):
        r = self._post({'project_id': self.project.id, 'confirm_name': 'myproject'})
        self.assertEqual(r.status_code, 400)
        self.assertTrue(Project.objects.filter(id=self.project.id).exists())

    def test_delete_with_correct_confirm_name_succeeds(self):
        r = self._post({'project_id': self.project.id, 'confirm_name': 'MyProject'})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Project.objects.filter(id=self.project.id).exists())

    def test_delete_other_users_project_still_403_even_with_name(self):
        other = User.objects.create_user(username='thief', password='pw123456')
        from solaradocs import views as v
        req = self.factory.post(
            '/deleteproject/',
            data=json.dumps({'project_id': self.project.id, 'confirm_name': 'MyProject'}),
            content_type='application/json',
            HTTP_AUTHORIZATION='Bearer t',
        )
        req.user = other
        with patch.object(v, 'verify_auth_token', return_value={'user_id': other.id}):
            r = v.delete_project(req)
        self.assertEqual(r.status_code, 403)
        self.assertTrue(Project.objects.filter(id=self.project.id).exists())


# ---------------------------------------------------------------------------
# Phase 5 — Past Due banner + billing portal
# ---------------------------------------------------------------------------
@override_settings(
    RATELIMIT_ENABLE=False,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class PastDueBannerTests(TestCase):
    def setUp(self):
        cache.clear()
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='alice', email='alice@test.com', password='pass123456',
        )

    def test_context_processor_returns_false_for_anon(self):
        from solaradocs.context_processors import past_due_banner
        from django.contrib.auth.models import AnonymousUser
        req = self.factory.get('/')
        req.user = AnonymousUser()
        self.assertEqual(past_due_banner(req), {'show_past_due_banner': False})

    def test_context_processor_returns_false_when_not_past_due(self):
        from solaradocs.context_processors import past_due_banner
        self.user.subscription_status = 'active'
        self.user.save()
        req = self.factory.get('/')
        req.user = self.user
        self.assertEqual(past_due_banner(req), {'show_past_due_banner': False})

    def test_context_processor_returns_true_when_past_due(self):
        from solaradocs.context_processors import past_due_banner
        self.user.subscription_status = 'past_due'
        self.user.save()
        req = self.factory.get('/')
        req.user = self.user
        self.assertEqual(past_due_banner(req), {'show_past_due_banner': True})

    def test_banner_renders_via_profile_when_past_due(self):
        from solaradocs.views import profile
        self.user.subscription_status = 'past_due'
        self.user.save()
        from solaradocs import views as v
        req = self.factory.get('/profile/')
        req.user = self.user
        with patch.object(v, 'verify_auth_token', return_value={'user_id': self.user.id}):
            r = profile(req)
        body = r.content.decode()
        self.assertIn('Your subscription is past due', body)
        self.assertIn('/billing-portal/', body)

    def test_banner_hidden_when_not_past_due(self):
        from solaradocs.views import profile
        self.user.subscription_status = 'active'
        self.user.save()
        from solaradocs import views as v
        req = self.factory.get('/profile/')
        req.user = self.user
        with patch.object(v, 'verify_auth_token', return_value={'user_id': self.user.id}):
            r = profile(req)
        self.assertNotIn(
            'Your subscription is past due',
            r.content.decode(),
        )

    def test_all_main_templates_include_banner_partial(self):
        from pathlib import Path
        base = Path('/Users/solara/Desktop/solaradocs/solaradocs/templates')
        for name in [
            'dashboard.html', 'profile.html', 'edit.html', 'collaborations.html',
            'changelog.html', 'docs.html', 'setup.html', 'success.html',
            'admin.html', 'buy.html', 'index.html',
        ]:
            self.assertIn(
                'partials/past_due_banner.html',
                (base / name).read_text(),
                msg=f'{name} is missing the past-due banner include',
            )


@override_settings(
    RATELIMIT_ENABLE=False,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class BillingPortalTests(TestCase):
    def setUp(self):
        cache.clear()
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='alice', email='alice@test.com', password='pass123456',
        )

    def _post(self, user=None):
        from solaradocs import views as v
        req = self.factory.post('/billing-portal/')
        req.user = user or self.user
        return v.billing_portal_session(req)

    def test_no_stripe_customer_redirects_to_profile(self):
        r = self._post()
        self.assertEqual(r.status_code, 302)
        self.assertIn('/profile/', r.url)

    def test_creates_stripe_session_and_redirects_when_customer_exists(self):
        self.user.stripe_customer_id = 'cus_abc'
        self.user.save()
        fake = MagicMock(url='https://billing.stripe.com/p/session_xyz')
        with patch('solaradocs.views.stripe.billing_portal.Session.create', return_value=fake) as mock_create:
            r = self._post()
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r.url, 'https://billing.stripe.com/p/session_xyz')
        mock_create.assert_called_once()
        kwargs = mock_create.call_args.kwargs
        self.assertEqual(kwargs['customer'], 'cus_abc')
        self.assertIn('/profile/', kwargs['return_url'])

    def test_stripe_error_falls_back_to_profile(self):
        import stripe as _stripe
        self.user.stripe_customer_id = 'cus_abc'
        self.user.save()
        with patch(
            'solaradocs.views.stripe.billing_portal.Session.create',
            side_effect=_stripe.error.StripeError('boom'),
        ):
            r = self._post()
        self.assertEqual(r.status_code, 302)
        self.assertIn('/profile/', r.url)


# ---------------------------------------------------------------------------
# Phase 6 — Changelog rewrite migration (scaffold)
# ---------------------------------------------------------------------------
@override_settings(
    RATELIMIT_ENABLE=False,
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class ChangelogRewriteMigrationTests(TestCase):
    def test_empty_entries_is_noop(self):
        from solaradocs.migrations import (
            __init__ as _,  # noqa: F401  (force pkg import)
        )
        from importlib import import_module
        mod = import_module('solaradocs.migrations.0016_rewrite_changelog')
        Changelog.objects.create(version='1.0.0', title='Pre-existing', description='x')
        # Default NEW_ENTRIES is empty → must not touch existing rows
        self.assertEqual(mod.NEW_ENTRIES, [])
        mod.rewrite(_FakeApps(), schema_editor=None)
        self.assertEqual(Changelog.objects.count(), 1)
        self.assertEqual(Changelog.objects.first().title, 'Pre-existing')

    def test_populated_entries_wipe_and_replace(self):
        from importlib import import_module
        mod = import_module('solaradocs.migrations.0016_rewrite_changelog')
        Changelog.objects.create(version='0.0.1', title='Old', description='legacy')
        sample = [
            {'version': '1.0.0', 'title': 'A', 'description': 'a', 'version_type': 'major'},
            {'version': '1.1.0', 'title': 'B', 'description': 'b', 'version_type': 'minor'},
        ]
        with patch.object(mod, 'NEW_ENTRIES', sample):
            mod.rewrite(_FakeApps(), schema_editor=None)
        titles = list(Changelog.objects.values_list('title', flat=True))
        self.assertNotIn('Old', titles)
        self.assertIn('A', titles)
        self.assertIn('B', titles)


class _FakeApps:
    """Minimal stand-in for apps registry — returns the real Changelog model."""
    def get_model(self, app_label, model_name):
        from solaradocs.models import Changelog as _C
        return _C


# ---------------------------------------------------------------------------
# Template tag: cents_to_dollars (bug fix for amounts < $1.00)
# ---------------------------------------------------------------------------
class CentsToDollarsFilterTests(TestCase):
    def test_round_dollar(self):
        from solaradocs.templatetags.billing_extras import cents_to_dollars
        self.assertEqual(cents_to_dollars(1600), '16.00')
        self.assertEqual(cents_to_dollars(100), '1.00')

    def test_sub_dollar(self):
        # The bug the old slice-based formatter had: 50 cents rendered as
        # ".50" instead of "0.50". Lock the fix down.
        from solaradocs.templatetags.billing_extras import cents_to_dollars
        self.assertEqual(cents_to_dollars(50), '0.50')
        self.assertEqual(cents_to_dollars(5), '0.05')
        self.assertEqual(cents_to_dollars(0), '0.00')

    def test_large_amounts_and_negatives(self):
        from solaradocs.templatetags.billing_extras import cents_to_dollars
        self.assertEqual(cents_to_dollars(123456), '1234.56')
        self.assertEqual(cents_to_dollars(-100), '-1.00')

    def test_invalid_input(self):
        from solaradocs.templatetags.billing_extras import cents_to_dollars
        self.assertEqual(cents_to_dollars(None), '0.00')
        self.assertEqual(cents_to_dollars('not-a-number'), '0.00')


# ---------------------------------------------------------------------------
# Past-due banner uses POST form (not bare GET link) — regression guard
# ---------------------------------------------------------------------------
class PastDueBannerPostShapeTests(TestCase):
    def test_banner_uses_post_form_not_get_link(self):
        from pathlib import Path
        body = Path(
            '/Users/solara/Desktop/solaradocs/solaradocs/templates/partials/past_due_banner.html'
        ).read_text()
        # Must POST so it hits the @require_POST view without a 405
        self.assertIn('method="post"', body)
        self.assertIn('action="/billing-portal/"', body)
        self.assertIn('{% csrf_token %}', body)
        # The old anchor-as-link approach would silently 405; guard against
        # someone reintroducing it.
        self.assertNotIn('<a href="/billing-portal/"', body)
