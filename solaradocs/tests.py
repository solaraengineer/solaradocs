"""
Comprehensive test suite for SolaraDocs views.py
Tests RBAC, input sanitization, validation, and authentication
"""

import json
import jwt
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.conf import settings

from .models import Project, Contributor, Documents, Teams, TeamMember, Backup, Audit, Pending
from .views import (
    sanitize_string, generate_auth_token, verify_auth_token,
    generate_editor_token, verify_editor_token,
    PROJECT_NAME_REGEX, USERNAME_REGEX, EMAIL_REGEX, TIER_LIMITS
)

User = get_user_model()


# =============================================================================
# INPUT SANITIZATION TESTS
# =============================================================================

class SanitizeStringTests(TestCase):
    """Tests for the sanitize_string utility function"""

    def test_valid_project_name(self):
        """Valid project names should pass"""
        result, error = sanitize_string("My Project 123", 100, PROJECT_NAME_REGEX, "Project name")
        self.assertEqual(result, "My Project 123")
        self.assertIsNone(error)

    def test_valid_project_name_with_special_chars(self):
        """Project names with allowed special chars should pass"""
        result, error = sanitize_string("Project @#$!", 100, PROJECT_NAME_REGEX, "Project name")
        self.assertEqual(result, "Project @#$!")
        self.assertIsNone(error)

    def test_project_name_strips_whitespace(self):
        """Whitespace should be stripped"""
        result, error = sanitize_string("  My Project  ", 100, PROJECT_NAME_REGEX, "Project name")
        self.assertEqual(result, "My Project")
        self.assertIsNone(error)

    def test_empty_string_rejected(self):
        """Empty strings should be rejected"""
        result, error = sanitize_string("", 100, PROJECT_NAME_REGEX, "Project name")
        self.assertIsNone(result)
        self.assertEqual(error, "Project name is required")

    def test_whitespace_only_rejected(self):
        """Whitespace-only strings should be rejected"""
        result, error = sanitize_string("   ", 100, PROJECT_NAME_REGEX, "Project name")
        self.assertIsNone(result)
        self.assertEqual(error, "Project name is required")

    def test_too_long_rejected(self):
        """Strings exceeding max_length should be rejected"""
        result, error = sanitize_string("a" * 101, 100, PROJECT_NAME_REGEX, "Project name")
        self.assertIsNone(result)
        self.assertEqual(error, "Project name too long (max 100 characters)")

    def test_invalid_characters_rejected(self):
        """Strings with invalid characters should be rejected"""
        result, error = sanitize_string("Project<script>", 100, PROJECT_NAME_REGEX, "Project name")
        self.assertIsNone(result)
        self.assertEqual(error, "Project name contains invalid characters")

    def test_non_string_rejected(self):
        """Non-string values should be rejected"""
        result, error = sanitize_string(123, 100, PROJECT_NAME_REGEX, "Project name")
        self.assertIsNone(result)
        self.assertEqual(error, "Project name must be a string")

        result, error = sanitize_string(None, 100, PROJECT_NAME_REGEX, "Project name")
        self.assertIsNone(result)
        self.assertEqual(error, "Project name must be a string")

        result, error = sanitize_string(['list'], 100, PROJECT_NAME_REGEX, "Project name")
        self.assertIsNone(result)
        self.assertEqual(error, "Project name must be a string")

    def test_valid_username(self):
        """Valid usernames should pass"""
        result, error = sanitize_string("user_123", 50, USERNAME_REGEX, "Username")
        self.assertEqual(result, "user_123")
        self.assertIsNone(error)

    def test_username_with_special_chars(self):
        """Usernames with allowed special chars"""
        result, error = sanitize_string("user@#$!", 50, USERNAME_REGEX, "Username")
        self.assertEqual(result, "user@#$!")
        self.assertIsNone(error)

    def test_username_no_spaces(self):
        """Usernames with spaces should fail"""
        result, error = sanitize_string("user name", 50, USERNAME_REGEX, "Username")
        self.assertIsNone(result)
        self.assertIn("invalid characters", error)


class RegexPatternTests(TestCase):
    """Tests for regex patterns used in validation"""

    def test_project_name_regex_valid(self):
        """Valid project names"""
        valid_names = [
            "Project",
            "Project 123",
            "My Awesome Project",
            "Test@Project",
            "Project#1",
            "Hey$There",
            "Bang!",
        ]
        for name in valid_names:
            self.assertTrue(PROJECT_NAME_REGEX.match(name), f"Should match: {name}")

    def test_project_name_regex_invalid(self):
        """Invalid project names"""
        invalid_names = [
            "Project<script>",
            "Test&Project",
            "Project%",
            "Name^Hat",
            "Project*Star",
            "Name(paren)",
            "Tab\there",
        ]
        for name in invalid_names:
            self.assertIsNone(PROJECT_NAME_REGEX.match(name), f"Should not match: {name}")

    def test_username_regex_valid(self):
        """Valid usernames"""
        valid_names = ["user", "user123", "user_name", "User@Test", "admin#1", "test$user", "bang!"]
        for name in valid_names:
            self.assertTrue(USERNAME_REGEX.match(name), f"Should match: {name}")

    def test_username_regex_invalid(self):
        """Invalid usernames - no spaces allowed"""
        invalid_names = ["user name", "test user", "has space"]
        for name in invalid_names:
            self.assertIsNone(USERNAME_REGEX.match(name), f"Should not match: {name}")

    def test_email_regex_valid(self):
        """Valid emails"""
        valid_emails = [
            "test@example.com",
            "user.name@domain.co",
            "user+tag@gmail.com",
            "test123@sub.domain.org",
        ]
        for email in valid_emails:
            self.assertTrue(EMAIL_REGEX.match(email), f"Should match: {email}")

    def test_email_regex_invalid(self):
        """Invalid emails"""
        invalid_emails = [
            "notanemail",
            "@nodomain.com",
            "no@tld",
            "spaces in@email.com",
            "missing@.com",
        ]
        for email in invalid_emails:
            self.assertIsNone(EMAIL_REGEX.match(email), f"Should not match: {email}")


# =============================================================================
# JWT TOKEN TESTS
# =============================================================================

@override_settings(
    JWT_PRIVATE_KEY="""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MvQepC8LiVLwITnT
9gXdGVDz2F9PZ7Y1aSQRD5rY5pNT1Gp1vLwBwyH8kREaVS9xC9v0SSHZ0qHR0Z0R
xRZ0U3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3Vh
Z3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3Vh
Z3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3Vh
Z3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZQIDAQABAoIBAC5RgZ+hBx7xHnFZ
nQmY5qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqECgYEA7YqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqECgYEA4XqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqUCgYEAqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqECgYBqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq=
-----END RSA PRIVATE KEY-----""",
    JWT_PUBLIC_KEY="""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWy
F8PbnGy0AHB7MvQepC8LiVLwITnT9gXdGVDz2F9PZ7Y1aSQRD5rY5pNT1Gp1vLwB
wyH8kREaVS9xC9v0SSHZ0qHR0Z0RxRZ0U3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3Vh
Z3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3Vh
Z3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3Vh
Z3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3VhZ3Vh
ZQIDAQAB
-----END PUBLIC KEY-----"""
)
class JWTTokenTests(TestCase):
    """Tests for JWT token generation and verification"""

    def test_generate_auth_token_structure(self):
        """Auth tokens should have correct structure"""
        token = generate_auth_token(user_id=123)
        self.assertIsInstance(token, str)
        # JWT has 3 parts separated by dots
        parts = token.split('.')
        self.assertEqual(len(parts), 3)

    def test_verify_valid_token(self):
        """Valid tokens should verify successfully"""
        token = generate_auth_token(user_id=123)
        payload = verify_auth_token(token)
        self.assertIsInstance(payload, dict)
        self.assertEqual(payload['user_id'], 123)

    def test_verify_expired_token(self):
        """Expired tokens should return 'expired'"""
        # Create token with past expiration
        payload = {
            'user_id': 123,
            'exp': datetime.utcnow() - timedelta(hours=2),
            'iat': datetime.utcnow() - timedelta(hours=3)
        }
        token = jwt.encode(payload, settings.JWT_PRIVATE_KEY, algorithm='RS384')
        result = verify_auth_token(token)
        self.assertEqual(result, 'expired')

    def test_verify_invalid_token(self):
        """Invalid tokens should return 'invalid'"""
        result = verify_auth_token("not.a.valid.token")
        self.assertEqual(result, 'invalid')

        result = verify_auth_token("")
        self.assertEqual(result, 'invalid')

    def test_verify_tampered_token(self):
        """Tampered tokens should fail verification"""
        token = generate_auth_token(user_id=123)
        # Tamper with the token
        tampered = token[:-5] + "XXXXX"
        result = verify_auth_token(tampered)
        self.assertEqual(result, 'invalid')

    def test_generate_editor_token_includes_project_id(self):
        """Editor tokens should include project_id"""
        token = generate_editor_token(user_id=1, project_id=42)
        payload = jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=['RS384'])
        self.assertEqual(payload['user_id'], 1)
        self.assertEqual(payload['project_id'], 42)

    def test_verify_editor_token_wrong_project(self):
        """Editor token verification should fail for wrong project"""
        token = generate_editor_token(user_id=1, project_id=42)
        result = verify_editor_token(token, project_id=99)
        self.assertIsNone(result)

    def test_verify_editor_token_correct_project(self):
        """Editor token verification should pass for correct project"""
        token = generate_editor_token(user_id=1, project_id=42)
        result = verify_editor_token(token, project_id=42)
        self.assertIsNotNone(result)
        self.assertEqual(result['project_id'], 42)


# =============================================================================
# AUTHENTICATION TESTS
# =============================================================================

class AuthenticationTests(TestCase):
    """Tests for login, register, and logout"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_login_valid_credentials(self):
        """Valid credentials should log in successfully"""
        response = self.client.post('/login/', {
            'username': 'testuser',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertIn('token', data)
        self.assertEqual(data['redirect'], '/dashboard/')

    def test_login_invalid_credentials(self):
        """Invalid credentials should fail"""
        response = self.client.post('/login/', {
            'username': 'testuser',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertFalse(data['success'])
        self.assertEqual(data['error'], 'Invalid credentials')

    def test_login_nonexistent_user(self):
        """Nonexistent user should fail with same error (no enumeration)"""
        response = self.client.post('/login/', {
            'username': 'nonexistent',
            'password': 'anypassword'
        })
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertEqual(data['error'], 'Invalid credentials')

    def test_login_invalid_username_format(self):
        """Invalid username format should fail"""
        response = self.client.post('/login/', {
            'username': 'invalid<script>',
            'password': 'password123'
        })
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertEqual(data['error'], 'Invalid credentials')

    def test_login_username_must_contain_letter(self):
        """Username must contain at least one letter"""
        response = self.client.post('/login/', {
            'username': '123456',
            'password': 'password123'
        })
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertEqual(data['error'], 'Invalid credentials')

    def test_login_redirect_if_authenticated(self):
        """Already authenticated users should redirect"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.get('/login/')
        self.assertEqual(response.status_code, 302)

    def test_register_valid_data(self):
        """Valid registration should succeed"""
        response = self.client.post('/register/', {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'securepass123'
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['success'])
        self.assertIn('token', data)
        self.assertTrue(User.objects.filter(username='newuser').exists())

    def test_register_duplicate_username(self):
        """Duplicate username should fail"""
        response = self.client.post('/register/', {
            'username': 'testuser',  # Already exists
            'email': 'different@example.com',
            'password': 'securepass123'
        })
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['error'], 'Username taken')

    def test_register_duplicate_email(self):
        """Duplicate email should fail"""
        response = self.client.post('/register/', {
            'username': 'differentuser',
            'email': 'test@example.com',  # Already exists
            'password': 'securepass123'
        })
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['error'], 'Email taken')

    def test_register_invalid_username_format(self):
        """Invalid username format should fail"""
        response = self.client.post('/register/', {
            'username': 'user<script>',
            'email': 'new@example.com',
            'password': 'securepass123'
        })
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['error'], 'Invalid username format')

    def test_register_username_too_short(self):
        """Username under 3 chars should fail"""
        response = self.client.post('/register/', {
            'username': 'ab',
            'email': 'new@example.com',
            'password': 'securepass123'
        })
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['error'], 'Username must be 3-30 characters')

    def test_register_username_too_long(self):
        """Username over 30 chars should fail"""
        response = self.client.post('/register/', {
            'username': 'a' * 31,
            'email': 'new@example.com',
            'password': 'securepass123'
        })
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['error'], 'Username must be 3-30 characters')

    def test_register_invalid_email(self):
        """Invalid email format should fail"""
        response = self.client.post('/register/', {
            'username': 'newuser',
            'email': 'notanemail',
            'password': 'securepass123'
        })
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['error'], 'Invalid email format')

    def test_register_password_too_short(self):
        """Password under 6 chars should fail"""
        response = self.client.post('/register/', {
            'username': 'newuser',
            'email': 'new@example.com',
            'password': '12345'
        })
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['error'], 'Password must be at least 6 characters')

    def test_register_username_needs_letter(self):
        """Username must contain at least one letter"""
        response = self.client.post('/register/', {
            'username': '123456',
            'email': 'new@example.com',
            'password': 'securepass123'
        })
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['error'], 'Username must contain letters')

    def test_logout(self):
        """Logout should redirect to login"""
        self.client.login(username='testuser', password='testpass123')
        response = self.client.post('/logout/')
        self.assertEqual(response.status_code, 302)


# =============================================================================
# RBAC - PROJECT OWNERSHIP TESTS
# =============================================================================

class ProjectOwnershipRBACTests(TestCase):
    """Tests for project ownership RBAC"""

    def setUp(self):
        self.client = Client()
        self.owner = User.objects.create_user(
            username='owner',
            email='owner@example.com',
            password='ownerpass123'
        )
        self.other_user = User.objects.create_user(
            username='other',
            email='other@example.com',
            password='otherpass123'
        )
        self.project = Project.objects.create(
            owner=self.owner,
            project_name='Test Project',
            tier='free'
        )

    def test_owner_can_delete_project(self):
        """Owner should be able to delete their project"""
        self.client.login(username='owner', password='ownerpass123')
        token = generate_auth_token(self.owner.id)

        response = self.client.post(
            '/delete_project/',
            data=json.dumps({'project_id': self.project.id}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Project.objects.filter(id=self.project.id).exists())

    def test_non_owner_cannot_delete_project(self):
        """Non-owner should not be able to delete project"""
        self.client.login(username='other', password='otherpass123')
        token = generate_auth_token(self.other_user.id)

        response = self.client.post(
            '/delete_project/',
            data=json.dumps({'project_id': self.project.id}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertEqual(data['error'], 'Permission denied')
        self.assertTrue(Project.objects.filter(id=self.project.id).exists())

    def test_owner_can_add_people(self):
        """Owner should be able to add collaborators"""
        self.client.login(username='owner', password='ownerpass123')
        token = generate_auth_token(self.owner.id)

        response = self.client.post(
            '/add_people/',
            data=json.dumps({
                'project_id': self.project.id,
                'usernames': 'other'
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Contributor.objects.filter(
            project=self.project,
            username='other'
        ).exists())

    def test_non_owner_cannot_add_people(self):
        """Non-owner should not be able to add collaborators"""
        self.client.login(username='other', password='otherpass123')
        token = generate_auth_token(self.other_user.id)

        response = self.client.post(
            '/add_people/',
            data=json.dumps({
                'project_id': self.project.id,
                'usernames': 'owner'
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertEqual(data['error'], 'Permission denied')

    def test_owner_can_change_roles(self):
        """Owner should be able to change contributor roles"""
        contributor = Contributor.objects.create(
            project=self.project,
            username='other',
            role='VIEWER'
        )
        self.client.login(username='owner', password='ownerpass123')
        token = generate_auth_token(self.owner.id)

        response = self.client.post(
            '/change_roles/',
            data=json.dumps({
                'project_id': self.project.id,
                'contributor_id': contributor.id,
                'role': 'EDITOR'
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 200)
        contributor.refresh_from_db()
        self.assertEqual(contributor.role, 'EDITOR')

    def test_non_owner_cannot_change_roles(self):
        """Non-owner should not be able to change roles"""
        Contributor.objects.create(
            project=self.project,
            username='other',
            role='VIEWER'
        )
        contributor = Contributor.objects.create(
            project=self.project,
            username='another',
            role='VIEWER'
        )
        User.objects.create_user(
            username='another',
            email='another@example.com',
            password='anotherpass123'
        )

        self.client.login(username='other', password='otherpass123')
        token = generate_auth_token(self.other_user.id)

        response = self.client.post(
            '/change_roles/',
            data=json.dumps({
                'project_id': self.project.id,
                'contributor_id': contributor.id,
                'role': 'ADMIN'
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 403)

    def test_only_owner_can_delete_contributor(self):
        """Only owner should be able to remove contributors"""
        contributor = Contributor.objects.create(
            project=self.project,
            username='other',
            role='VIEWER'
        )

        # Non-owner attempt
        self.client.login(username='other', password='otherpass123')
        token = generate_auth_token(self.other_user.id)

        response = self.client.post(
            '/deleteuser/',
            data=json.dumps({
                'project_id': self.project.id,
                'contributor_id': contributor.id
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 403)

        # Owner attempt
        self.client.login(username='owner', password='ownerpass123')
        token = generate_auth_token(self.owner.id)

        response = self.client.post(
            '/deleteuser/',
            data=json.dumps({
                'project_id': self.project.id,
                'contributor_id': contributor.id
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 200)


# =============================================================================
# RBAC - TEAM MANAGEMENT TESTS
# =============================================================================

class TeamManagementRBACTests(TestCase):
    """Tests for team management RBAC"""

    def setUp(self):
        self.client = Client()
        self.owner = User.objects.create_user(
            username='owner',
            email='owner@example.com',
            password='ownerpass123'
        )
        self.contributor = User.objects.create_user(
            username='contributor',
            email='contrib@example.com',
            password='contribpass123'
        )
        self.project = Project.objects.create(
            owner=self.owner,
            project_name='Test Project',
            tier='team'  # Higher tier for team features
        )
        Contributor.objects.create(
            project=self.project,
            username='contributor',
            role='VIEWER'
        )

    def test_owner_can_create_team(self):
        """Owner should be able to create teams"""
        self.client.login(username='owner', password='ownerpass123')
        token = generate_auth_token(self.owner.id)

        response = self.client.post(
            f'/project/{self.project.id}/teams/create/',
            data=json.dumps({'team_name': 'Dev Team'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(Teams.objects.filter(
            project=self.project,
            team_name='Dev Team'
        ).exists())

    def test_contributor_cannot_create_team(self):
        """Contributor should not be able to create teams"""
        self.client.login(username='contributor', password='contribpass123')
        token = generate_auth_token(self.contributor.id)

        response = self.client.post(
            f'/project/{self.project.id}/teams/create/',
            data=json.dumps({'team_name': 'Unauthorized Team'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 403)

    def test_owner_can_delete_team(self):
        """Owner should be able to delete teams"""
        team = Teams.objects.create(
            project=self.project,
            team_name='To Delete'
        )
        self.client.login(username='owner', password='ownerpass123')
        token = generate_auth_token(self.owner.id)

        response = self.client.post(
            f'/project/{self.project.id}/teams/{team.id}/delete/',
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(Teams.objects.filter(id=team.id).exists())

    def test_contributor_cannot_delete_team(self):
        """Contributor should not be able to delete teams"""
        team = Teams.objects.create(
            project=self.project,
            team_name='Protected Team'
        )
        self.client.login(username='contributor', password='contribpass123')
        token = generate_auth_token(self.contributor.id)

        response = self.client.post(
            f'/project/{self.project.id}/teams/{team.id}/delete/',
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Teams.objects.filter(id=team.id).exists())

    def test_owner_can_add_team_member(self):
        """Owner should be able to add team members"""
        team = Teams.objects.create(
            project=self.project,
            team_name='Dev Team'
        )
        self.client.login(username='owner', password='ownerpass123')
        token = generate_auth_token(self.owner.id)

        response = self.client.post(
            f'/project/{self.project.id}/teams/{team.id}/members/add/',
            data=json.dumps({
                'username': 'contributor',
                'role': 'EDITOR'
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(TeamMember.objects.filter(
            team=team,
            user=self.contributor
        ).exists())

    def test_cannot_add_non_contributor_to_team(self):
        """Cannot add user who isn't a project contributor to team"""
        outsider = User.objects.create_user(
            username='outsider',
            email='outsider@example.com',
            password='outsiderpass123'
        )
        team = Teams.objects.create(
            project=self.project,
            team_name='Dev Team'
        )
        self.client.login(username='owner', password='ownerpass123')
        token = generate_auth_token(self.owner.id)

        response = self.client.post(
            f'/project/{self.project.id}/teams/{team.id}/members/add/',
            data=json.dumps({
                'username': 'outsider',
                'role': 'EDITOR'
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['error'], 'User must be a contributor first')


# =============================================================================
# RBAC - DOCUMENT ACCESS TESTS
# =============================================================================

class DocumentAccessRBACTests(TestCase):
    """Tests for document access control"""

    def setUp(self):
        self.client = Client()
        self.owner = User.objects.create_user(
            username='owner',
            email='owner@example.com',
            password='ownerpass123'
        )
        self.team_member = User.objects.create_user(
            username='member',
            email='member@example.com',
            password='memberpass123'
        )
        self.non_member = User.objects.create_user(
            username='outsider',
            email='outsider@example.com',
            password='outsiderpass123'
        )
        self.project = Project.objects.create(
            owner=self.owner,
            project_name='Test Project',
            tier='team'
        )
        self.team = Teams.objects.create(
            project=self.project,
            team_name='Dev Team'
        )
        self.document = Documents.objects.create(
            project=self.project,
            document_name='Test Doc',
            content='Initial content',
            team_assigned=self.team
        )
        Contributor.objects.create(
            project=self.project,
            username='member',
            role='EDITOR'
        )
        Contributor.objects.create(
            project=self.project,
            username='outsider',
            role='VIEWER'
        )
        TeamMember.objects.create(
            team=self.team,
            user=self.team_member,
            role='EDITOR'
        )

    def test_owner_can_access_all_documents(self):
        """Owner should be able to access all documents"""
        self.client.login(username='owner', password='ownerpass123')
        token = generate_auth_token(self.owner.id)

        response = self.client.get(
            f'/project/{self.project.id}/documents/',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(len(data['documents']), 1)

    def test_team_member_can_access_team_documents(self):
        """Team member should be able to access their team's documents"""
        self.client.login(username='member', password='memberpass123')
        token = generate_auth_token(self.team_member.id)

        response = self.client.get(
            f'/project/{self.project.id}/documents/{self.document.id}/',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 200)

    def test_non_team_member_cannot_access_team_documents(self):
        """Non-team member should not be able to access team documents"""
        self.client.login(username='outsider', password='outsiderpass123')
        token = generate_auth_token(self.non_member.id)

        response = self.client.get(
            f'/project/{self.project.id}/documents/{self.document.id}/',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 403)

    def test_non_contributor_cannot_access_project(self):
        """User not on project should not access documents"""
        stranger = User.objects.create_user(
            username='stranger',
            email='stranger@example.com',
            password='strangerpass123'
        )
        self.client.login(username='stranger', password='strangerpass123')
        token = generate_auth_token(stranger.id)

        response = self.client.get(
            f'/project/{self.project.id}/documents/',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 403)


# =============================================================================
# RBAC - DOCUMENT EDITING TESTS
# =============================================================================

class DocumentEditingRBACTests(TestCase):
    """Tests for document editing permissions"""

    def setUp(self):
        self.client = Client()
        self.owner = User.objects.create_user(
            username='owner',
            email='owner@example.com',
            password='ownerpass123'
        )
        self.editor = User.objects.create_user(
            username='editor',
            email='editor@example.com',
            password='editorpass123'
        )
        self.viewer = User.objects.create_user(
            username='viewer',
            email='viewer@example.com',
            password='viewerpass123'
        )
        self.project = Project.objects.create(
            owner=self.owner,
            project_name='Test Project',
            tier='team',
            backups_enabled=True
        )
        self.team = Teams.objects.create(
            project=self.project,
            team_name='Dev Team'
        )
        self.document = Documents.objects.create(
            project=self.project,
            document_name='Test Doc',
            content='Initial content',
            team_assigned=self.team
        )
        Contributor.objects.create(
            project=self.project,
            username='editor',
            role='EDITOR'
        )
        Contributor.objects.create(
            project=self.project,
            username='viewer',
            role='VIEWER'
        )
        TeamMember.objects.create(
            team=self.team,
            user=self.editor,
            role='EDITOR',
            can_direct_save=True
        )
        TeamMember.objects.create(
            team=self.team,
            user=self.viewer,
            role='EDITOR',
            can_direct_save=False
        )

    def test_editor_with_direct_save_can_edit(self):
        """Editor with direct save permission should save directly"""
        self.client.login(username='editor', password='editorpass123')
        token = generate_auth_token(self.editor.id)
        editor_token = generate_editor_token(self.editor.id, self.project.id)

        response = self.client.post(
            f'/project/{self.project.id}/documents/{self.document.id}/save/',
            data=json.dumps({
                'content': 'Updated by editor',
                'editor_token': editor_token
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_X_EDITOR_TOKEN=editor_token
        )
        self.assertEqual(response.status_code, 200)
        self.document.refresh_from_db()
        self.assertEqual(self.document.content, 'Updated by editor')

    def test_editor_without_direct_save_creates_pending(self):
        """Editor without direct save should create pending edit"""
        self.client.login(username='viewer', password='viewerpass123')
        token = generate_auth_token(self.viewer.id)
        editor_token = generate_editor_token(self.viewer.id, self.project.id)

        response = self.client.post(
            f'/project/{self.project.id}/documents/{self.document.id}/save/',
            data=json.dumps({
                'content': 'Pending content',
                'editor_token': editor_token
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_X_EDITOR_TOKEN=editor_token
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get('pending', False))
        # Document should be unchanged
        self.document.refresh_from_db()
        self.assertEqual(self.document.content, 'Initial content')
        # Pending should exist
        self.assertTrue(Pending.objects.filter(
            document=self.document,
            user=self.viewer
        ).exists())


# =============================================================================
# INPUT VALIDATION TESTS
# =============================================================================

class InputValidationTests(TestCase):
    """Tests for input validation across endpoints"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.project = Project.objects.create(
            owner=self.user,
            project_name='Test Project',
            tier='free'
        )

    def test_invalid_project_id_type(self):
        """Non-integer project ID should fail"""
        self.client.login(username='testuser', password='testpass123')
        token = generate_auth_token(self.user.id)

        response = self.client.post(
            '/delete_project/',
            data=json.dumps({'project_id': 'abc'}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['error'], 'Invalid project ID')

    def test_negative_project_id(self):
        """Negative project ID should fail"""
        self.client.login(username='testuser', password='testpass123')
        token = generate_auth_token(self.user.id)

        response = self.client.post(
            '/delete_project/',
            data=json.dumps({'project_id': -1}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['error'], 'Invalid project ID')

    def test_invalid_role_value(self):
        """Invalid role value should fail"""
        contributor = Contributor.objects.create(
            project=self.project,
            username='other',
            role='VIEWER'
        )
        User.objects.create_user(
            username='other',
            email='other@example.com',
            password='otherpass123'
        )

        self.client.login(username='testuser', password='testpass123')
        token = generate_auth_token(self.user.id)

        response = self.client.post(
            '/change_roles/',
            data=json.dumps({
                'project_id': self.project.id,
                'contributor_id': contributor.id,
                'role': 'SUPERADMIN'  # Invalid role
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['error'], 'Invalid role')

    def test_invalid_json_body(self):
        """Invalid JSON should fail"""
        self.client.login(username='testuser', password='testpass123')
        token = generate_auth_token(self.user.id)

        response = self.client.post(
            '/delete_project/',
            data='not valid json {{{',
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['error'], 'Invalid JSON')

    def test_missing_required_fields(self):
        """Missing required fields should fail"""
        self.client.login(username='testuser', password='testpass123')
        token = generate_auth_token(self.user.id)

        response = self.client.post(
            '/add_people/',
            data=json.dumps({'project_id': self.project.id}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 400)


# =============================================================================
# TIER LIMITS TESTS
# =============================================================================

class TierLimitsTests(TestCase):
    """Tests for tier-based limits"""

    def setUp(self):
        self.client = Client()
        self.free_user = User.objects.create_user(
            username='freeuser',
            email='free@example.com',
            password='freepass123',
            Tier='free'
        )
        self.team_user = User.objects.create_user(
            username='teamuser',
            email='team@example.com',
            password='teampass123',
            Tier='team'
        )

    def test_free_tier_project_limit(self):
        """Free tier should be limited to 1 project"""
        self.client.login(username='freeuser', password='freepass123')
        token = generate_auth_token(self.free_user.id)

        # Create first project
        response = self.client.post(
            '/setup/',
            data={'project_name': 'First Project'},
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 200)

        # Try to create second project
        response = self.client.post(
            '/setup/',
            data={'project_name': 'Second Project'},
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertIn('limit reached', data['error'].lower())

    def test_free_tier_collaborator_limit(self):
        """Free tier should be limited to 3 collaborators"""
        # Create collaborator users
        for i in range(5):
            User.objects.create_user(
                username=f'collab{i}',
                email=f'collab{i}@example.com',
                password='collabpass123'
            )

        self.client.login(username='freeuser', password='freepass123')
        token = generate_auth_token(self.free_user.id)

        # Try to create project with too many collaborators
        response = self.client.post(
            '/setup/',
            data={
                'project_name': 'Test Project',
                'people': 'collab0 collab1 collab2 collab3 collab4'
            },
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertIn('limit', data['error'].lower())

    def test_team_tier_has_higher_limits(self):
        """Team tier should have higher limits"""
        # Create collaborator users
        for i in range(10):
            User.objects.create_user(
                username=f'teamcollab{i}',
                email=f'teamcollab{i}@example.com',
                password='collabpass123'
            )

        self.client.login(username='teamuser', password='teampass123')
        token = generate_auth_token(self.team_user.id)

        # Create project with more collaborators (team allows up to 20)
        collabs = ' '.join([f'teamcollab{i}' for i in range(10)])
        response = self.client.post(
            '/setup/',
            data={
                'project_name': 'Team Project',
                'people': collabs
            },
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 200)

    def test_free_tier_no_audit_logs(self):
        """Free tier should not have audit logs"""
        project = Project.objects.create(
            owner=self.free_user,
            project_name='Free Project',
            tier='free'
        )
        self.client.login(username='freeuser', password='freepass123')
        token = generate_auth_token(self.free_user.id)

        response = self.client.get(
            f'/project/{project.id}/audits/',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 403)
        data = response.json()
        self.assertIn('not available for your tier', data['error'].lower())


# =============================================================================
# AUTH TOKEN DECORATOR TESTS
# =============================================================================

class AuthTokenDecoratorTests(TestCase):
    """Tests for the require_auth_token decorator"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.project = Project.objects.create(
            owner=self.user,
            project_name='Test Project',
            tier='free'
        )

    def test_missing_token_rejected(self):
        """Request without token should be rejected"""
        self.client.login(username='testuser', password='testpass123')

        response = self.client.post(
            '/delete_project/',
            data=json.dumps({'project_id': self.project.id}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertEqual(data['error'], 'Auth token required')

    def test_invalid_token_rejected(self):
        """Request with invalid token should be rejected"""
        self.client.login(username='testuser', password='testpass123')

        response = self.client.post(
            '/delete_project/',
            data=json.dumps({'project_id': self.project.id}),
            content_type='application/json',
            HTTP_AUTHORIZATION='Bearer invalid.token.here'
        )
        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertEqual(data['error'], 'Invalid token')

    def test_get_requests_use_session_auth(self):
        """GET requests should use session auth, not token"""
        self.client.login(username='testuser', password='testpass123')

        response = self.client.get('/dashboard/')
        self.assertEqual(response.status_code, 200)


# =============================================================================
# XSS/INJECTION PREVENTION TESTS
# =============================================================================

class InjectionPreventionTests(TestCase):
    """Tests to verify XSS and injection prevention"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_xss_in_project_name_rejected(self):
        """XSS attempts in project name should be rejected"""
        self.client.login(username='testuser', password='testpass123')
        token = generate_auth_token(self.user.id)

        xss_payloads = [
            '<script>alert(1)</script>',
            'Test<img src=x onerror=alert(1)>',
            'Project&lt;script&gt;',
            "Project'; DROP TABLE projects;--",
        ]

        for payload in xss_payloads:
            response = self.client.post(
                '/setup/',
                data={'project_name': payload},
                HTTP_AUTHORIZATION=f'Bearer {token}'
            )
            self.assertEqual(
                response.status_code, 400,
                f"Should reject XSS payload: {payload}"
            )

    def test_xss_in_username_rejected(self):
        """XSS attempts in username should be rejected"""
        xss_payloads = [
            '<script>alert(1)</script>',
            'user<img src=x onerror=alert(1)>',
            "user'; DROP TABLE users;--",
        ]

        for payload in xss_payloads:
            response = self.client.post('/register/', {
                'username': payload,
                'email': 'test@example.com',
                'password': 'securepass123'
            })
            self.assertEqual(
                response.status_code, 400,
                f"Should reject XSS payload: {payload}"
            )


# =============================================================================
# EDGE CASES AND BOUNDARY TESTS
# =============================================================================

class EdgeCaseTests(TestCase):
    """Tests for edge cases and boundary conditions"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_nonexistent_project(self):
        """Operations on nonexistent projects should fail gracefully"""
        self.client.login(username='testuser', password='testpass123')
        token = generate_auth_token(self.user.id)

        response = self.client.post(
            '/delete_project/',
            data=json.dumps({'project_id': 99999}),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 404)
        data = response.json()
        self.assertEqual(data['error'], 'Project not found')

    def test_duplicate_contributor_handling(self):
        """Adding same contributor twice should be handled"""
        other_user = User.objects.create_user(
            username='other',
            email='other@example.com',
            password='otherpass123'
        )
        project = Project.objects.create(
            owner=self.user,
            project_name='Test Project',
            tier='team'
        )
        Contributor.objects.create(
            project=project,
            username='other',
            role='VIEWER'
        )

        self.client.login(username='testuser', password='testpass123')
        token = generate_auth_token(self.user.id)

        response = self.client.post(
            '/add_people/',
            data=json.dumps({
                'project_id': project.id,
                'usernames': 'other'  # Already exists
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['added_count'], 0)  # No new additions

    def test_project_name_at_max_length(self):
        """Project name at exactly max length should work"""
        self.client.login(username='testuser', password='testpass123')
        token = generate_auth_token(self.user.id)

        # 100 chars is the max
        long_name = 'A' * 100
        response = self.client.post(
            '/setup/',
            data={'project_name': long_name},
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 200)

    def test_empty_usernames_list(self):
        """Empty usernames in add_people should fail"""
        project = Project.objects.create(
            owner=self.user,
            project_name='Test Project',
            tier='free'
        )
        self.client.login(username='testuser', password='testpass123')
        token = generate_auth_token(self.user.id)

        response = self.client.post(
            '/add_people/',
            data=json.dumps({
                'project_id': project.id,
                'usernames': ''
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}'
        )
        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertEqual(data['error'], 'No usernames provided')


# =============================================================================
# CONCURRENT ACCESS TESTS
# =============================================================================

class ConcurrentAccessTests(TestCase):
    """Tests for concurrent access scenarios"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.project = Project.objects.create(
            owner=self.user,
            project_name='Test Project',
            tier='team',
            backups_enabled=True
        )
        self.team = Teams.objects.create(
            project=self.project,
            team_name='Dev Team'
        )
        self.document = Documents.objects.create(
            project=self.project,
            document_name='Test Doc',
            content='Initial content',
            team_assigned=self.team
        )

    def test_save_unchanged_content(self):
        """Saving unchanged content should be handled"""
        TeamMember.objects.create(
            team=self.team,
            user=self.user,
            role='ADMIN'
        )

        self.client.login(username='testuser', password='testpass123')
        token = generate_auth_token(self.user.id)
        editor_token = generate_editor_token(self.user.id, self.project.id)

        response = self.client.post(
            f'/project/{self.project.id}/documents/{self.document.id}/save/',
            data=json.dumps({
                'content': 'Initial content',  # Same as existing
                'editor_token': editor_token
            }),
            content_type='application/json',
            HTTP_AUTHORIZATION=f'Bearer {token}',
            HTTP_X_EDITOR_TOKEN=editor_token
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data.get('message'), 'No changes')


# =============================================================================
# STRIPE WEBHOOK TESTS
# =============================================================================

class StripeWebhookTests(TestCase):
    """Tests for Stripe webhook handling"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            Tier='free'
        )

    @patch('stripe.Webhook.construct_event')
    def test_successful_payment_upgrades_tier(self, mock_construct):
        """Successful payment should upgrade user tier"""
        mock_construct.return_value = {
            'type': 'checkout.session.completed',
            'data': {
                'object': {
                    'metadata': {
                        'user_id': str(self.user.id),
                        'plan_tier': 'team'
                    },
                    'payment_status': 'paid'
                }
            }
        }

        response = self.client.post(
            '/stripe_webhook/',
            data='{}',
            content_type='application/json',
            HTTP_STRIPE_SIGNATURE='test_signature'
        )
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.Tier, 'team')

    @patch('stripe.Webhook.construct_event')
    def test_invalid_signature_rejected(self, mock_construct):
        """Invalid webhook signature should be rejected"""
        mock_construct.side_effect = stripe.error.SignatureVerificationError(
            'Invalid signature', 'sig'
        )

        response = self.client.post(
            '/stripe_webhook/',
            data='{}',
            content_type='application/json',
            HTTP_STRIPE_SIGNATURE='bad_signature'
        )
        self.assertEqual(response.status_code, 400)


# =============================================================================
# HELPER FUNCTION TO RUN TESTS
# =============================================================================

if __name__ == '__main__':
    import django
    django.setup()
    from django.test.utils import get_runner
    from django.conf import settings

    TestRunner = get_runner(settings)
    test_runner = TestRunner()
    failures = test_runner.run_tests(["__main__"])