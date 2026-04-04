from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie, csrf_protect
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.cache import cache_page
from django.db import transaction
from django.db.models import Q, F
from django.conf import settings
import stripe
import secrets
import string
import json
import jwt
from django.core.cache import cache
from datetime import datetime, timedelta
from django_ratelimit.decorators import ratelimit
from functools import wraps
from .forms import LoginForm, RegisterForm

from django.contrib.auth import update_session_auth_hash
from .models import Project, Contributor, Pending, User, Backup, Audit, Documents, Teams, TeamMember, Changelog, \
    PendingAction, ViewerDocumentAccess, InviteCode
from .views_emails import send_welcome_email, send_subscription_email, send_cancellation_email, send_password_reset_email
from .r2_backups import backup_document_to_r2, restore_document_from_backup
import re
import difflib
from django.utils.html import escape as html_escape

import logging
logger = logging.getLogger(__name__)

PROJECT_NAME_REGEX = re.compile(r'^[a-zA-Z0-9\s@#$!]+$')
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_@#$!]+$')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


ERROR_PAGES = {
    400: {
        'error_code': '400',
        'error_title': 'Bad request.',
        'error_desc': 'Something about that request didn\'t make sense. Double-check and try again.',
    },
    401: {
        'error_code': '401',
        'error_title': 'Not authenticated.',
        'error_desc': 'You need to be logged in to access this. Sign in and try again.',
    },
    403: {
        'error_code': '403',
        'error_title': 'Access denied.',
        'error_desc': 'You don\'t have permission to be here. If this is a mistake, contact support.',
    },
    404: {
        'error_code': '404',
        'error_title': 'Page not found.',
        'error_desc': 'Whatever you were looking for isn\'t here. It may have been moved or deleted.',
    },
    408: {
        'error_code': '408',
        'error_title': 'Request timed out.',
        'error_desc': 'The server waited too long for your request. Check your connection and try again.',
    },
    413: {
        'error_code': '413',
        'error_title': 'That\'s too heavy.',
        'error_desc': 'The request body exceeds the maximum allowed size. Try sending less data.',
    },
    429: {
        'error_code': '429',
        'error_title': 'Slow down there.',
        'error_desc': 'You\'re sending too many requests. Take a breath and try again in a moment.',
    },
    500: {
        'error_code': '500',
        'error_title': 'Something went wrong.',
        'error_desc': 'An unexpected error occurred on our end. We\'re probably already looking into it.',
    },
    502: {
        'error_code': '502',
        'error_title': 'Something broke upstream.',
        'error_desc': 'The server received an invalid response. We\'re probably already on it.',
    },
    503: {
        'error_code': '503',
        'error_title': 'Service unavailable.',
        'error_desc': 'We\'re temporarily offline for maintenance or overloaded. Try again shortly.',
    },
}

def sanitize_string(value, max_length, pattern, field_name):
    if not isinstance(value, str):
        return None, f'{field_name} must be a string'

    value = value.strip()

    if not value:
        return None, f'{field_name} is required'

    if len(value) > max_length:
        return None, f'{field_name} too long (max {max_length} characters)'

    if not pattern.match(value):
        return None, f'{field_name} contains invalid characters'

    return value, None


JWT_PRIVATE_KEY = settings.JWT_PRIVATE_KEY
JWT_PUBLIC_KEY = settings.JWT_PUBLIC_KEY
JWT_EXPIRY_HOURS = 1

if not JWT_PRIVATE_KEY or not JWT_PUBLIC_KEY:
    raise ValueError("JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required for RS384 authentication")

stripe.api_key = settings.STRIPE_SECRET_KEY
stripe.public_key = settings.STRIPE_PUBLIC_KEY

TIER_LIMITS = {
    'free': {'projects': 2, 'documents': 5, 'teams': 2, 'members': 3, 'collaborations': 2,
             'backups': False, 'audit': False, 'pending': False},
    'personal': {'projects': 4, 'documents': 10, 'teams': 4, 'members': 6, 'collaborations': 5,
                 'backups': True, 'audit': False, 'pending': False},
    'team': {'projects': 8, 'documents': 20, 'teams': 6, 'members': 20, 'collaborations': 8,
             'backups': True, 'audit': True, 'pending': True},
    'enterprise': {'projects': None, 'documents': None, 'teams': None, 'members': None, 'collaborations': None,
                   'backups': True, 'audit': True, 'pending': True},
}


@require_GET
@ratelimit(key='ip', rate='10/m', block=True)
def get_oauth_token(request):
    try:
        if not request.user.is_authenticated:
            return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)

        token = generate_auth_token(request.user.id)
        return JsonResponse({'success': True, 'token': token})
    except Exception:
        logger.exception("get_oauth_token failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


def generate_auth_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_PRIVATE_KEY, algorithm='RS384')


def verify_auth_token(token, verify_expiration=True):
    try:
        return jwt.decode(token, JWT_PUBLIC_KEY, algorithms=['RS384'], options={'verify_exp': verify_expiration})
    except jwt.ExpiredSignatureError:
        return 'expired'
    except jwt.InvalidTokenError:
        return 'invalid'


def require_auth_token(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            if not request.user.is_authenticated:
                return redirect('login')
            return view_func(request, *args, **kwargs)
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return JsonResponse({'success': False, 'error': 'Auth token required'}, status=401)
        payload = verify_auth_token(token)
        if payload is None:
            return JsonResponse({'success': False, 'error': 'Invalid token'}, status=401)
        if payload == 'expired':
            expired_payload = verify_auth_token(token, verify_expiration=False)
            if expired_payload and expired_payload != 'expired':
                token = generate_auth_token(expired_payload['user_id'])
                return JsonResponse({'success': False, 'error': 'Token expired', 'new_token': token}, status=401)
            return JsonResponse({'success': False, 'error': 'Invalid token'}, status=401)
        if payload == 'invalid':
            return JsonResponse({'success': False, 'error': 'Invalid token'}, status=401)
        try:
            user = request.user
            if not user:
                return JsonResponse({'success': False, 'error': 'User not found'}, status=404)
            return view_func(request, *args, **kwargs)
        except jwt.PyJWTError as e:
            return JsonResponse({'success': False, 'error': 'Please try again later'}, status=401)

    return wrapper


@require_GET
@ratelimit(key='ip', rate='30/m', block=True)
def dashboard(request):
    if not request.user.is_authenticated:
        return redirect('login')

    try:
        projects = Project.objects.filter(owner_id=request.user.id).order_by('-created_at')
        return render(request, 'dashboard.html', {'projects': projects})
    except Exception:
        logger.exception("dashboard failed")
        return render_error(request, 500)


@require_auth_token
@login_required(login_url='/login')
@ratelimit(key='ip', rate='10/m', block=True)
def setup(request):
    if request.method == 'GET':
        try:
            user_tier = request.user.Tier
            tier_config = TIER_LIMITS.get(user_tier, TIER_LIMITS['free'])
            return render(request, 'setup.html', {'tier': user_tier, 'tier_config': tier_config})
        except Exception:
            logger.exception("setup failed")
            return render_error(request, 500)

    try:
        user_tier = request.user.Tier
        if user_tier not in TIER_LIMITS:
            return JsonResponse({'success': False, 'error': 'Invalid tier contact support'}, status=400)

        tier_config = TIER_LIMITS.get(user_tier, TIER_LIMITS['free'])

        project_name, error = sanitize_string(
            request.POST.get('project_name', ''),
            max_length=100,
            pattern=PROJECT_NAME_REGEX,
            field_name='Project name'
        )
        if error:
            return JsonResponse({'success': False, 'error': error}, status=400)

        backups_raw = request.POST.get('backups', '')
        if backups_raw not in ('', 'true', 'false', '1', '0', 'on', 'off', True, False):
            return JsonResponse({'success': False, 'error': 'Invalid backups value'}, status=400)

        backups_enabled = backups_raw in ('true', '1', 'on', True) and tier_config.get('backups', False)

        current_project_count = Project.objects.filter(owner=request.user).count()
        max_projects = tier_config.get('projects')
        if max_projects is not None and current_project_count >= max_projects:
            return JsonResponse({'success': False, 'error': 'Project limit reached for your tier'}, status=403)

        with transaction.atomic():
            project = Project.objects.create(
                owner=request.user,
                project_name=project_name,
                people='',
                backups_enabled=backups_enabled,
                tier=user_tier,
            )

            public_team = Teams.objects.create(
                project=project,
                team_name='Public',
            )

            Documents.objects.create(
                project=project,
                document_name='Getting Started',
                content='',
                team_assigned=public_team,
            )

        return JsonResponse({'success': True, 'redirect': '/dashboard/'})
    except Exception:
        logger.exception("setup failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='5/m', block=True)
def change_roles(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        project_id = data.get('project_id')
        contributor_id = data.get('contributor_id')
        new_role = data.get('role', '')

        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        if not isinstance(new_role, str):
            return JsonResponse({'success': False, 'error': 'Invalid role type'}, status=400)

        new_role = new_role.upper().strip()

        if new_role not in ('VIEWER', 'EDITOR', 'ADMIN'):
            return JsonResponse({'success': False, 'error': 'Invalid role'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        is_owner = request.user.id == project.owner_id
        is_admin_contributor = False

        if not is_owner:
            is_admin_contributor = Contributor.objects.filter(
                project_id=project_id,
                username=request.user.username,
                role='ADMIN'
            ).exists()

        if not is_owner and not is_admin_contributor:
            return JsonResponse({'success': False, 'error': 'Permission denied'}, status=403)

        if is_admin_contributor and not is_owner:
            target = Contributor.objects.filter(id=contributor_id, project_id=project_id).first()
            if not target:
                return JsonResponse({'success': False, 'error': 'Contributor not found'}, status=404)
            if target.role == 'ADMIN':
                return JsonResponse({'success': False, 'error': 'Only project owner can change admin roles'}, status=403)
            if new_role == 'ADMIN':
                return JsonResponse({'success': False, 'error': 'Only project owner can assign admin role'}, status=403)

        updated = Contributor.objects.filter(id=contributor_id, project_id=project_id).update(role=new_role)

        if not updated:
            return JsonResponse({'success': False, 'error': 'Contributor not found'}, status=404)

        return JsonResponse({'success': True})
    except Exception:
        logger.exception("change_roles failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@ratelimit(key='ip', rate='5/m', block=True)
@require_POST
@require_auth_token
def add_people(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        project_id = data.get('project_id')
        usernames = data.get('usernames', '')

        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        if not isinstance(usernames, str):
            return JsonResponse({'success': False, 'error': 'Invalid usernames format'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        if request.user.id != project.owner.id:
            return JsonResponse({'success': False, 'error': 'Permission denied'}, status=403)

        people = list({p.strip() for p in usernames.split() if p.strip()})

        if not people:
            return JsonResponse({'success': False, 'error': 'No usernames provided'}, status=400)

        for username in people:
            if not USERNAME_REGEX.match(username):
                return JsonResponse({'success': False, 'error': f'Invalid username format: {username}'}, status=400)
            if not User.objects.filter(username=username).exists():
                return JsonResponse({'success': False, 'error': f'User {username} not found'}, status=404)

        user_tier = request.user.Tier
        tier_config = TIER_LIMITS.get(user_tier, TIER_LIMITS['free'])
        max_collaborators = tier_config.get('members')

        current_count = Contributor.objects.filter(project_id=project_id).count()
        if max_collaborators is not None and (current_count + len(people)) > max_collaborators:
            return JsonResponse({'success': False, 'error': f'Collaborator limit is {max_collaborators} for your tier'},
                                status=403)

        existing = set(
            Contributor.objects.filter(project_id=project_id, username__in=people).values_list('username', flat=True)
        )
        new_people = [p for p in people if p not in existing]

        for username in new_people:
            target_user = User.objects.filter(username=username).first()
            if not target_user:
                return JsonResponse({'success': False, 'error': f'User {username} not found'}, status=404)
            target_tier = target_user.Tier.lower()
            target_tier_config = TIER_LIMITS.get(target_tier, TIER_LIMITS['free'])
            max_collaborations = target_tier_config.get('collaborations')
            if max_collaborations is not None:
                current_collaborations = Contributor.objects.filter(username=username).count()
                if current_collaborations >= max_collaborations:
                    return JsonResponse({
                        'success': False,
                        'error': f'{username} has reached their collaboration limit ({max_collaborations} projects) for their tier'
                    }, status=403)

        if new_people:
            created = Contributor.objects.bulk_create(
                [Contributor(project_id=project_id, username=p, role=data.get('role', 'VIEWER')) for p in new_people]
            )
            contributors = [{'id': c.id, 'username': c.username, 'role': c.role} for c in created]
        else:
            contributors = []

        return JsonResponse({'success': True, 'added_count': len(new_people), 'contributors': contributors})
    except Exception:
        logger.exception("add_people failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@cache_page(60 * 15)
@require_GET
def about(request):
    return render(request, 'about.html')


@require_GET
@cache_page(60 * 15)
def docs(request):
    return render(request, 'docs.html')


@require_GET
@cache_page(60 * 15)
def changelog(request):
    try:
        changelogs = Changelog.objects.all().order_by('-created_at')
        return render(request, 'changelog.html', {'changelogs': changelogs})
    except Exception:
        logger.exception("changelog failed")
        return render_error(request, 500)


@ratelimit(key='ip', rate='5/m', block=True)
def login(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'GET':
        return render(request, 'login.html', {'form': LoginForm()})

    try:
        form = LoginForm(request.POST)
        if not form.is_valid():
            return JsonResponse({'success': False, 'error': 'Invalid form data'}, status=400)

        username = form.cleaned_data['username']
        password = form.cleaned_data['password']

        if not username or not password:
            return JsonResponse({'success': False, 'error': 'Invalid credentials'}, status=401)

        if not USERNAME_REGEX.match(username):
            return JsonResponse({'success': False, 'error': 'Invalid credentials'}, status=401)

        if not re.search(r'[A-Za-z]', username):
            return JsonResponse({'success': False, 'error': 'Invalid credentials'}, status=401)

        user = authenticate(request, username=username, password=password)

        if user is None:
            return JsonResponse({'success': False, 'error': 'Invalid credentials'}, status=401)

        auth_login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        token = generate_auth_token(request.user.id)
        return JsonResponse({'success': True, 'redirect': '/dashboard/', 'token': token})

    except Exception:
        logger.exception("login failed")
        return JsonResponse({'success': False, 'error': 'Server error'}, status=500)


@ratelimit(key='ip', rate='5/m', block=True)
def register(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'GET':
        return render(request, 'register.html', {'form': RegisterForm()})

    try:
        form = RegisterForm(request.POST)
        if not form.is_valid():
            return JsonResponse({'success': False, 'error': 'Invalid form data'}, status=400)

        username = form.cleaned_data['username']
        email = form.cleaned_data['email']
        password = form.cleaned_data['password']

        if not isinstance(username, str) or not isinstance(email, str) or not isinstance(password, str):
            return JsonResponse({'success': False, 'error': 'Invalid input types'}, status=400)

        username = username.strip()
        email = email.strip().lower()
        password = password.strip()

        if not username or not email or not password:
            return JsonResponse({'success': False, 'error': 'All fields required'}, status=400)

        if not USERNAME_REGEX.match(username):
            return JsonResponse({'success': False, 'error': 'Invalid username format'}, status=400)

        if not re.search(r'[A-Za-z]', username):
            return JsonResponse({'success': False, 'error': 'Username must contain letters'}, status=400)

        if len(username) < 3 or len(username) > 30:
            return JsonResponse({'success': False, 'error': 'Username must be 3-30 characters'}, status=400)

        if not EMAIL_REGEX.match(email):
            return JsonResponse({'success': False, 'error': 'Invalid email format'}, status=400)

        if len(password) < 6:
            return JsonResponse({'success': False, 'error': 'Password must be at least 6 characters'}, status=400)

        existing = User.objects.filter(
            Q(username=username) | Q(email=email)
        ).values('username', 'email').first()

        if existing:
            if existing['username'] == username:
                return JsonResponse({'success': False, 'error': 'Username taken'}, status=400)
            return JsonResponse({'success': False, 'error': 'Email taken'}, status=400)

        user = User.objects.create_user(username=username, password=password, email=email)
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        auth_login(request, user)
        token = generate_auth_token(request.user.id)
        send_welcome_email.delay(username, email)
        return JsonResponse({'success': True, 'redirect': '/dashboard/', 'token': token})

    except Exception:
        logger.exception("register failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@ratelimit(key='ip', rate='10/m', block=True)
def logout_view(request):
    auth_logout(request)
    return redirect('login')


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def deleteuser(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        project_id = data.get('project_id')
        contributor_id = data.get('contributor_id')

        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        if not isinstance(contributor_id, int) or contributor_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid contributor ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        if request.user.id != project.owner.id:
            return JsonResponse({'success': False, 'error': 'Permission denied'}, status=403)

        contributor = Contributor.objects.filter(id=contributor_id, project_id=project_id).first()

        if not contributor:
            return JsonResponse({'success': False, 'error': 'Contributor not found'}, status=404)

        contributor.delete()

        return JsonResponse({'success': True})
    except Exception:
        logger.exception("deleteuser failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@ratelimit(key='ip', rate='30/m', block=True)
def project_detail(request, project_id):
    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return render_error(request, 404)
    except Exception:
        logger.exception("project_detail failed")
        return render_error(request, 500)

    is_owner = project.owner_id == request.user.id
    contributor = None
    role = 'OWNER' if is_owner else None

    if not is_owner:
        contributor = Contributor.objects.filter(
            project_id=project_id,
            username=request.user.username
        ).values('role').first()

        if not contributor:
            return render_error(request, 403)

        role = contributor['role']

    return render(request, 'edit.html', {
        'project': project,
        'is_owner': is_owner,
        'role': role,
    })


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='5/m', block=True)
def delete_project(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        project_id = data.get('project_id')

        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        if request.user.id != project.owner_id:
            return JsonResponse({'success': False, 'error': 'Permission denied'}, status=403)

        project.delete()

        return JsonResponse({'success': True})
    except Exception:
        logger.exception("delete_project failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def list_project_backups(request, project_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()
        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        tier = project.tier.lower()
        tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])
        if not tier_config.get('backups', False):
            return JsonResponse({'success': False, 'error': 'Backups not available for this tier'}, status=403)

        if not project.backups_enabled:
            return JsonResponse({
                'success': True,
                'disabled': True,
                'message': 'Backups are turned off. Earlier snapshots are preserved and will be available when backups are re-enabled.',
                'backups': []
            })

        is_owner = project.owner_id == request.user.id
        can_see_all = False
        allowed_team_ids = []

        if is_owner:
            can_see_all = True
        else:
            is_project_admin = Contributor.objects.filter(
                project_id=project_id,
                username=request.user.username,
                role='ADMIN'
            ).exists()

            if is_project_admin:
                can_see_all = True
            else:
                admin_teams = TeamMember.objects.filter(
                    team__project_id=project_id,
                    user=request.user,
                    role='ADMIN'
                ).values_list('team_id', flat=True)

                allowed_team_ids = list(admin_teams)
                if not allowed_team_ids:
                    return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        if can_see_all:
            backups = Backup.objects.filter(
                project_id=project_id
            ).select_related('document').order_by('-created_at')
        else:
            backups = Backup.objects.filter(
                project_id=project_id,
                document__team_assigned_id__in=allowed_team_ids
            ).select_related('document').order_by('-created_at')

        data = [{
            'id': b.id,
            'document_id': b.document_id,
            'document_name': b.document.document_name,
            'version': b.version,
            'created_at': b.created_at.isoformat(),
        } for b in backups[:100]]

        return JsonResponse({'success': True, 'backups': data})
    except Exception:
        logger.exception("list_project_backups failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


_HTML_TAG_RE = re.compile(r'<[^>]+>')

def _strip_html(text):
    text = _HTML_TAG_RE.sub(' ', text)
    return ' '.join(text.split())

def _generate_side_by_side_diff_html(current_text, proposed_text, current_label='Current', proposed_label='Proposed'):
    current_words = _strip_html(current_text).split()
    proposed_words = _strip_html(proposed_text).split()
    sm = difflib.SequenceMatcher(None, current_words, proposed_words)

    left_parts = []
    right_parts = []
    has_changes = False

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            text = html_escape(' '.join(current_words[i1:i2]))
            left_parts.append(text)
            right_parts.append(text)
        elif tag == 'replace':
            has_changes = True
            old = html_escape(' '.join(current_words[i1:i2]))
            new = html_escape(' '.join(proposed_words[j1:j2]))
            left_parts.append(f'<span class="diff-del">{old}</span>')
            right_parts.append(f'<span class="diff-add">{new}</span>')
        elif tag == 'delete':
            has_changes = True
            old = html_escape(' '.join(current_words[i1:i2]))
            left_parts.append(f'<span class="diff-del">{old}</span>')
        elif tag == 'insert':
            has_changes = True
            new = html_escape(' '.join(proposed_words[j1:j2]))
            right_parts.append(f'<span class="diff-add">{new}</span>')

    if not has_changes:
        return '<div class="diff-no-changes">No differences found</div>'

    left_html = ' '.join(left_parts)
    right_html = ' '.join(right_parts)

    return f'''
    <div class="diff-container">
        <div class="diff-side">
            <div class="diff-side-header diff-side-current">{html_escape(current_label)}</div>
            <div class="diff-side-content">{left_html}</div>
        </div>
        <div class="diff-side">
            <div class="diff-side-header diff-side-proposed">{html_escape(proposed_label)}</div>
            <div class="diff-side-content">{right_html}</div>
        </div>
    </div>'''


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def pending_diff(request, project_id, pending_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)
        if not isinstance(pending_id, int) or pending_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid pending ID'}, status=400)

        pending = Pending.objects.select_related('project', 'document', 'user').filter(
            id=pending_id, project_id=project_id
        ).first()

        if not pending:
            return JsonResponse({'success': False, 'error': 'Pending edit not found'}, status=404)

        project = pending.project
        is_owner = project.owner_id == request.user.id
        can_view = False

        if is_owner:
            can_view = True
        else:
            is_project_admin = Contributor.objects.filter(
                project_id=project_id, username=request.user.username, role='ADMIN'
            ).exists()
            if is_project_admin:
                can_view = True
            else:
                is_team_admin = TeamMember.objects.filter(
                    team_id=pending.team_id, user=request.user, role='ADMIN'
                ).exists()
                if is_team_admin:
                    can_view = True

        if not can_view:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        document = pending.document
        if not document:
            return JsonResponse({'success': False, 'error': 'Document no longer exists'}, status=404)

        current_content = document.content or ''
        proposed_content = pending.submitted_content or ''

        diff_html = _generate_side_by_side_diff_html(current_content, proposed_content, 'Current', 'Proposed')

        return JsonResponse({
            'success': True,
            'diff_html': diff_html,
            'document_name': document.document_name,
            'username': pending.user.username,
        })
    except Exception:
        logger.exception("pending_diff failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='20/m', block=True)
def backup_diff(request, project_id, backup_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)
        if not isinstance(backup_id, int) or backup_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid backup ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()
        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        tier = project.tier.lower()
        tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])
        if not tier_config.get('backups', False):
            return JsonResponse({'success': False, 'error': 'Backups not available for this tier'}, status=403)

        is_owner = project.owner_id == request.user.id
        can_view = False

        if is_owner:
            can_view = True
        else:
            is_project_admin = Contributor.objects.filter(
                project_id=project_id, username=request.user.username, role='ADMIN'
            ).exists()
            if is_project_admin:
                can_view = True
            else:
                admin_teams = TeamMember.objects.filter(
                    team__project_id=project_id, user=request.user, role='ADMIN'
                ).values_list('team_id', flat=True)
                if admin_teams.exists():
                    can_view = True

        if not can_view:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        backup = Backup.objects.select_related('document').filter(
            id=backup_id, project_id=project_id
        ).first()

        if not backup:
            return JsonResponse({'success': False, 'error': 'Backup not found'}, status=404)

        document = backup.document
        current_content = document.content or ''

        response = settings.R2_CLIENT.get_object(
            Bucket=settings.R2_BUCKET_NAME,
            Key=backup.r2_key,
        )
        payload = json.loads(response['Body'].read().decode('utf-8'))
        backup_content = payload.get('content', '')

        diff_html = _generate_side_by_side_diff_html(
            current_content, backup_content, 'Current', f'Backup v{backup.version}'
        )

        return JsonResponse({
            'success': True,
            'diff_html': diff_html,
            'document_name': document.document_name,
            'version': backup.version,
        })
    except Exception:
        logger.exception("backup_diff failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@csrf_protect
@ratelimit(key='ip', rate='5/m', block=True)
def revert_backup(request, project_id, backup_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)
        if not isinstance(backup_id, int) or backup_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid backup ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()
        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        tier = project.tier.lower()
        tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])
        if not tier_config.get('backups', False):
            return JsonResponse({'success': False, 'error': 'Backups not available for this tier'}, status=403)

        if not project.backups_enabled:
            return JsonResponse({'success': False, 'error': 'Backups are currently turned off'}, status=403)

        backup = Backup.objects.filter(
            id=backup_id, project_id=project_id
        ).select_related('document', 'document__team_assigned').first()

        if not backup:
            return JsonResponse({'success': False, 'error': 'Backup not found'}, status=404)

        is_owner = project.owner_id == request.user.id
        can_revert = False

        if is_owner:
            can_revert = True
        else:
            is_project_admin = Contributor.objects.filter(
                project_id=project_id,
                username=request.user.username,
                role='ADMIN'
            ).exists()

            if is_project_admin:
                can_revert = True
            else:
                is_team_admin = TeamMember.objects.filter(
                    team_id=backup.document.team_assigned_id,
                    user=request.user,
                    role='ADMIN'
                ).exists()

                if is_team_admin:
                    can_revert = True

        if not can_revert:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        try:
            restore_document_from_backup(backup.id)
        except Exception:
            logger.exception("revert_backup failed")
            return JsonResponse({'success': False, 'error': 'Failed to restore backup'}, status=500)

        if tier_config.get('audit', False):
            Audit.objects.create(
                project=project,
                document=backup.document,
                user=request.user,
                action=f'revert:v{backup.version}'
            )

        return JsonResponse({
            'success': True,
            'document_id': backup.document_id,
            'version': backup.version
        })
    except Exception:
        logger.exception("revert_backup failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@csrf_protect
@ratelimit(key='ip', rate='10/m', block=True)
def toggle_backups(request, project_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()
        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        if request.user.id != project.owner_id:
            return JsonResponse({'success': False, 'error': 'Only the project owner can toggle backups'}, status=403)

        tier = project.tier.lower()
        tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])
        if not tier_config.get('backups', False):
            return JsonResponse({'success': False, 'error': 'Backups not available for this tier'}, status=403)

        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

        enabled = data.get('enabled')
        if not isinstance(enabled, bool):
            return JsonResponse({'success': False, 'error': 'Invalid value for enabled'}, status=400)

        project.backups_enabled = enabled
        project.save(update_fields=['backups_enabled'])

        return JsonResponse({'success': True, 'backups_enabled': enabled})
    except Exception:
        logger.exception("toggle_backups failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@csrf_protect
@ratelimit(key='ip', rate='10/m', block=True)
def rename_project(request, project_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()
        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        if request.user.id != project.owner_id:
            return JsonResponse({'success': False, 'error': 'Only the project owner can rename the project'}, status=403)

        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

        raw_name = data.get('project_name', '')
        project_name, err = sanitize_string(raw_name, 100, PROJECT_NAME_REGEX, 'Project name')
        if err:
            return JsonResponse({'success': False, 'error': err}, status=400)

        project.project_name = project_name
        project.save(update_fields=['project_name'])

        return JsonResponse({'success': True, 'project_name': project_name})
    except Exception:
        logger.exception("rename_project failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_collaborators(request, project_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()
        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        is_owner = project.owner_id == request.user.id
        if not is_owner:
            is_admin = Contributor.objects.filter(
                project_id=project_id,
                username=request.user.username,
                role='ADMIN'
            ).exists()
            if not is_admin:
                return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        contributors = Contributor.objects.filter(project_id=project_id).order_by('added_at')
        data = [{
            'id': c.id,
            'username': c.username,
            'role': c.role,
            'added_at': c.added_at.isoformat(),
        } for c in contributors]

        return JsonResponse({'success': True, 'collaborators': data})
    except Exception:
        logger.exception("get_collaborators failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def handle_pending(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        pending_id = data.get('pending_id')
        action = data.get('action', '').lower()

        if not isinstance(pending_id, int) or pending_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid pending ID'}, status=400)

        if action not in ('accept', 'reject'):
            return JsonResponse({'success': False, 'error': 'Invalid action. Must be accept or reject'}, status=400)

        with transaction.atomic():
            pending = Pending.objects.select_related(
                'project', 'document', 'team', 'user'
            ).filter(id=pending_id).first()

            if not pending:
                return JsonResponse({'success': False, 'error': 'Pending edit not found'}, status=404)

            project = pending.project
            is_owner = project.owner_id == request.user.id

            can_handle = False

            if is_owner:
                can_handle = True
            else:
                is_project_admin = Contributor.objects.filter(
                    project_id=project.id,
                    username=request.user.username,
                    role='ADMIN'
                ).exists()

                if is_project_admin:
                    can_handle = True
                else:
                    is_team_admin = TeamMember.objects.filter(
                        team_id=pending.team_id,
                        user=request.user,
                        role='ADMIN'
                    ).exists()

                    if is_team_admin:
                        can_handle = True

            if not can_handle:
                return JsonResponse({'success': False, 'error': 'Not authorized to handle this pending edit'}, status=403)

            tier = project.tier.lower()
            tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])

            document = pending.document
            pending_user = pending.user
            document_name = document.document_name if document else 'Unknown'
            pending_note = pending.note

            if action == 'accept':
                if not document:
                    return JsonResponse({'success': False, 'error': 'Document no longer exists'}, status=404)

                document = Documents.objects.select_for_update().get(id=document.id)

                if project.backups_enabled and tier_config.get('backups', False):
                    backup_document_to_r2.delay(document.id)

                document.content = pending.submitted_content
                document.save(update_fields=['content'])

                if tier_config.get('audit', False):
                    Audit.objects.create(
                        project=project,
                        document=document,
                        user=pending_user,
                        action='edit'
                    )

            PendingAction.objects.create(
                project=project,
                document=document if document else None,
                pending_user=pending_user,
                actioned_by=request.user,
                action=action,
                document_name=document_name,
                pending_note=pending_note
            )

            if tier_config.get('audit', False):
                Audit.objects.create(
                    project=project,
                    document=document if document else None,
                    user=request.user,
                    action=f'pending_{action}'
                )

            pending.delete()

        return JsonResponse({
            'success': True,
            'action': action,
            'document_id': document.id if document else None,
            'document_name': document_name
        })
    except Exception:
        logger.exception("handle_pending failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@ratelimit(key='ip', rate='30/m', block=True)
def collaborations(request):
    try:
        collaborated_projects = Contributor.objects.filter(
            username=request.user.username
        ).select_related('project').order_by('-project__created_at')

        return render(request, 'collaborations.html', {'collaborated_projects': collaborated_projects})
    except Exception:
        logger.exception("collaborations failed")
        return render_error(request, 500)


@csrf_protect
@ratelimit(key='ip', rate='10/m', block=True)
@login_required
def logout(request):
    auth_logout(request)
    return redirect('login')


@ratelimit(key='ip', rate='30/m', block=True)
def home(request):
    context = {}
    alert_raw = cache.get('broadcast:alert')
    if alert_raw:
        try:
            context['broadcast_alert'] = json.loads(alert_raw)
        except (json.JSONDecodeError, TypeError):
            pass
    return render(request, 'index.html', context)


PRICE_IDS = {
    'personal': settings.STRIPE_PERSONAL_PRICE_ID,
    'team': settings.STRIPE_TEAM_PRICE_ID,
    'enterprise': settings.STRIPE_ENTERPRISE_PRICE_ID,
}

@login_required
@require_POST
@transaction.atomic
@ratelimit(key='ip', rate='5/m', block=True)
def create_checkout_session(request):
    try:
        tier = request.POST.get('tier')

        if tier not in PRICE_IDS:
            return JsonResponse({'success': False, 'error': 'Invalid tier'}, status=400)

        try:
            if request.user.stripe_customer_id:
                customer_id = request.user.stripe_customer_id
            else:
                customer = stripe.Customer.create(
                    email=request.user.email,
                    metadata={'user_id': str(request.user.id)},
                )
                customer_id = customer.id
                request.user.stripe_customer_id = customer_id
                request.user.save(update_fields=['stripe_customer_id'])

            existing_subs = stripe.Subscription.list(
                customer=customer_id,
                status='active',
                limit=10
            )

            if existing_subs.data:
                for sub in existing_subs.auto_paging_iter():
                    try:
                        stripe.Subscription.cancel(sub.id)
                    except stripe.error.StripeError:
                        logger.exception(
                            f"Failed to cancel old sub {sub.id} for user {request.user.id} "
                            f"on customer {customer_id}"
                        )

            subscription = stripe.Subscription.create(
                customer=customer_id,
                items=[{'price': PRICE_IDS[tier]}],
                payment_behavior='default_incomplete',
                expand=['latest_invoice.confirmation_secret'],
                metadata={
                    'user_id': str(request.user.id),
                    'tier': tier,
                },
            )

            return JsonResponse({
                'client_secret': subscription.latest_invoice.confirmation_secret.client_secret,
                'subscription_id': subscription.id,
            })

        except stripe.error.StripeError as e:
            logger.exception("Stripe error in create_checkout_session")
            return JsonResponse({'success': False, 'error': str(e)}, status=503)
    except Exception:
        logger.exception("create_checkout_session failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)



@csrf_exempt
@require_POST
def stripe_webhook(request):
    payload = request.body
    sig_header = request.headers.get('Stripe-Signature', '')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        return HttpResponse(status=400)
    except stripe.error.SignatureVerificationError:
        return HttpResponse(status=400)

    if event['type'] == 'customer.subscription.created':
        subscription = event['data']['object']
        customer_id = subscription.get('customer')

        if customer_id:
            try:
                user = User.objects.get(stripe_customer_id=customer_id)
            except User.DoesNotExist:
                customer = stripe.Customer.retrieve(customer_id)
                email = customer.get('email')
                if email:
                    try:
                        user = User.objects.get(email=email)
                        user.stripe_customer_id = customer_id
                        user.save(update_fields=['stripe_customer_id'])
                    except User.DoesNotExist:
                        return HttpResponse(status=200)
                else:
                    return HttpResponse(status=200)

    elif event['type'] == 'invoice.paid':
        invoice = event['data']['object']
        customer_id = invoice.get('customer')
        subscription_id = invoice.get('subscription')

        tier = None
        if subscription_id:
            sub = stripe.Subscription.retrieve(subscription_id)
            tier = sub.metadata.get('tier')
            if not tier:
                items = sub.get('items', {}).get('data', [])
                if items:
                    price_id = items[0].get('price', {}).get('id')
                    tier = {
                        settings.STRIPE_PERSONAL_PRICE_ID: 'personal',
                        settings.STRIPE_TEAM_PRICE_ID: 'team',
                        settings.STRIPE_ENTERPRISE_PRICE_ID: 'enterprise',
                    }.get(price_id)

        if customer_id:
            try:
                user = User.objects.get(stripe_customer_id=customer_id)
                if tier:
                    user.Tier = tier
                    Project.objects.filter(owner=user).update(tier=tier)
                user.subscription_status = 'active'
                user.retries_left = 0
                user.save(update_fields=['Tier', 'subscription_status', 'retries_left'])
            except User.DoesNotExist:
                if tier:
                    try:
                        user = User.objects.get(email=invoice.get('customer_email'))
                        user.Tier = tier
                        user.stripe_customer_id = customer_id
                        user.subscription_status = 'active'
                        user.retries_left = 0
                        Project.objects.filter(owner=user).update(tier=tier)
                        user.save(update_fields=['Tier', 'stripe_customer_id', 'subscription_status', 'retries_left'])
                    except User.DoesNotExist:
                        pass

            # duplicate detection — only log when something is actually wrong
            active_subs = stripe.Subscription.list(
                customer=customer_id,
                status='active'
            )
            if len(active_subs.data) > 1:
                logger.critical(
                    f"DUPLICATE SUBS: User {user.id} has {len(active_subs.data)} "
                    f"active subs on customer {customer_id}. "
                    f"Sub IDs: {[s.id for s in active_subs.data]}"
                )
    elif event['type'] == 'invoice.payment_failed':
        invoice = event['data']['object']
        customer_id = invoice.get('customer')

        if customer_id:
            try:
                user = User.objects.get(stripe_customer_id=customer_id)

                if user.Tier == 'free':
                    return HttpResponse(status=200)

                user.retries_left = F('retries_left') + 1
                user.subscription_status = 'past_due'
                user.save(update_fields=['retries_left', 'subscription_status'])

                user.refresh_from_db()
                if user.retries_left >= 3:
                    user.Tier = 'free'
                    user.subscription_status = 'canceled'
                    user.retries_left = 0
                    user.save(update_fields=['Tier', 'subscription_status', 'retries_left'])

                    Project.objects.filter(owner=user).update(tier='free')

                    stuck_pendings = Pending.objects.filter(project__owner=user)
                    for p in stuck_pendings:
                        p.document.content = p.submitted_content
                        p.document.save(update_fields=['content'])
                    stuck_pendings.delete()

            except User.DoesNotExist:
                pass

    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        customer_id = subscription.get('customer')

        if customer_id:
            try:
                user = User.objects.get(stripe_customer_id=customer_id)

                # check for any active subs — if one exists, sync tier from it
                active_subs = stripe.Subscription.list(
                    customer=customer_id,
                    status='active',
                    limit=10
                )
                if active_subs.data:
                    # active sub exists — set tier from it, don't downgrade
                    active_sub = active_subs.data[0]
                    tier = active_sub.metadata.get('tier')
                    if not tier:
                        items = active_sub.get('items', {}).get('data', [])
                        if items:
                            price_id = items[0].get('price', {}).get('id')
                            tier = {
                                settings.STRIPE_PERSONAL_PRICE_ID: 'personal',
                                settings.STRIPE_TEAM_PRICE_ID: 'team',
                                settings.STRIPE_ENTERPRISE_PRICE_ID: 'enterprise',
                            }.get(price_id)
                    if tier:
                        user.Tier = tier
                        user.subscription_status = 'active'
                        user.save(update_fields=['Tier', 'subscription_status'])
                        Project.objects.filter(owner=user).update(tier=tier)
                    return HttpResponse(status=200)

                # check for incomplete subs — cleanup dead checkouts
                incomplete_subs = stripe.Subscription.list(
                    customer=customer_id,
                    status='incomplete',
                    limit=10
                )
                for inc_sub in incomplete_subs.auto_paging_iter():
                    try:
                        stripe.Subscription.cancel(inc_sub.id)
                    except stripe.error.StripeError:
                        logger.exception(f"Failed to cancel incomplete sub {inc_sub.id}")

                # nothing left — downgrade to free
                user.Tier = 'free'
                user.subscription_status = 'canceled'
                user.retries_left = 0
                user.save(update_fields=['Tier', 'subscription_status', 'retries_left'])

                Project.objects.filter(owner=user).update(tier='free')

                stuck_pendings = Pending.objects.filter(project__owner=user)
                for p in stuck_pendings:
                    p.document.content = p.submitted_content
                    p.document.save(update_fields=['content'])
                stuck_pendings.delete()

            except User.DoesNotExist:
                pass

    elif event['type'] == 'customer.subscription.updated':
        subscription = event['data']['object']
        customer_id = subscription.get('customer')
        status = subscription.get('status')
        cancel_at_period_end = subscription.get('cancel_at_period_end', False)

        items = subscription.get('items', {}).get('data', [])
        tier = None
        if items:
            price_id = items[0].get('price', {}).get('id')
            tier = {
                settings.STRIPE_PERSONAL_PRICE_ID: 'personal',
                settings.STRIPE_TEAM_PRICE_ID: 'team',
                settings.STRIPE_ENTERPRISE_PRICE_ID: 'enterprise',
            }.get(price_id)

        if customer_id:
            try:
                user = User.objects.get(stripe_customer_id=customer_id)

                if cancel_at_period_end:
                    user.subscription_status = 'canceled'
                elif status == 'active':
                    if tier:
                        user.Tier = tier
                    user.subscription_status = 'active'
                elif status == 'past_due':
                    user.subscription_status = 'past_due'
                elif status in ('canceled', 'unpaid'):
                    user.subscription_status = 'canceled'

                user.save(update_fields=['Tier', 'subscription_status'])
            except User.DoesNotExist:
                pass

    return HttpResponse(status=200)



@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def success(request):
    return render(request, 'success.html', {
        'plan_name': request.session.get('plan_name', 'Student'),
        'amount': request.session.get('amount', '5.00'),
        'user': request.user
    })


@ratelimit(key='ip', rate='30/m', block=True)
def buy(request):
    return render(request, 'buy.html', {
        'stripe_publishable_key': settings.STRIPE_PUBLIC_KEY,
        'user': request.user
    })


@ratelimit(key='ip', rate='30/m', block=True)
def terms(request):
    return render(request, 'terms.html', {})


@ratelimit(key='ip', rate='30/m', block=True)
def privacy(request):
    return render(request, 'privacy.html', {})


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_documents(request, project_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        is_owner = project.owner_id == request.user.id

        is_admin = Contributor.objects.filter(
            project_id=project_id,
            username=request.user.username,
            role='ADMIN',
        ).exists()

        if is_owner or is_admin:
            documents = Documents.objects.filter(
                project_id=project_id
            ).select_related('team_assigned').order_by('-created_at')
        else:
            is_contributor = Contributor.objects.filter(
                project_id=project_id,
                username=request.user.username
            ).exists()

            if not is_contributor:
                return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

            user_team_ids = list(TeamMember.objects.filter(
                team__project_id=project_id,
                user=request.user
            ).values_list('team_id', flat=True))

            public_team_ids = list(Teams.objects.filter(
                project_id=project_id,
                team_name='Public'
            ).values_list('id', flat=True))

            visible_team_ids = list(set(user_team_ids + public_team_ids))

            documents = Documents.objects.filter(
                project_id=project_id,
                team_assigned_id__in=visible_team_ids
            ).select_related('team_assigned').order_by('-created_at')

        docs_data = [{
            'id': doc.id,
            'document_name': doc.document_name,
            'content': doc.content,
            'team_name': doc.team_assigned.team_name,
            'team_id': doc.team_assigned_id,
            'created_at': doc.created_at.isoformat()
        } for doc in documents]

        return JsonResponse({'success': True, 'documents': docs_data})
    except Exception:
        logger.exception("get_documents failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_document(request, project_id, doc_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        if not isinstance(doc_id, int) or doc_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid document ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        is_owner = project.owner_id == request.user.id

        if not is_owner:
            is_contributor = Contributor.objects.filter(
                project_id=project_id,
                username=request.user.username
            ).exists()

            if not is_contributor:
                return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        document = Documents.objects.select_related('team_assigned').filter(
            id=doc_id,
            project_id=project_id
        ).first()

        if not document:
            return JsonResponse({'success': False, 'error': 'Document not found'}, status=404)

        is_admin = Contributor.objects.filter(
            project_id=project_id,
            username=request.user.username,
            role='ADMIN',
        ).exists()

        if not is_owner and not is_admin:
            is_public_team = document.team_assigned.team_name == 'Public'

            if not is_public_team:
                is_team_member = TeamMember.objects.filter(
                    team_id=document.team_assigned_id,
                    user=request.user
                ).exists()

                if not is_team_member:
                    return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        return JsonResponse({
            'success': True,
            'document': {
                'id': document.id,
                'document_name': document.document_name,
                'content': document.content,
                'team_name': document.team_assigned.team_name,
                'team_id': document.team_assigned_id,
                'created_at': document.created_at.isoformat()
            }
        })
    except Exception:
        logger.exception("get_document failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def add_document(request, project_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        document_name = data.get('document_name', '')
        team_id = data.get('team_id')

        if not isinstance(document_name, str):
            return JsonResponse({'success': False, 'error': 'Invalid document name'}, status=400)

        document_name = document_name.strip()

        if not document_name:
            return JsonResponse({'success': False, 'error': 'Document name required'}, status=400)

        if len(document_name) > 255:
            return JsonResponse({'success': False, 'error': 'Document name too long'}, status=400)

        if not isinstance(team_id, int) or team_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid team ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        team = Teams.objects.filter(id=team_id, project_id=project_id).first()

        if not team:
            return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

        is_owner = project.owner_id == request.user.id

        if not is_owner:
            is_contributor = Contributor.objects.filter(
                project_id=project_id,
                username=request.user.username
            ).exists()

            if not is_contributor:
                return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

            is_project_admin = Contributor.objects.filter(
                project_id=project_id,
                username=request.user.username,
                role='ADMIN'
            ).exists()

            if not is_project_admin:
                team_admin_membership = TeamMember.objects.filter(
                    team__project_id=project_id,
                    user=request.user,
                    role='ADMIN'
                ).first()

                if not team_admin_membership:
                    return JsonResponse(
                        {'success': False, 'error': 'Only owners, admins and team admins can create documents'}, status=403)

                if team_admin_membership.team_id != team_id:
                    return JsonResponse({'success': False, 'error': 'You can only create documents for your own team'},
                                        status=403)

        tier = project.tier.lower()
        tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])
        max_docs = tier_config.get('documents')

        if max_docs is not None:
            current_doc_count = Documents.objects.filter(project_id=project_id).count()
            if current_doc_count >= max_docs:
                return JsonResponse({'success': False, 'error': f'Document limit ({max_docs}) reached for your tier'},
                                    status=403)

        with transaction.atomic():
            document = Documents.objects.create(
                project=project,
                document_name=document_name,
                content='',
                team_assigned=team
            )

            if tier_config.get('audit', False):
                Audit.objects.create(
                    project=project,
                    document=document,
                    user=request.user,
                    action='create'
                )

        return JsonResponse({
            'success': True,
            'document': {
                'id': document.id,
                'document_name': document.document_name,
                'team_name': team.team_name,
                'team_id': team.id
            }
        })
    except Exception:
        logger.exception("add_document failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def save_document(request, project_id, doc_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        if not isinstance(doc_id, int) or doc_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid document ID'}, status=400)

        content = data.get('content')
        change_note = data.get('note', '').strip()

        if content is None:
            return JsonResponse({'success': False, 'error': 'Content required'}, status=400)

        if not isinstance(content, str):
            return JsonResponse({'success': False, 'error': 'Invalid content type'}, status=400)

        if len(change_note) > 500:
            return JsonResponse({'success': False, 'error': 'Note too long (max 500 chars)'}, status=400)

        try:
            with transaction.atomic():
                project = Project.objects.get(id=project_id)
                document = Documents.objects.select_for_update().get(id=doc_id, project_id=project_id)

                is_owner = project.owner_id == request.user.id
                tier = project.tier.lower()
                tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])

                can_direct_save = False
                requires_pending = False

                if is_owner:
                    can_direct_save = True
                else:
                    contributor = Contributor.objects.filter(
                        project_id=project_id,
                        username=request.user.username
                    ).first()

                    if not contributor:
                        return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

                    if contributor.role == 'ADMIN':
                        can_direct_save = True
                    elif document.team_assigned.team_name == 'Public':
                        if contributor.role == 'EDITOR':
                            can_direct_save = True
                        elif contributor.role == 'VIEWER':
                            return JsonResponse({'success': False, 'error': 'Viewers cannot edit documents'}, status=403)
                    else:
                        membership = TeamMember.objects.filter(
                            team_id=document.team_assigned_id,
                            user=request.user
                        ).first()

                        if not membership:
                            return JsonResponse({'success': False, 'error': 'Not a team member for this document'},
                                                status=403)

                        if membership.role == 'ADMIN':
                            can_direct_save = True
                        elif membership.role == 'EDITOR':
                            if membership.can_direct_save:
                                can_direct_save = True
                            elif tier_config.get('pending', False):
                                requires_pending = True
                            else:
                                can_direct_save = True
                        else:
                            return JsonResponse({'success': False, 'error': 'Invalid role'}, status=403)

                if requires_pending:
                    if not change_note:
                        return JsonResponse({
                            'success': False,
                            'error': 'A note is required when submitting changes for review',
                            'requires_note': True
                        }, status=400)

                    if document.content == content:
                        return JsonResponse({'success': True, 'message': 'No changes to submit'})

                    Pending.objects.create(
                        project=project,
                        team=document.team_assigned,
                        document=document,
                        user=request.user,
                        submitted_content=content,
                        note=change_note
                    )
                    return JsonResponse({'success': True, 'pending': True})

                if document.content == content:
                    return JsonResponse({'success': True, 'message': 'No changes'})

                if project.backups_enabled and tier_config.get('backups', False):
                    backup_document_to_r2.delay(document.id)

                if tier_config.get('audit', False):
                    Audit.objects.create(
                        project=project,
                        document=document,
                        user=request.user,
                        action='edit'
                    )

                document.content = content
                document.save(update_fields=['content'])

        except Project.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)
        except Documents.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Document not found'}, status=404)

        return JsonResponse({'success': True})
    except Exception:
        logger.exception("save_document failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='10/m', block=True)
@csrf_protect
def rename_document(request, project_id, doc_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        new_name = data.get('document_name', '').strip()

        if not new_name:
            return JsonResponse({'success': False, 'error': 'Document name required'}, status=400)

        if len(new_name) > 255:
            return JsonResponse({'success': False, 'error': 'Document name too long'}, status=400)

        try:
            project = Project.objects.get(id=project_id)
        except Project.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        try:
            document = Documents.objects.get(id=doc_id, project_id=project_id)
        except Documents.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Document not found'}, status=404)

        is_owner = project.owner_id == request.user.id

        if not is_owner:
            is_project_admin = Contributor.objects.filter(
                project_id=project_id,
                username=request.user.username,
                role='ADMIN'
            ).exists()

            if not is_project_admin:
                is_team_admin = TeamMember.objects.filter(
                    team_id=document.team_assigned_id,
                    user=request.user,
                    role='ADMIN'
                ).exists()

                if not is_team_admin:
                    return JsonResponse({'success': False,
                                         'error': 'Only project owner, project admin, or team admin can rename documents'},
                                        status=403)

        old_name = document.document_name

        with transaction.atomic():
            document.document_name = new_name
            document.save(update_fields=['document_name'])

            tier = project.tier.lower()
            tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])

            if tier_config.get('audit', False):
                Audit.objects.create(
                    project=project,
                    document=document,
                    user=request.user,
                    action='rename'
                )

        return JsonResponse({
            'success': True,
            'document': {
                'id': document.id,
                'document_name': new_name,
                'old_name': old_name
            }
        })
    except Exception:
        logger.exception("rename_document failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='10/m', block=True)
@csrf_exempt
def delete_document(request, project_id, doc_id):
    try:
        try:
            project = Project.objects.get(id=project_id)
        except Project.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        try:
            document = Documents.objects.get(id=doc_id, project_id=project_id)
        except Documents.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Document not found'}, status=404)

        is_owner = project.owner_id == request.user.id

        if not is_owner:
            is_project_admin = Contributor.objects.filter(
                project_id=project_id,
                username=request.user.username,
                role='ADMIN'
            ).exists()

            if not is_project_admin:
                is_team_admin = TeamMember.objects.filter(
                    team_id=document.team_assigned_id,
                    user=request.user,
                    role='ADMIN'
                ).exists()

                if not is_team_admin:
                    return JsonResponse({'success': False,
                                         'error': 'Only project owner, project admin, or team admin can delete documents'},
                                        status=403)

        document_name = document.document_name
        document_id = document.id

        with transaction.atomic():
            tier = project.tier.lower()
            tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])

            if tier_config.get('audit', False):
                Audit.objects.create(
                    project=project,
                    document=None,
                    user=request.user,
                    action=f'delete:{document_name}'
                )

            document.delete()

        return JsonResponse({
            'success': True,
            'deleted': {
                'id': document_id,
                'document_name': document_name
            }
        })
    except Exception:
        logger.exception("delete_document failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_teams(request, project_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        is_owner = project.owner_id == request.user.id

        if not is_owner:
            contributor = Contributor.objects.filter(
                project_id=project_id,
                username=request.user.username
            ).exists()

            if not contributor:
                return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

            user_team_ids = TeamMember.objects.filter(
                team__project_id=project_id,
                user=request.user
            ).values_list('team_id', flat=True)

            teams = Teams.objects.filter(id__in=user_team_ids).order_by('team_name')
        elif is_owner:
            teams = Teams.objects.filter(project_id=project_id)

        teams_data = []
        for team in teams:
            members = TeamMember.objects.filter(team=team).select_related('user')
            teams_data.append({
                'id': team.id,
                'team_name': team.team_name,
                'created_at': team.created_at.isoformat(),
                'members': [{
                    'id': m.user.id,
                    'username': m.user.username,
                    'role': m.role,
                    'can_direct_save': m.can_direct_save
                } for m in members]
            })

        return JsonResponse({'success': True, 'teams': teams_data})
    except Exception:
        logger.exception("get_teams failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_pending_edits(request, project_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        is_owner = project.owner_id == request.user.id

        can_see_all = False
        team_admin_team_ids = []

        if is_owner:
            can_see_all = True
        else:
            is_project_admin = Contributor.objects.filter(
                project_id=project_id,
                username=request.user.username,
                role='ADMIN'
            ).exists()

            if is_project_admin:
                can_see_all = True
            else:
                team_admin_team_ids = list(TeamMember.objects.filter(
                    team__project_id=project_id,
                    user=request.user,
                    role='ADMIN'
                ).values_list('team_id', flat=True))

                if not team_admin_team_ids:
                    return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        tier = project.tier.lower()
        tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])

        if not tier_config.get('pending', False):
            return JsonResponse({'success': False, 'error': 'Pending edits not available for your tier'}, status=403)

        if can_see_all:
            pending_edits = Pending.objects.filter(
                project_id=project_id
            ).select_related('document', 'user', 'team').order_by('-created_at')
        else:
            pending_edits = Pending.objects.filter(
                project_id=project_id,
                team_id__in=team_admin_team_ids
            ).select_related('document', 'user', 'team').order_by('-created_at')

        pending_data = [{
            'id': p.id,
            'document_id': p.document.id,
            'document_name': p.document.document_name,
            'username': p.user.username,
            'team_id': p.team.id,
            'team_name': p.team.team_name,
            'submitted_content': p.submitted_content,
            'note': p.note,
            'created_at': p.created_at.isoformat()
        } for p in pending_edits]

        return JsonResponse({'success': True, 'pending': pending_data})
    except Exception:
        logger.exception("get_pending_edits failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_audits(request, project_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        is_owner = project.owner_id == request.user.id

        if not is_owner:
            contributor = Contributor.objects.filter(
                project_id=project_id,
                username=request.user.username
            ).exists()

            if not contributor:
                return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        tier = project.tier.lower()
        tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])

        if not tier_config.get('audit', False):
            return JsonResponse({'success': False, 'error': 'Audit logs not available for your tier'}, status=403)

        audits = Audit.objects.filter(
            project_id=project_id
        ).select_related('document', 'user').order_by('-created_at')[:500]

        audits_data = [{
            'id': audit.id,
            'username': audit.user.username,
            'document_name': audit.document.document_name if audit.document else 'N/A',
            'action': audit.action,
            'created_at': audit.created_at.isoformat()
        } for audit in audits]

        return JsonResponse({'success': True, 'audits': audits_data})
    except Exception:
        logger.exception("get_audits failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_pending_actions(request, project_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        is_owner = project.owner_id == request.user.id

        if not is_owner:
            contributor = Contributor.objects.filter(
                project_id=project_id,
                username=request.user.username
            ).exists()

            if not contributor:
                return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        tier = project.tier.lower()
        tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])

        if not tier_config.get('audit', False):
            return JsonResponse({'success': False, 'error': 'Audit logs not available for your tier'}, status=403)

        pending_actions = PendingAction.objects.filter(
            project_id=project_id
        ).select_related('pending_user', 'actioned_by', 'document').order_by('-created_at')[:100]

        actions_data = [{
            'id': action.id,
            'actioned_by': action.actioned_by.username,
            'pending_user': action.pending_user.username,
            'action': action.action,
            'document_name': action.document_name,
            'pending_note': action.pending_note,
            'created_at': action.created_at.isoformat()
        } for action in pending_actions]

        return JsonResponse({'success': True, 'pending_actions': actions_data})
    except Exception:
        logger.exception("get_pending_actions failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def create_team(request, project_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        team_name = data.get('team_name', '')

        if not isinstance(team_name, str):
            return JsonResponse({'success': False, 'error': 'Invalid team name'}, status=400)

        team_name = team_name.strip()

        if not team_name:
            return JsonResponse({'success': False, 'error': 'Team name required'}, status=400)

        if len(team_name) > 255:
            return JsonResponse({'success': False, 'error': 'Team name too long'}, status=400)

        if not PROJECT_NAME_REGEX.match(team_name):
            return JsonResponse({'success': False, 'error': 'Team name contains invalid characters'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        if project.owner_id != request.user.id:
            return JsonResponse({'success': False, 'error': 'Only project owner can create teams'}, status=403)

        tier = project.tier.lower()
        tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])
        max_teams = tier_config.get('teams')

        if max_teams is not None:
            current_team_count = Teams.objects.filter(project_id=project_id).count()
            if current_team_count >= max_teams:
                return JsonResponse({'success': False, 'error': f'Team limit ({max_teams}) reached for your tier'},
                                    status=403)

        if Teams.objects.filter(project_id=project_id, team_name=team_name).exists():
            return JsonResponse({'success': False, 'error': 'Team name already exists in this project'}, status=400)

        with transaction.atomic():
            team = Teams.objects.create(
                project=project,
                team_name=team_name
            )

            if tier_config.get('audit', False):
                Audit.objects.create(
                    project=project,
                    document=None,
                    user=request.user,
                    action='create_team'
                )

        return JsonResponse({
            'success': True,
            'team': {
                'id': team.id,
                'team_name': team.team_name,
                'members': []
            }
        })
    except Exception:
        logger.exception("create_team failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def update_team(request, project_id, team_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        if not isinstance(team_id, int) or team_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid team ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        if project.owner_id != request.user.id:
            return JsonResponse({'success': False, 'error': 'Only project owner can edit teams'}, status=403)

        team = Teams.objects.filter(id=team_id, project_id=project_id).first()

        if not team:
            return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

        team_name = data.get('team_name', '')

        if not isinstance(team_name, str):
            return JsonResponse({'success': False, 'error': 'Invalid team name'}, status=400)

        team_name = team_name.strip()

        if team_name:
            if len(team_name) > 255:
                return JsonResponse({'success': False, 'error': 'Team name too long'}, status=400)

            if not PROJECT_NAME_REGEX.match(team_name):
                return JsonResponse({'success': False, 'error': 'Team name contains invalid characters'}, status=400)

            if Teams.objects.filter(project_id=project_id, team_name=team_name).exclude(id=team_id).exists():
                return JsonResponse({'success': False, 'error': 'Team name already exists'}, status=400)

            team.team_name = team_name
            team.save(update_fields=['team_name'])

        return JsonResponse({
            'success': True,
            'team': {
                'id': team.id,
                'team_name': team.team_name
            }
        })
    except Exception:
        logger.exception("update_team failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def delete_team(request, project_id, team_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        if not isinstance(team_id, int) or team_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid team ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        if project.owner_id != request.user.id:
            return JsonResponse({'success': False, 'error': 'Only project owner can delete teams'}, status=403)

        deleted, _ = Teams.objects.filter(id=team_id, project_id=project_id).delete()

        if not deleted:
            return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

        return JsonResponse({'success': True})
    except Exception:
        logger.exception("delete_team failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def add_team_member(request, project_id, team_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        if not isinstance(team_id, int) or team_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid team ID'}, status=400)

        username = data.get('username', '')
        role = data.get('role', 'EDITOR')

        if not isinstance(username, str):
            return JsonResponse({'success': False, 'error': 'Invalid username'}, status=400)

        if not isinstance(role, str):
            return JsonResponse({'success': False, 'error': 'Invalid role'}, status=400)

        username = username.strip()
        role = role.upper().strip()

        if not username:
            return JsonResponse({'success': False, 'error': 'Username required'}, status=400)

        if not USERNAME_REGEX.match(username):
            return JsonResponse({'success': False, 'error': 'Invalid username format'}, status=400)

        if role not in ('EDITOR', 'ADMIN'):
            return JsonResponse({'success': False, 'error': 'Invalid role'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        if project.owner_id != request.user.id:
            return JsonResponse({'success': False, 'error': 'Only project owner can add team members'}, status=403)

        team = Teams.objects.filter(id=team_id, project_id=project_id).first()

        if not team:
            return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

        is_contributor = Contributor.objects.filter(
            project_id=project_id,
            username=username
        ).exists()

        if not is_contributor:
            return JsonResponse({'success': False, 'error': 'User must be a contributor first'}, status=400)

        user = User.objects.filter(username=username).first()

        if not user:
            return JsonResponse({'success': False, 'error': 'User not found'}, status=404)

        if TeamMember.objects.filter(team=team, user=user).exists():
            return JsonResponse({'success': False, 'error': 'User already in team'}, status=400)

        tier = project.tier.lower()
        tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])
        max_members = tier_config.get('members')

        if max_members is not None:
            current_count = TeamMember.objects.filter(team=team).count()
            if current_count >= max_members:
                return JsonResponse({'success': False, 'error': f'Member limit ({max_members}) reached for your tier'},
                                    status=403)

        TeamMember.objects.create(team=team, user=user, role=role)

        return JsonResponse({
            'success': True,
            'member': {
                'id': user.id,
                'username': user.username,
                'role': role
            }
        })
    except Exception:
        logger.exception("add_team_member failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def remove_team_member(request, project_id, team_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        if not isinstance(team_id, int) or team_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid team ID'}, status=400)

        username = data.get('username', '')

        if not isinstance(username, str):
            return JsonResponse({'success': False, 'error': 'Invalid username'}, status=400)

        username = username.strip()

        if not username:
            return JsonResponse({'success': False, 'error': 'Username required'}, status=400)

        if not USERNAME_REGEX.match(username):
            return JsonResponse({'success': False, 'error': 'Invalid username format'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        if project.owner_id != request.user.id:
            return JsonResponse({'success': False, 'error': 'Only project owner can remove team members'}, status=403)

        team = Teams.objects.filter(id=team_id, project_id=project_id).first()

        if not team:
            return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

        user = User.objects.filter(username=username).first()

        if not user:
            return JsonResponse({'success': False, 'error': 'User not found'}, status=404)

        deleted, _ = TeamMember.objects.filter(team=team, user=user).delete()

        if not deleted:
            return JsonResponse({'success': False, 'error': 'User not in team'}, status=400)

        return JsonResponse({'success': True})
    except Exception:
        logger.exception("remove_team_member failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def update_team_member_role(request, project_id, team_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        if not isinstance(team_id, int) or team_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid team ID'}, status=400)

        username = data.get('username', '')
        role = data.get('role', '')

        if not isinstance(username, str):
            return JsonResponse({'success': False, 'error': 'Invalid username'}, status=400)

        if not isinstance(role, str):
            return JsonResponse({'success': False, 'error': 'Invalid role'}, status=400)

        username = username.strip()
        role = role.upper().strip()

        if not username:
            return JsonResponse({'success': False, 'error': 'Username required'}, status=400)

        if not USERNAME_REGEX.match(username):
            return JsonResponse({'success': False, 'error': 'Invalid username format'}, status=400)

        if role not in ('EDITOR', 'ADMIN'):
            return JsonResponse({'success': False, 'error': 'Invalid role'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        if project.owner_id != request.user.id:
            return JsonResponse({'success': False, 'error': 'Only project owner can change member roles'}, status=403)

        team = Teams.objects.filter(id=team_id, project_id=project_id).first()

        if not team:
            return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

        user = User.objects.filter(username=username).first()

        if not user:
            return JsonResponse({'success': False, 'error': 'User not found'}, status=404)

        membership = TeamMember.objects.filter(team=team, user=user).first()

        if not membership:
            return JsonResponse({'success': False, 'error': 'User not in team'}, status=404)

        membership.role = role
        membership.save(update_fields=['role'])

        return JsonResponse({
            'success': True,
            'member': {
                'id': user.id,
                'username': user.username,
                'role': role,
                'can_direct_save': membership.can_direct_save
            }
        })
    except Exception:
        logger.exception("update_team_member_role failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def update_team_member_review(request, project_id, team_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        if not isinstance(team_id, int) or team_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid team ID'}, status=400)

        username = data.get('username', '')
        can_direct_save = data.get('can_direct_save')

        if not isinstance(username, str):
            return JsonResponse({'success': False, 'error': 'Invalid username'}, status=400)

        username = username.strip()

        if not username:
            return JsonResponse({'success': False, 'error': 'Username required'}, status=400)

        if not USERNAME_REGEX.match(username):
            return JsonResponse({'success': False, 'error': 'Invalid username format'}, status=400)

        if can_direct_save is None:
            return JsonResponse({'success': False, 'error': 'can_direct_save field required'}, status=400)

        if not isinstance(can_direct_save, bool):
            return JsonResponse({'success': False, 'error': 'can_direct_save must be boolean'}, status=400)

        project = Project.objects.filter(id=project_id).first()

        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        if project.owner_id != request.user.id:
            return JsonResponse({'success': False, 'error': 'Only project owner can change review settings'}, status=403)

        team = Teams.objects.filter(id=team_id, project_id=project_id).first()

        if not team:
            return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

        user = User.objects.filter(username=username).first()

        if not user:
            return JsonResponse({'success': False, 'error': 'User not found'}, status=404)

        membership = TeamMember.objects.filter(team=team, user=user).first()

        if not membership:
            return JsonResponse({'success': False, 'error': 'User not in team'}, status=404)

        membership.can_direct_save = can_direct_save
        membership.save(update_fields=['can_direct_save'])

        return JsonResponse({
            'success': True,
            'member': {
                'id': user.id,
                'username': user.username,
                'role': membership.role,
                'can_direct_save': membership.can_direct_save
            }
        })
    except Exception:
        logger.exception("update_team_member_review failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@login_required
@require_GET
def profile(request):
    return render(request, 'profile.html', {'user': request.user})


@login_required
@require_POST
@ratelimit(key='ip', rate='5/m', block=True)
def change_password(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')

        if not current_password or not new_password:
            return JsonResponse({'success': False, 'error': 'All fields required'}, status=400)

        if len(new_password) < 6:
            return JsonResponse({'success': False, 'error': 'Password must be at least 6 characters'}, status=400)

        if not request.user.check_password(current_password):
            return JsonResponse({'success': False, 'error': 'Current password is incorrect'}, status=400)

        request.user.set_password(new_password)
        request.user.save()

        update_session_auth_hash(request, request.user)

        return JsonResponse({'success': True})
    except Exception:
        logger.exception("change_password failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@login_required
@require_POST
@ratelimit(key='ip', rate='5/m', block=True)
def cancel_subscription(request):
    try:
        if not request.user.stripe_customer_id:
            return JsonResponse({'success': False, 'error': 'No active subscription'}, status=400)

        try:
            subscriptions = stripe.Subscription.list(
                customer=request.user.stripe_customer_id,
                status='active',
                limit=1
            )

            if not subscriptions.data:
                return JsonResponse({'success': False, 'error': 'No active subscription'}, status=400)

            stripe.Subscription.modify(
                subscriptions.data[0].id,
                cancel_at_period_end=True
            )

            tier_before = request.user.Tier
            request.user.subscription_status = 'canceled'
            request.user.save(update_fields=['subscription_status'])

            send_cancellation_email.delay(request.user.email, request.user.username, tier_before)

            return JsonResponse({'success': True})

        except stripe.error.StripeError:
            return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)
    except Exception:
        logger.exception("cancel_subscription failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@login_required
@require_POST
@ratelimit(key='ip', rate='3/m', block=True)
def delete_account(request):
    try:
        user = request.user

        if user.stripe_customer_id:
            try:
                subscriptions = stripe.Subscription.list(
                    customer=user.stripe_customer_id,
                    status='active'
                )
                for sub in subscriptions.data:
                    stripe.Subscription.cancel(sub.id)
            except stripe.error.StripeError:
                return JsonResponse(
                    {'success': False, 'error': 'Please contact support if your subscrption hasnt automaticaly cancelled'},
                    status=500)

        auth_logout(request)
        user.delete()

        return JsonResponse({'success': True})
    except Exception:
        logger.exception("delete_account failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)

@ratelimit(key='ip', rate='3/m', block=True)
@require_GET
def password_reset(request):
    return render(request, 'reset_password.html')

@csrf_exempt
@require_POST
@ratelimit(key='ip', rate='5/m', block=True)
def password_reset_send(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        email = data.get('email', '')

        if not isinstance(email, str):
            return JsonResponse({'success': False, 'error': 'Invalid email'}, status=400)

        email = email.strip().lower()

        if not email or not EMAIL_REGEX.match(email):
            return JsonResponse({'success': False, 'error': 'Invalid email format'}, status=400)

        user = User.objects.filter(email=email).first()

        if user:
            code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])

            cache.set(f'pw_reset_code:{email}', code, timeout=900)
            cache.set(f'pw_reset_attempts:{email}', 0, timeout=900)
            cache.delete(f'pw_reset_token:{email}')

            send_password_reset_email(user.email, user.username, code)

        return JsonResponse({'success': True})
    except Exception:
        logger.exception("password_reset_send failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)

@csrf_exempt
@require_POST
@ratelimit(key='ip', rate='10/m', block=True)
def password_reset_verify(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        email = data.get('email', '')
        code = data.get('code', '')

        if not isinstance(email, str) or not isinstance(code, str):
            return JsonResponse({'success': False, 'error': 'Invalid input'}, status=400)

        email = email.strip().lower()
        code = code.strip()

        if not email or not code:
            return JsonResponse({'success': False, 'error': 'Email and code required'}, status=400)

        if len(code) != 6 or not code.isdigit():
            return JsonResponse({'success': False, 'error': 'Invalid code format'}, status=400)

        attempts = cache.get(f'pw_reset_attempts:{email}', None)
        if attempts is None:
            return JsonResponse({'success': False, 'error': 'No reset requested or code expired'}, status=400)

        if attempts >= 5:
            cache.delete(f'pw_reset_code:{email}')
            cache.delete(f'pw_reset_attempts:{email}')
            return JsonResponse({'success': False, 'error': 'Too many attempts. Request a new code'}, status=400)

        stored_code = cache.get(f'pw_reset_code:{email}')
        if not stored_code:
            return JsonResponse({'success': False, 'error': 'Code expired. Request a new one'}, status=400)

        cache.set(f'pw_reset_attempts:{email}', attempts + 1, timeout=900)

        if code != stored_code:
            return JsonResponse({'success': False, 'error': 'Invalid code'}, status=400)

        token = secrets.token_urlsafe(32)
        cache.set(f'pw_reset_token:{email}', token, timeout=600)
        cache.delete(f'pw_reset_code:{email}')
        cache.delete(f'pw_reset_attempts:{email}')

        return JsonResponse({'success': True, 'token': token})
    except Exception:
        logger.exception("password_reset_verify failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@csrf_exempt
@require_POST
@ratelimit(key='ip', rate='5/m', block=True)
def password_reset_confirm(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        email = data.get('email', '')
        token = data.get('token', '')
        new_password = data.get('new_password', '')

        if not isinstance(email, str) or not isinstance(token, str) or not isinstance(new_password, str):
            return JsonResponse({'success': False, 'error': 'Invalid input'}, status=400)

        email = email.strip().lower()
        token = token.strip()

        if not email or not token or not new_password:
            return JsonResponse({'success': False, 'error': 'All fields required'}, status=400)

        if len(new_password) < 6:
            return JsonResponse({'success': False, 'error': 'Password must be at least 6 characters'}, status=400)

        stored_token = cache.get(f'pw_reset_token:{email}')
        if not stored_token or stored_token != token:
            return JsonResponse({'success': False, 'error': 'Invalid or expired token'}, status=400)

        user = User.objects.filter(email=email).first()
        if not user:
            return JsonResponse({'success': False, 'error': 'Invalid request'}, status=400)

        user.set_password(new_password)
        user.save()

        cache.delete(f'pw_reset_token:{email}')

        return JsonResponse({'success': True})
    except Exception:
        logger.exception("password_reset_confirm failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_viewer_access(request, project_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()
        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        if request.user.id != project.owner_id:
            return JsonResponse({'success': False, 'error': 'Permission denied'}, status=403)

        doc_ids = list(
            ViewerDocumentAccess.objects.filter(project_id=project_id).values_list('document_id', flat=True)
        )

        return JsonResponse({'success': True, 'document_ids': doc_ids})
    except Exception:
        logger.exception("get_viewer_access failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def save_viewer_access(request, project_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()
        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        if request.user.id != project.owner_id:
            return JsonResponse({'success': False, 'error': 'Permission denied'}, status=403)

        document_ids = data.get('document_ids', [])

        if not isinstance(document_ids, list):
            return JsonResponse({'success': False, 'error': 'Invalid document_ids'}, status=400)

        for did in document_ids:
            if not isinstance(did, int) or did < 1:
                return JsonResponse({'success': False, 'error': 'Invalid document ID in list'}, status=400)

        valid_doc_ids = set(
            Documents.objects.filter(project_id=project_id, id__in=document_ids).values_list('id', flat=True)
        )

        invalid = set(document_ids) - valid_doc_ids
        if invalid:
            return JsonResponse({'success': False, 'error': 'Some document IDs are invalid'}, status=400)

        with transaction.atomic():
            ViewerDocumentAccess.objects.filter(project_id=project_id).delete()
            if document_ids:
                ViewerDocumentAccess.objects.bulk_create([
                    ViewerDocumentAccess(project_id=project_id, document_id=did)
                    for did in document_ids
                ])

        return JsonResponse({'success': True, 'count': len(document_ids)})
    except Exception:
        logger.exception("save_viewer_access failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_viewer_documents(request, project_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()
        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        contributor = Contributor.objects.filter(
            project_id=project_id,
            username=request.user.username,
            role='VIEWER'
        ).first()

        if not contributor:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        accessible_doc_ids = ViewerDocumentAccess.objects.filter(
            project_id=project_id
        ).values_list('document_id', flat=True)

        documents = Documents.objects.filter(
            id__in=accessible_doc_ids
        ).values('id', 'document_name')

        docs_data = [{'id': d['id'], 'document_name': d['document_name']} for d in documents]

        return JsonResponse({'success': True, 'documents': docs_data})
    except Exception:
        logger.exception("get_viewer_documents failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_viewer_document_content(request, project_id, doc_id):
    try:
        if not isinstance(project_id, int) or project_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)
        if not isinstance(doc_id, int) or doc_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid document ID'}, status=400)

        project = Project.objects.filter(id=project_id).first()
        if not project:
            return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

        contributor = Contributor.objects.filter(
            project_id=project_id,
            username=request.user.username,
            role='VIEWER'
        ).first()

        if not contributor:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        has_access = ViewerDocumentAccess.objects.filter(
            project_id=project_id,
            document_id=doc_id
        ).exists()

        if not has_access:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        document = Documents.objects.filter(id=doc_id, project_id=project_id).first()
        if not document:
            return JsonResponse({'success': False, 'error': 'Document not found'}, status=404)

        return JsonResponse({
            'success': True,
            'document': {
                'id': document.id,
                'document_name': document.document_name,
                'content': document.content
            }
        })
    except Exception:
        logger.exception("get_viewer_document_content failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)



def render_error(request, code):
    return render(request, 'error.html', ERROR_PAGES[code], status=code)


def error_400(request):
    return render_error(request, 400)

def error_401(request):
    return render_error(request, 401)

def error_403(request):
    return render_error(request, 403)

def error_404(request):
    return render_error(request, 404)

def error_408(request):
    return render_error(request, 408)

def error_413(request):
    return render_error(request, 413)

def error_429(request):
    return render_error(request, 429)

def error_500(request):
    return render_error(request, 500)

def error_502(request):
    return render_error(request, 502)

def error_503(request):
    return render_error(request, 503)


INVITE_CODE_CHARS = string.ascii_uppercase + string.digits

EXPIRY_DURATIONS = {
    '15m': timedelta(minutes=15),
    '30m': timedelta(minutes=30),
    '1h': timedelta(hours=1),
    '2h': timedelta(hours=2),
    '4h': timedelta(hours=4),
    '24h': timedelta(hours=24),
    'never': None,
}


def generate_unique_code():
    for _ in range(20):
        code = ''.join(secrets.choice(INVITE_CODE_CHARS) for _ in range(6))
        if not InviteCode.objects.filter(code=code).exists():
            return code
    return None


@require_auth_token
@ratelimit(key='ip', rate='30/m', block=True)
def list_invite_codes(request, project_id):
    try:
        project = Project.objects.get(id=project_id)
        if project.owner_id != request.user.id:
            return JsonResponse({'success': False, 'error': 'Only the project owner can view invite codes'}, status=403)

        codes = InviteCode.objects.filter(project=project).order_by('-created_at')
        result = []
        for ic in codes:
            if ic.is_expired():
                ic.delete()
                continue
            result.append({
                'id': ic.id,
                'code': ic.code,
                'role': ic.role,
                'created_at': ic.created_at.isoformat(),
                'expires_at': ic.expires_at.isoformat() if ic.expires_at else None,
            })

        return JsonResponse({'success': True, 'invite_codes': result})
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)
    except Exception:
        logger.exception("list_invite_codes failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='20/m', block=True)
def delete_invite_code(request, project_id, code_id):
    try:
        project = Project.objects.get(id=project_id)
        if project.owner_id != request.user.id:
            return JsonResponse({'success': False, 'error': 'Only the project owner can delete invite codes'}, status=403)

        invite = InviteCode.objects.get(id=code_id, project=project)
        invite.delete()
        return JsonResponse({'success': True})
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)
    except InviteCode.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Invite code not found'}, status=404)
    except Exception:
        logger.exception("delete_invite_code failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='20/m', block=True)
def generate_invite_code(request, project_id):
    try:
        project = Project.objects.get(id=project_id)
        if project.owner_id != request.user.id:
            return JsonResponse({'success': False, 'error': 'Only the project owner can generate invite codes'}, status=403)

        data = json.loads(request.body)
        role = data.get('role', '').upper()
        expiry = data.get('expiry', '')

        if role not in ('VIEWER', 'EDITOR', 'ADMIN'):
            return JsonResponse({'success': False, 'error': 'Invalid role'}, status=400)

        if expiry not in EXPIRY_DURATIONS:
            return JsonResponse({'success': False, 'error': 'Invalid expiry duration'}, status=400)

        code = generate_unique_code()
        if not code:
            return JsonResponse({'success': False, 'error': 'Could not generate a unique code, try again'}, status=500)

        from django.utils.timezone import now as tz_now
        created = tz_now()
        duration = EXPIRY_DURATIONS[expiry]
        expires_at = created + duration if duration else None

        invite = InviteCode.objects.create(
            project=project,
            code=code,
            role=role,
            expires_at=expires_at,
        )

        return JsonResponse({
            'success': True,
            'code': invite.code,
            'role': invite.role,
            'expires_at': invite.expires_at.isoformat() if invite.expires_at else None,
        })
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)
    except Exception:
        logger.exception("generate_invite_code failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='20/m', block=True)
def redeem_invite_code(request):
    try:
        data = json.loads(request.body)
        code = data.get('code', '').strip().upper()

        if not code or len(code) != 6:
            return JsonResponse({'success': False, 'error': 'Invalid code format'}, status=400)

        try:
            invite = InviteCode.objects.select_related('project').get(code=code)
        except InviteCode.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Invalid code'}, status=404)

        if invite.is_expired():
            invite.delete()
            return JsonResponse({'success': False, 'error': 'Code expired'}, status=410)

        project = invite.project

        if project.owner_id == request.user.id:
            return JsonResponse({'success': False, 'error': 'You are the owner of this project'}, status=400)

        if Contributor.objects.filter(project=project, username=request.user.username).exists():
            return JsonResponse({'success': False, 'error': 'You are already a collaborator on this project'}, status=409)

        Contributor.objects.create(
            project=project,
            username=request.user.username,
            role=invite.role,
        )

        return JsonResponse({
            'success': True,
            'project_name': project.project_name,
            'role': invite.role,
        })
    except Exception:
        logger.exception("redeem_invite_code failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


