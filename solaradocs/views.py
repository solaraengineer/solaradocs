from wsgiref.util import request_uri

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie, csrf_protect
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.cache import cache_page
from django.db import transaction
from django.db.models import Q
from django.conf import settings
import stripe
import json
import jwt
from datetime import datetime, timedelta
from django_ratelimit.decorators import ratelimit
from functools import wraps
from .forms import LoginForm, RegisterForm

from django.contrib.auth import update_session_auth_hash
from .models import Project, Contributor, Pending, User, Backup, Audit, Documents, Teams, TeamMember, Changelog
import re

PROJECT_NAME_REGEX = re.compile(r'^[a-zA-Z0-9\s@#$!]+$')
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_@#$!]+$')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


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

# Require RS384 with RSA keys - no fallback
if not JWT_PRIVATE_KEY or not JWT_PUBLIC_KEY:
    raise ValueError("JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required for RS384 authentication")

stripe.api_key = settings.STRIPE_SECRET_KEY
stripe.public_key = settings.STRIPE_PUBLIC_KEY

TIER_LIMITS = {
    'free': {'projects': 1, 'documents': 2, 'teams': 1, 'members': 3, 'backups': False, 'audit': False, 'pending': False},
    'student': {'projects': 3, 'documents': 5, 'teams': 2, 'members': 6, 'backups': True, 'audit': False, 'pending': False},
    'team': {'projects': 5, 'documents': 20, 'teams': 5, 'members': 20, 'backups': True, 'audit': True, 'pending': True},
    'enterprise': {'projects': None, 'documents': None, 'teams': None, 'members': None, 'backups': True, 'audit': True, 'pending': True},
}


@require_GET
def get_oauth_token(request):
    if not request.user.is_authenticated:
        return JsonResponse({'success': False, 'error': 'Not authenticated'}, status=401)

    token = generate_auth_token(request.user.id)
    return JsonResponse({'success': True, 'token': token})


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


def generate_editor_token(user_id, project_id):
    payload = {
        'user_id': user_id,
        'project_id': project_id,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_PRIVATE_KEY, algorithm='RS384')


def verify_editor_token(token, project_id):
    try:
        payload = jwt.decode(token, JWT_PUBLIC_KEY, algorithms=['RS384'])
        if payload.get('project_id') != project_id:
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_editor_token(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        token = request.headers.get('X-Editor-Token') or request.POST.get('editor_token')
        if not token:
            data = json.loads(request.body) if request.body else {}
            token = data.get('editor_token')

        project_id = kwargs.get('project_id') or (json.loads(request.body) if request.body else {}).get('project_id')

        if not token or not project_id:
            return JsonResponse({'success': False, 'error': 'Editor token required'}, status=401)

        payload = verify_editor_token(token, project_id)
        if not payload:
            return JsonResponse({'success': False, 'error': 'Invalid or expired token'}, status=401)

        if payload['user_id'] != request.user.id:
            return JsonResponse({'success': False, 'error': 'Token user mismatch'}, status=403)

        request.editor_payload = payload
        return view_func(request, *args, **kwargs)

    return wrapper


@require_GET
def dashboard(request):
    if not request.user.is_authenticated:
        return redirect('login')

    projects = Project.objects.filter(owner_id=request.user.id).order_by('-created_at')
    return render(request, 'dashboard.html', {'projects': projects})

@require_auth_token
@login_required(login_url='/login')
def setup(request):
    if request.method == 'GET':
        user_tier = request.user.Tier
        tier_config = TIER_LIMITS.get(user_tier, TIER_LIMITS['free'])
        return render(request, 'setup.html', {'tier': user_tier, 'tier_config': tier_config})

    user_tier = request.user.Tier
    if user_tier not in TIER_LIMITS:
        return JsonResponse({'success': False, 'error': 'Invalid tier'}, status=400)

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

    raw_people = request.POST.get('people', '')
    people = []

    if raw_people.strip():
        for username in raw_people.split():
            username = username.strip()
            if not username:
                continue

            clean_username, error = sanitize_string(
                username,
                max_length=50,
                pattern=USERNAME_REGEX,
                field_name='Username'
            )
            if error:
                return JsonResponse({'success': False, 'error': f'Invalid username: {username}'}, status=400)

            if not User.objects.filter(username=clean_username).exists():
                return JsonResponse({'success': False, 'error': f'User not found: {clean_username}'}, status=404)

            people.append(clean_username)

    people = list(dict.fromkeys(people))

    current_project_count = Project.objects.filter(owner=request.user).count()
    max_projects = tier_config.get('projects')
    if max_projects is not None and current_project_count >= max_projects:
        return JsonResponse({'success': False, 'error': 'Project limit reached for your tier'}, status=403)

    max_collaborators = tier_config.get('members')
    if max_collaborators is not None and len(people) > max_collaborators:
        return JsonResponse({'success': False, 'error': f'Collaborator limit is {max_collaborators} for your tier'},
                            status=403)

    with transaction.atomic():
        project = Project.objects.create(
            owner=request.user,
            project_name=project_name,
            people=','.join(people),
            backups_enabled=backups_enabled,
            tier=user_tier,
        )

        if people:
            Contributor.objects.bulk_create(
                [Contributor(project=project, username=p, role='VIEWER') for p in people]
            )

    return JsonResponse({'success': True, 'redirect': '/dashboard/'})


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='5/m', block=True)
def change_roles(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    project_id = data.get('project_id')
    contributor_id = data.get('contributor_id')
    new_role = data.get('role', '')

    if not isinstance(project_id, int) or project_id < 1:
        return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

    if not isinstance(contributor_id, int) or contributor_id < 1:
        return JsonResponse({'success': False, 'error': 'Invalid contributor ID'}, status=400)

    if not isinstance(new_role, str):
        return JsonResponse({'success': False, 'error': 'Invalid role type'}, status=400)

    new_role = new_role.upper().strip()

    if new_role not in ('VIEWER', 'EDITOR', 'ADMIN'):
        return JsonResponse({'success': False, 'error': 'Invalid role'}, status=400)

    project = Project.objects.filter(id=project_id).first()

    if not project:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    if request.user.id != project.owner.id:
        return JsonResponse({'success': False, 'error': 'Permission denied'}, status=403)

    updated = Contributor.objects.filter(id=contributor_id, project_id=project_id).update(role=new_role)

    if not updated:
        return JsonResponse({'success': False, 'error': 'Contributor not found'}, status=404)

    return JsonResponse({'success': True})


@ratelimit(key='ip', rate='5/m', block=True)
@require_POST
@require_auth_token
def add_people(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

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

    if new_people:
        Contributor.objects.bulk_create(
            [Contributor(project_id=project_id, username=p, role='VIEWER') for p in new_people]
        )

    return JsonResponse({'success': True, 'added_count': len(new_people)})


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
    changelogs = Changelog.objects.all().order_by('-created_at')
    return render(request, 'changelog.html', {'changelogs': changelogs})


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
        return JsonResponse({'success': True, 'redirect': '/dashboard/', 'token': token})

    except Exception:
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
def logout_view(request):
    auth_logout(request)
    return redirect('login')


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='5/m', block=True)
def deleteuser(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

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

@require_GET
@require_auth_token
# KEEP IN MIND FOR LATER VARIES LEAVE FOR NOW
def project_detail(request, project_id):
    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    is_owner = project.owner_id == request.user.id
    contributor = None
    role = 'OWNER' if is_owner else None

    if not is_owner:
        contributor = Contributor.objects.filter(
            project_id=project_id,
            username=request.user.username
        ).values('role').first()

        if not contributor:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        role = contributor['role']

    editor_token = generate_editor_token(request.user.id, project_id)

    return render(request, 'edit.html', {
        'project': project,
        'is_owner': is_owner,
        'role': role,
        'editor_token': editor_token
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


@require_POST
@require_auth_token
# READ OVER AGAIN SEE SENSE GET BACK TO IT SOON
def revert(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    project_id = data.get('project_id')
    backup_id = data.get('backup_id')

    if not all([project_id, backup_id]):
        return JsonResponse({'success': False, 'error': 'Missing required fields'})

    with transaction.atomic():
        backup = Backup.objects.filter(
            Q(id=backup_id) & Q(project_id=project_id) & Q(project__owner_id=request.user.id)
        ).values('content').first()

        if not backup:
            return JsonResponse({'success': False, 'error': 'Backup not found'}, status=404)

        Project.objects.filter(id=project_id).update(content=backup['content'])
        Backup.objects.filter(id=backup_id).delete()

    return JsonResponse({'success': True})


@require_POST
@require_auth_token
# another function to review.
def handle_pending(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    pending_id = data.get('pending_id')
    action = data.get('action', '').lower()

    if not pending_id:
        return JsonResponse({'success': False, 'error': 'Pending ID required'})

    if action not in ('accept', 'reject'):
        return JsonResponse({'success': False, 'error': 'Invalid action'})

    with transaction.atomic():
        pending = Pending.objects.filter(id=pending_id).select_related('project').first()

        if not pending:
            return JsonResponse({'success': False, 'error': 'Not found'}, status=404)

        if pending.project.owner_id != request.user.id:
            return JsonResponse({'success': False, 'error': 'Not authorized'}, status=403)

        if action == 'accept':
            pending.project.content = pending.submitted_content
            pending.project.save(update_fields=['content'])

        pending.delete()

    return JsonResponse({'success': True})


@require_GET
@require_auth_token
def collaborations(request):
    collaborated_projects = Contributor.objects.filter(
        username=request.user.username
    ).select_related('project').order_by('-project__created_at')

    return render(request, 'collaborations.html', {'collaborated_projects': collaborated_projects})


@csrf_exempt
def logout(request):
    auth_logout(request)
    return redirect('login')


def home(request):
    return render(request, 'index.html')


PRICE_IDS = {
    'student': 'price_1SstN86RgjVGr3Dc9jG2YCip',
    'team': 'price_1SspcWHVqJxZgWX0bv4QsgrW',
    'enterprise': 'price_1SspdtHVqJxZgWX0J2ZR4dIU',
}


@login_required
@require_POST
@transaction.atomic
@ratelimit(key='ip', rate='5/m', block=True)
def create_checkout_session(request):
    tier = request.POST.get('tier')

    if tier not in PRICE_IDS:
        return JsonResponse({'success': False, 'error': 'Invalid tier'}, status=400)

    try:
        session = stripe.checkout.Session.create(
            customer_email=request.user.email,
            mode='subscription',
            line_items=[{
                'price': PRICE_IDS[tier],
                'quantity': 1,
            }],
            metadata={
                'user_id': str(request.user.id),
                'tier': tier,
            },
            success_url=request.build_absolute_uri('/success/') + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.build_absolute_uri('/buy/'),
        )
        return redirect(session.url)
    except stripe.error.StripeError:
        return JsonResponse({'success': False, 'error': 'Payment service unavailable'}, status=503)


@csrf_exempt
@require_POST
@ratelimit(key='ip', rate='20/m', block=True)
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

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('metadata', {}).get('user_id')
        tier = session.get('metadata', {}).get('tier')
        customer_id = session.get('customer')

        if user_id and tier:
            try:
                user = User.objects.get(id=int(user_id))
                user.Tier = tier
                user.stripe_customer_id = customer_id
                user.subscription_status = 'active'
                user.save(update_fields=['Tier', 'stripe_customer_id', 'subscription_status'])
            except (User.DoesNotExist, ValueError):
                pass

    elif event['type'] == 'invoice.paid':
        invoice = event['data']['object']
        customer_id = invoice.get('customer')

        if customer_id:
            try:
                user = User.objects.get(stripe_customer_id=customer_id)
                user.subscription_status = 'active'
                user.save(update_fields=['subscription_status'])
            except User.DoesNotExist:
                pass

    elif event['type'] == 'invoice.payment_failed':
        invoice = event['data']['object']
        customer_id = invoice.get('customer')

        if customer_id:
            try:
                user = User.objects.get(stripe_customer_id=customer_id)
                user.subscription_status = 'past_due'
                user.save(update_fields=['subscription_status'])
            except User.DoesNotExist:
                pass

    elif event['type'] == 'customer.subscription.deleted':
        subscription = event['data']['object']
        customer_id = subscription.get('customer')

        if customer_id:
            try:
                user = User.objects.get(stripe_customer_id=customer_id)
                user.Tier = 'free'
                user.subscription_status = 'canceled'
                user.save(update_fields=['Tier', 'subscription_status'])
            except User.DoesNotExist:
                pass

    return HttpResponse(status=200)


@login_required
def success(request):
    return render(request, 'success.html', {
        'plan_name': request.session.get('plan_name', 'Student'),
        'amount': request.session.get('amount', '5.00'),
        'user': request.user
    })



def buy(request):
    return render(request, 'buy.html')


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_documents(request, project_id):
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

        user_team_ids = TeamMember.objects.filter(
            team__project_id=project_id,
            user=request.user
        ).values_list('team_id', flat=True)

        documents = Documents.objects.filter(
            project_id=project_id,
            team_assigned_id__in=user_team_ids
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


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_document(request, project_id, doc_id):
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


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def add_document(request, project_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

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
                return JsonResponse({'success': False, 'error': 'Only owners, admins and team admins can create documents'}, status=403)

            if team_admin_membership.team_id != team_id:
                return JsonResponse({'success': False, 'error': 'You can only create documents for your own team'}, status=403)

    tier = project.tier.lower()
    tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])
    max_docs = tier_config.get('documents')

    if max_docs is not None:
        current_doc_count = Documents.objects.filter(project_id=project_id).count()
        if current_doc_count >= max_docs:
            return JsonResponse({'success': False, 'error': f'Document limit ({max_docs}) reached for your tier'}, status=403)

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


@require_POST
@require_auth_token
@require_editor_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def save_document(request, project_id, doc_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    if not isinstance(project_id, int) or project_id < 1:
        return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

    if not isinstance(doc_id, int) or doc_id < 1:
        return JsonResponse({'success': False, 'error': 'Invalid document ID'}, status=400)

    content = data.get('content')

    if content is None:
        return JsonResponse({'success': False, 'error': 'Content required'}, status=400)

    if not isinstance(content, str):
        return JsonResponse({'success': False, 'error': 'Invalid content type'}, status=400)

    try:
        with transaction.atomic():
            project = Project.objects.get(id=project_id)
            document = Documents.objects.select_for_update().get(id=doc_id, project_id=project_id)

            is_owner = project.owner_id == request.user.id
            tier = project.tier.lower()
            tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])

            if not is_owner:
                is_contributor = Contributor.objects.filter(
                    project_id=project_id,
                    username=request.user.username
                ).exists()

                if not is_contributor:
                    return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

                membership = TeamMember.objects.filter(
                    team_id=document.team_assigned_id,
                    user=request.user
                ).first()

                if not membership:
                    return JsonResponse({'success': False, 'error': 'Not a team member'}, status=403)

                if membership.role == 'EDITOR':
                    if not membership.can_direct_save and tier_config.get('pending', False):
                        Pending.objects.create(
                            project=project,
                            team=document.team_assigned,
                            document=document,
                            user=request.user,
                            submitted_content=content
                        )
                        return JsonResponse({'success': True, 'pending': True})
                elif membership.role != 'ADMIN':
                    return JsonResponse({'success': False, 'error': 'Invalid role'}, status=403)

            if document.content == content:
                return JsonResponse({'success': True, 'message': 'No changes'})

            if project.backups_enabled and tier_config.get('backups', False):
                backup_count = Backup.objects.filter(document=document).count()
                max_backups = 50

                if backup_count >= max_backups:
                    Backup.objects.filter(document=document).order_by('created_at').first().delete()

                Backup.objects.create(
                    project=project,
                    document=document,
                    content=document.content
                )

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


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='10/m', block=True)
@csrf_protect
def rename_document(request, project_id, doc_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    new_name = data.get('document_name', '').strip()

    if not new_name:
        return JsonResponse({'success': False, 'error': 'Document name required'})

    if len(new_name) > 255:
        return JsonResponse({'success': False, 'error': 'Document name too long'})

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
        is_team_admin = TeamMember.objects.filter(
            team_id=document.team_assigned_id,
            user=request.user,
            role='ADMIN'
        ).exists()

        if not is_team_admin:
            return JsonResponse({'success': False, 'error': 'Only project owner or team admin can rename documents'}, status=403)

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


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='10/m', block=True)
@csrf_exempt
def delete_document(request, project_id, doc_id):
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
        is_team_admin = TeamMember.objects.filter(
            team_id=document.team_assigned_id,
            user=request.user,
            role='ADMIN'
        ).exists()

        if not is_team_admin:
            return JsonResponse({'success': False, 'error': 'Only project owner or team admin can delete documents'}, status=403)

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

@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_teams(request, project_id):
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
    else:
        teams = Teams.objects.filter(project_id=project_id).order_by('team_name')

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


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_pending_edits(request, project_id):
    if not isinstance(project_id, int) or project_id < 1:
        return JsonResponse({'success': False, 'error': 'Invalid project ID'}, status=400)

    project = Project.objects.filter(id=project_id).first()

    if not project:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    is_owner = project.owner_id == request.user.id

    if not is_owner:
        is_admin = TeamMember.objects.filter(
            team__project_id=project_id,
            user=request.user,
            role='ADMIN'
        ).exists()

        if not is_admin:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

    tier = project.tier.lower()
    tier_config = TIER_LIMITS.get(tier, TIER_LIMITS['free'])

    if not tier_config.get('pending', False):
        return JsonResponse({'success': False, 'error': 'Pending edits not available for your tier'}, status=403)

    if is_owner:
        pending_edits = Pending.objects.filter(
            project_id=project_id
        ).select_related('document', 'user', 'team').order_by('-created_at')
    else:
        admin_team_ids = TeamMember.objects.filter(
            team__project_id=project_id,
            user=request.user,
            role='ADMIN'
        ).values_list('team_id', flat=True)

        pending_edits = Pending.objects.filter(
            project_id=project_id,
            team_id__in=admin_team_ids
        ).select_related('document', 'user', 'team').order_by('-created_at')

    pending_data = [{
        'id': p.id,
        'document_id': p.document.id,
        'document_name': p.document.document_name,
        'username': p.user.username,
        'team_name': p.team.team_name,
        'submitted_content': p.submitted_content,
        'created_at': p.created_at.isoformat()
    } for p in pending_edits]

    return JsonResponse({'success': True, 'pending': pending_data})


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def get_audits(request, project_id):
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
    ).select_related('document', 'user').order_by('-created_at')[:100]

    audits_data = [{
        'id': audit.id,
        'username': audit.user.username,
        'document_name': audit.document.document_name if audit.document else 'N/A',
        'action': audit.action,
        'created_at': audit.created_at.isoformat()
    } for audit in audits]

    return JsonResponse({'success': True, 'audits': audits_data})


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def create_team(request, project_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

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
            return JsonResponse({'success': False, 'error': f'Team limit ({max_teams}) reached for your tier'}, status=403)

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


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def update_team(request, project_id, team_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

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


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def delete_team(request, project_id, team_id):
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


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def add_team_member(request, project_id, team_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

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
            return JsonResponse({'success': False, 'error': f'Member limit ({max_members}) reached for your tier'}, status=403)

    TeamMember.objects.create(team=team, user=user, role=role)

    return JsonResponse({
        'success': True,
        'member': {
            'id': user.id,
            'username': user.username,
            'role': role
        }
    })


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def remove_team_member(request, project_id, team_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

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


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def update_team_member_role(request, project_id, team_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

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


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='10/m', block=True)
def update_team_member_review(request, project_id, team_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

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


@login_required
@require_POST
@ratelimit(key='ip', rate='5/m', block=True)
def cancel_subscription(request):
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

        request.user.subscription_status = 'canceled'
        request.user.save(update_fields=['subscription_status'])

        return JsonResponse({'success': True})

    except stripe.error.StripeError:
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@login_required
@require_POST
@ratelimit(key='ip', rate='3/m', block=True)
def delete_account(request):
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
            pass

    auth_logout(request)
    user.delete()

    return JsonResponse({'success': True})