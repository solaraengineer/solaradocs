from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
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
from .models import Project, Contributor, Pending, User, Backup, Audit, Documents, Teams, TeamMember

JWT_SECRET = settings.JWT_SECRET
JWT_EXPIRY_HOURS = 1

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
    return jwt.encode(payload, JWT_SECRET, algorithm='HS512')


def verify_auth_token(token, verify_expiration=True):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS512'], options={'verify_exp': verify_expiration})
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
            request.user = User.objects.get(id=payload['user_id'])
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'User not found'}, status=401)

        return view_func(request, *args, **kwargs)

    return wrapper


def generate_editor_token(user_id, project_id):
    payload = {
        'user_id': user_id,
        'project_id': project_id,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS512')


def verify_editor_token(token, project_id):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS512'])
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
def setup(request):
    if request.method == 'GET':
        user_tier = request.user.Tier
        tier_config = TIER_LIMITS.get(user_tier, TIER_LIMITS['free'])
        return render(request, 'setup.html', {'tier': user_tier, 'tier_config': tier_config})

    project_name = request.POST.get('project_name', '').strip()
    raw_people = request.POST.get('people', '')
    backups = request.POST.get('backups')

    if not project_name:
        return JsonResponse({'success': False, 'error': 'Project name is required'})

    if len(project_name) > 100:
        return JsonResponse({'success': False, 'error': 'Project name too long'})

    user_tier = request.user.Tier
    tier_config = TIER_LIMITS.get(user_tier, TIER_LIMITS['free'])

    current_project_count = Project.objects.filter(owner=request.user).count()
    max_projects = tier_config.get('projects')
    if max_projects is not None and current_project_count >= max_projects:
        return JsonResponse({'success': False, 'error': 'Project limit reached for your tier'})

    people = list({p.strip() for p in raw_people.split() if p.strip()})

    max_collaborators = tier_config.get('members')
    if max_collaborators is not None and len(people) > max_collaborators:
        return JsonResponse({'success': False, 'error': f'Collaborator limit is {max_collaborators} for your tier'})

    backups_allowed = tier_config.get('backups', False)
    backups_enabled = bool(backups) and backups_allowed

    if user_tier not in TIER_LIMITS:
        return JsonResponse({'success': False, 'error': 'Invalid tier'})

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
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    project_id = data.get('project_id')
    contributor_id = data.get('contributor_id')
    new_role = data.get('role', '').upper()

    if not all([project_id, contributor_id, new_role]):
        return JsonResponse({'success': False, 'error': 'Missing required fields'})

    if new_role not in ('VIEWER', 'EDITOR', 'ADMIN'):
        return JsonResponse({'success': False, 'error': 'Invalid role'})

    updated = Contributor.objects.filter(
        Q(id=contributor_id) & Q(project_id=project_id) & Q(project__owner_id=request.user.id)
    ).update(role=new_role)

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
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    project_id = data.get('project_id')
    usernames = data.get('usernames', '')

    if not project_id:
        return JsonResponse({'success': False, 'error': 'Project ID required'})

    try:
        project = Project.objects.get(id=project_id, owner_id=request.user.id)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    people = list({p.strip() for p in usernames.split() if p.strip()})
    if not people:
        return JsonResponse({'success': False, 'error': 'No usernames provided'})

    # Validate users exist
    for username in people:
        if not User.objects.filter(username=username).exists():
            return JsonResponse({'success': False, 'error': f'User {username} not found'})

    user_tier = request.user.Tier
    tier_config = TIER_LIMITS.get(user_tier, TIER_LIMITS['free'])
    max_collaborators = tier_config.get('members')

    current_count = Contributor.objects.filter(project_id=project_id).count()
    if max_collaborators is not None and (current_count + len(people)) > max_collaborators:
        return JsonResponse({'success': False, 'error': f'Collaborator limit is {max_collaborators} for your tier'})

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


@cache_page(60 * 15)
@require_GET
def docs(request):
    return render(request, 'docs.html')


@ratelimit(key='ip', rate='5/m', block=True)
def login(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'GET':
        return render(request, 'login.html', {'form': LoginForm()})

    try:
        form = LoginForm(request.POST)
        if not form.is_valid():
            return JsonResponse({'success': False, 'error': 'Invalid form data'})

        username = form.cleaned_data['username']
        password = form.cleaned_data['password']

        if not username or not password:
            return JsonResponse({'success': False, 'error': 'Invalid credentials'}, status=401)

        user = authenticate(request, username=username, password=password)

        if user is None:
            return JsonResponse({'success': False, 'error': 'Invalid credentials'}, status=401)

        auth_login(request, user)
        user_id = request.user.id
        token = generate_auth_token(user_id)
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
            return JsonResponse({'success': False, 'error': 'Invalid form data'})

        username = form.cleaned_data['username']
        email = form.cleaned_data['email']
        password = form.cleaned_data['password']

        existing = User.objects.filter(
            Q(username=username) | Q(email=email)
        ).values('username', 'email').first()

        if existing:
            if existing['username'] == username:
                return JsonResponse({'success': False, 'error': 'Username taken'})
            return JsonResponse({'success': False, 'error': 'Email taken'})

        user = User.objects.create_user(username=username, password=password, email=email)
        auth_login(request, user)
        user_id = request.user.id
        token = generate_auth_token(user_id)
        return JsonResponse({'success': True, 'redirect': '/dashboard/', 'token': token})

    except Exception:
        return JsonResponse({'success': False, 'error': str({e})}, status=500)


@require_POST
def logout_view(request):
    auth_logout(request)
    return redirect('login')


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='5/m', block=True)
def deleteuser(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    project_id = data.get('project_id')
    contributor_id = data.get('contributor_id')

    if not all([project_id, contributor_id]):
        return JsonResponse({'success': False, 'error': 'Missing required fields'})

    Contributor.objects.filter(
        Q(id=contributor_id) & Q(project_id=project_id) & Q(project__owner_id=request.user.id)
    ).delete()

    return JsonResponse({'success': True})




@require_GET
@require_auth_token
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
@ensure_csrf_cookie
def delete_project(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    project_id = data.get('project_id')
    if not project_id:
        return JsonResponse({'success': False, 'error': 'Project ID required'})

    deleted, _ = Project.objects.filter(id=project_id, owner_id=request.user.id).delete()

    if not deleted:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    return JsonResponse({'success': True})


@require_POST
@require_auth_token
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


@login_required
@require_POST
def create_checkout_session(request):
    tier = request.POST.get('tier')

    prices = {
        'student': {'amount': 500, 'name': 'Student', 'display_price': '5.00'},
        'team': {'amount': 1500, 'name': 'Team', 'display_price': '15.00'},
        'enterprise': {'amount': 3500, 'name': 'Large Teams', 'display_price': '35.00'},
    }

    if tier not in prices:
        return JsonResponse({'success': False, 'error': 'Invalid tier'}, status=400)

    selected_tier = prices[tier]

    request.session['plan_name'] = selected_tier['name']
    request.session['amount'] = selected_tier['display_price']
    request.session['tier'] = tier

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': selected_tier['name'],
                    },
                    'unit_amount': selected_tier['amount'],
                },
                'quantity': 1,
            }],
            mode='payment',
            customer_email=request.user.email,
            metadata={
                'plan_tier': tier,
                'user_id': str(request.user.id),
            },
            success_url=request.build_absolute_uri('/success/') + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.build_absolute_uri('/buy/'),
        )
        return redirect(session.url)
    except stripe.error.StripeError:
        return JsonResponse({'success': False, 'error': 'Payment service unavailable'}, status=503)


@login_required
def success(request):
    return render(request, 'success.html', {
        'plan_name': request.session.get('plan_name', 'Student'),
        'amount': request.session.get('amount', '5.00'),
        'user': request.user
    })


@csrf_exempt
@require_POST
def stripe_webhook(request):
    payload = request.body
    sig_header = request.headers.get('Stripe-Signature', '')
    webhook_secret = settings.STRIPE_WEBHOOK_SECRET

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except ValueError:
        return JsonResponse({'success': False, 'error': 'Invalid payload'}, status=400)
    except stripe.error.SignatureVerificationError:
        return JsonResponse({'success': False, 'error': 'Invalid signature'}, status=400)

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('metadata', {}).get('user_id')
        tier = session.get('metadata', {}).get('plan_tier')

        if user_id and tier and session.get('payment_status') == 'paid':
            try:
                user = User.objects.get(id=int(user_id))
                user.Tier = tier
                user.save(update_fields=['Tier'])
            except (User.DoesNotExist, ValueError):
                pass

    return JsonResponse({'success': True})


def buy(request):
    return render(request, 'buy.html')


@require_GET
@require_auth_token
def get_documents(request, project_id):
    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    is_owner = project.owner_id == request.user.id

    if not is_owner:
        contributor = Contributor.objects.filter(
            project_id=project_id,
            username=request.user.username
        ).first()

        if not contributor:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        user_team_ids = TeamMember.objects.filter(
            team__project_id=project_id,
            user=request.user
        ).values_list('team_id', flat=True)

        documents = Documents.objects.filter(
            project_id=project_id,
            team_assigned_id__in=user_team_ids
        ).select_related('team_assigned').order_by('-created_at')
    else:
        documents = Documents.objects.filter(
            project_id=project_id
        ).select_related('team_assigned').order_by('-created_at')

    docs_data = [{
        'id': doc.id,
        'document_name': doc.document_name,
        'team_name': doc.team_assigned.team_name,
        'team_id': doc.team_assigned_id,
        'created_at': doc.created_at.isoformat()
    } for doc in documents]

    return JsonResponse({'success': True, 'documents': docs_data})


@require_GET
@require_auth_token
def get_document(request, project_id, doc_id):
    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    try:
        document = Documents.objects.select_related('team_assigned').get(
            id=doc_id,
            project_id=project_id
        )
    except Documents.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Document not found'}, status=404)

    is_owner = project.owner_id == request.user.id

    if not is_owner:
        is_contributor = Contributor.objects.filter(
            project_id=project_id,
            username=request.user.username
        ).exists()

        if not is_contributor:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        is_team_member = TeamMember.objects.filter(
            team_id=document.team_assigned_id,
            user=request.user
        ).exists()

        if not is_team_member:
            return JsonResponse({'success': False, 'error': 'Not a member of this document\'s team'}, status=403)

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
@ratelimit(key='ip', rate='10/m', block=True)
@csrf_exempt
def add_document(request, project_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    document_name = data.get('document_name', '').strip()
    team_id = data.get('team_id')

    if not document_name:
        return JsonResponse({'success': False, 'error': 'Document name required'})

    if len(document_name) > 255:
        return JsonResponse({'success': False, 'error': 'Document name too long'})

    if not team_id:
        return JsonResponse({'success': False, 'error': 'Team ID required'})

    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    try:
        team = Teams.objects.get(id=team_id, project_id=project_id)
    except Teams.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

    is_owner = project.owner_id == request.user.id

    if not is_owner:
        is_contributor = Contributor.objects.filter(
            project_id=project_id,
            username=request.user.username
        ).exists()

        if not is_contributor:
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        is_team_admin = TeamMember.objects.filter(
            team=team,
            user=request.user,
            role='ADMIN'
        ).exists()

        if not is_team_admin:
            return JsonResponse({'success': False, 'error': 'Only owners and team admins can create documents'},
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


@require_POST
@require_auth_token
@require_editor_token
@csrf_exempt
@ratelimit(key='ip', rate='30/m', block=True)
def save_document(request, project_id, doc_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    content = data.get('content')

    if content is None:
        return JsonResponse({'success': False, 'error': 'Content required'})

    try:
        with transaction.atomic():
            project = Project.objects.select_for_update().get(id=project_id)
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
                    if tier_config.get('pending', False):
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


@require_GET
@require_auth_token
def get_teams(request, project_id):
    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
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
                'role': m.role
            } for m in members]
        })

    return JsonResponse({'success': True, 'teams': teams_data})


@require_GET
@require_auth_token
def get_audits(request, project_id):
    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
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
@ratelimit(key='ip', rate='10/m', block=True)
def create_team(request, project_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    team_name = data.get('team_name', '').strip()

    if not team_name:
        return JsonResponse({'success': False, 'error': 'Team name required'})

    if len(team_name) > 255:
        return JsonResponse({'success': False, 'error': 'Team name too long'})

    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
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
        return JsonResponse({'success': False, 'error': 'Team name already exists in this project'})

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
@ratelimit(key='ip', rate='10/m', block=True)
def update_team(request, project_id, team_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    if project.owner_id != request.user.id:
        return JsonResponse({'success': False, 'error': 'Only project owner can edit teams'}, status=403)

    try:
        team = Teams.objects.get(id=team_id, project_id=project_id)
    except Teams.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

    team_name = data.get('team_name', '').strip()

    if team_name:
        if len(team_name) > 255:
            return JsonResponse({'success': False, 'error': 'Team name too long'})
        if Teams.objects.filter(project_id=project_id, team_name=team_name).exclude(id=team_id).exists():
            return JsonResponse({'success': False, 'error': 'Team name already exists'})
        team.team_name = team_name
        team.save()

    return JsonResponse({
        'success': True,
        'team': {
            'id': team.id,
            'team_name': team.team_name
        }
    })


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='10/m', block=True)
def delete_team(request, project_id, team_id):
    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    if project.owner_id != request.user.id:
        return JsonResponse({'success': False, 'error': 'Only project owner can delete teams'}, status=403)

    deleted, _ = Teams.objects.filter(id=team_id, project_id=project_id).delete()

    if not deleted:
        return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

    return JsonResponse({'success': True})


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='10/m', block=True)
def add_team_member(request, project_id, team_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    username = data.get('username', '').strip()
    role = data.get('role', 'EDITOR').upper()

    if not username:
        return JsonResponse({'success': False, 'error': 'Username required'})

    if role not in ('EDITOR', 'ADMIN'):
        return JsonResponse({'success': False, 'error': 'Invalid role'})

    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    if project.owner_id != request.user.id:
        return JsonResponse({'success': False, 'error': 'Only project owner can add team members'}, status=403)

    try:
        team = Teams.objects.get(id=team_id, project_id=project_id)
    except Teams.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

    is_contributor = Contributor.objects.filter(
        project_id=project_id,
        username=username
    ).exists()

    if not is_contributor:
        return JsonResponse({'success': False, 'error': 'User must be a contributor first'})

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not found'}, status=404)

    if TeamMember.objects.filter(team=team, user=user).exists():
        return JsonResponse({'success': False, 'error': 'User already in team'})

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


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='10/m', block=True)
def remove_team_member(request, project_id, team_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    username = data.get('username', '').strip()

    if not username:
        return JsonResponse({'success': False, 'error': 'Username required'})

    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    if project.owner_id != request.user.id:
        return JsonResponse({'success': False, 'error': 'Only project owner can remove team members'}, status=403)

    try:
        team = Teams.objects.get(id=team_id, project_id=project_id)
    except Teams.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not found'}, status=404)

    deleted, _ = TeamMember.objects.filter(team=team, user=user).delete()

    if not deleted:
        return JsonResponse({'success': False, 'error': 'User not in team'})

    return JsonResponse({'success': True})


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='10/m', block=True)
def update_team_member_role(request, project_id, team_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    username = data.get('username', '').strip()
    role = data.get('role', '').upper()

    if not username:
        return JsonResponse({'success': False, 'error': 'Username required'})

    if role not in ('EDITOR', 'ADMIN'):
        return JsonResponse({'success': False, 'error': 'Invalid role'})

    try:
        project = Project.objects.get(id=project_id)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    if project.owner_id != request.user.id:
        return JsonResponse({'success': False, 'error': 'Only project owner can change member roles'}, status=403)

    try:
        team = Teams.objects.get(id=team_id, project_id=project_id)
    except Teams.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not found'}, status=404)

    try:
        membership = TeamMember.objects.get(team=team, user=user)
    except TeamMember.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'User not in team'}, status=404)

    membership.role = role
    membership.save()

    return JsonResponse({
        'success': True,
        'member': {
            'id': user.id,
            'username': user.username,
            'role': role
        }
    })