from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.cache import cache_page
from django.db import transaction
from django.db.models import Q
from django.conf import settings
import json
import jwt
from datetime import datetime, timedelta
from django_ratelimit.decorators import ratelimit
from functools import wraps

from .forms import LoginForm, RegisterForm
from .models import Project, Contributor, Pending, User, Backup

JWT_SECRET = settings.JWT_SECRET
JWT_EXPIRY_HOURS = 1


def home(request):
    return render(request, 'index.html')


def generate_auth_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS512')


def verify_auth_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS512'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth_token(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')

        if not token:
            return JsonResponse({'success': False, 'error': 'Auth token required'}, status=401)

        payload = verify_auth_token(token)
        if not payload:
            return JsonResponse({'success': False, 'error': 'Invalid or expired token'}, status=401)

        if not request.user.is_authenticated or payload['user_id'] != request.user.id:
            return JsonResponse({'success': False, 'error': 'Token user mismatch'}, status=403)

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
        return render(request, 'setup.html')

    project_name = request.POST.get('project_name', '').strip()
    raw_people = request.POST.get('people', '')
    backups = request.POST.get('backups')

    if not project_name:
        return JsonResponse({'success': False, 'error': 'Project name is required'})

    if len(project_name) > 255:
        return JsonResponse({'success': False, 'error': 'Project name too long'})

    people = list({p.strip() for p in raw_people.split() if p.strip()})

    with transaction.atomic():
        project = Project.objects.create(
            owner=request.user,
            project_name=project_name,
            people=','.join(people),
            backups_enabled=bool(backups)
        )

        if people:
            Contributor.objects.bulk_create(
                [Contributor(project=project, username=p, role='VIEWER') for p in people]
            )

    return redirect('dashboard')


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='5/', block=True)
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

    if new_role not in ('VIEWER', 'EDITOR'):
        return JsonResponse({'success': False, 'error': 'Invalid role'})

    updated = Contributor.objects.filter(
        Q(id=contributor_id) & Q(project_id=project_id) & Q(project__owner_id=request.user.id)
    ).update(role=new_role)

    if not updated:
        return JsonResponse({'success': False, 'error': 'Contributor not found'}, status=404)

    return JsonResponse({'success': True})

@ratelimit(key='ip', rate='5//', block=True)
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

    if not Project.objects.filter(id=project_id, owner_id=request.user.id).exists():
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    people = list({p.strip() for p in usernames.split() if p.strip()})
    if not people:
        return JsonResponse({'success': False, 'error': 'No usernames provided'})

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

@ratelimit(key='ip', rate='5/', block=True)
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
        token = generate_auth_token(user.id)
        return JsonResponse({'success': True, 'redirect': '/dashboard/', 'token': token})

    except Exception as e:
        return JsonResponse({'success': False, 'error': f'Server error {e}'}, status=500)

@ratelimit(key='ip', rate='5/', block=True)
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
        token = generate_auth_token(user.id)
        return JsonResponse({'success': True, 'redirect': '/dashboard/', 'token': token})

    except Exception:
        return JsonResponse({'success': False, 'error': 'Server error'}, status=500)


@require_POST
def logout_view(request):
    auth_logout(request)
    return redirect('login')


@require_POST
@require_auth_token
@ratelimit(key='ip', rate='5/', block=True)
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


@require_POST
@require_auth_token
@require_editor_token
@ratelimit(key='ip', rate='5/', block=True)
def save_docs(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    project_id = data.get('project_id')
    content = data.get('content')

    if project_id is None or content is None:
        return JsonResponse({'success': False, 'error': 'Missing required fields'})

    try:
        project = Project.objects.select_for_update().get(id=project_id)
    except Project.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)

    is_owner = project.owner_id == request.user.id

    if not is_owner:
        contributor = Contributor.objects.filter(
            project_id=project_id,
            username=request.user.username
        ).values('role').first()

        if not contributor:
            return JsonResponse({'success': False, 'error': 'Not authorized'}, status=403)

        if contributor['role'] == 'VIEWER':
            return JsonResponse({'success': False, 'error': 'Viewers cannot edit'}, status=403)

        if contributor['role'] == 'EDITOR':
            Pending.objects.create(
                submitted_content=content,
                project_id=project_id,
                username=request.user.username
            )
            return JsonResponse({'success': True, 'pending': True})

    with transaction.atomic():
        if project.backups_enabled and project.content != content:
            Backup.objects.create(
                owner_id=request.user.id,
                project_id=project_id,
                content=project.content
            )
        project.content = content
        project.save(update_fields=['content'])

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


def logout(request):
    auth_logout(request)
    return redirect('login')
