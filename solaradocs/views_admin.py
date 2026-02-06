from django.views.decorators.csrf import csrf_exempt

from solaradocs.models import *
import json
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET
from django.contrib.auth.decorators import login_required
from django_ratelimit.decorators import ratelimit


def admin_required(view_func):
    """Decorator that checks user is authenticated and is a superuser."""
    from functools import wraps
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({'success': False, 'error': 'Authentication required'}, status=401)
        if not request.user.is_superuser:
            return JsonResponse({'success': False, 'error': 'Admin access required'}, status=403)
        return view_func(request, *args, **kwargs)
    return wrapper


#@admin_required
@ratelimit(key='ip', rate='30/m', block=True)
def admin_panel(request):
    users = User.objects.all().prefetch_related('owned_projects')
    projects = Project.objects.all().select_related('owner').prefetch_related('project_documents', 'project_teams')
    changelogs = Changelog.objects.all()

    stats = {
        'total_users': User.objects.count(),
        'total_projects': Project.objects.count(),
        'total_documents': Documents.objects.count(),
        'paid_users': User.objects.exclude(Tier='free').count(),
    }

    return render(request, 'admin.html', {
        'users': users,
        'projects': projects,
        'changelogs': changelogs,
        'stats': stats,
    })


@require_POST
@admin_required
@ratelimit(key='ip', rate='5/m', block=True)
def admin_update_user(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    user = User.objects.filter(id=data.get('user_id')).first()
    if not user:
        return JsonResponse({'success': False, 'error': 'User not found'}, status=404)
    tier = data.get('tier', '')
    if tier not in ('free', 'personal', 'team', 'enterprise'):
        return JsonResponse({'success': False, 'error': 'Invalid tier'}, status=400)
    user.Tier = tier
    user.save(update_fields=['Tier'])
    return JsonResponse({'success': True})


@require_POST
@admin_required
@ratelimit(key='ip', rate='3/m', block=True)
def admin_delete_user(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    deleted, _ = User.objects.filter(id=data.get('user_id')).delete()
    if not deleted:
        return JsonResponse({'success': False, 'error': 'User not found'}, status=404)
    return JsonResponse({'success': True})


@require_POST
@admin_required
@ratelimit(key='ip', rate='3/m', block=True)
def admin_delete_project(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    deleted, _ = Project.objects.filter(id=data.get('project_id')).delete()
    if not deleted:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)
    return JsonResponse({'success': True})


@require_POST
#@admin_required
@csrf_exempt
@ratelimit(key='ip', rate='5/m', block=True)
def admin_add_changelog(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    Changelog.objects.create(
        version=data['version'],
        title=data['title'],
        description=data['description'],
        version_type=data['version_type']
    )
    return JsonResponse({'success': True})


@require_POST
#@admin_required
@ratelimit(key='ip', rate='5/m', block=True)
def admin_update_changelog(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    Changelog.objects.filter(id=data.get('changelog_id')).update(
        version=data['version'],
        title=data['title'],
        description=data['description'],
        version_type=data['version_type']
    )
    return JsonResponse({'success': True})


@require_POST
#@admin_required
@ratelimit(key='ip', rate='3/m', block=True)
def admin_delete_changelog(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)
    deleted, _ = Changelog.objects.filter(id=data.get('changelog_id')).delete()
    if not deleted:
        return JsonResponse({'success': False, 'error': 'Changelog not found'}, status=404)
    return JsonResponse({'success': True})