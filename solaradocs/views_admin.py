from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET
from django.http import JsonResponse
from django.shortcuts import render
from django.db.models import Count, Sum, Q, F
from django.db.models.functions import TruncDate, TruncMonth
from django.utils import timezone
from django_ratelimit.decorators import ratelimit
from solaradocs.models import *
import json
from datetime import timedelta


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


# ─── Dashboard ───────────────────────────────────────────────

@csrf_exempt
@ratelimit(key='ip', rate='30/m', block=True)
def admin_panel(request):
    now = timezone.now()
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)

    users = User.objects.all().prefetch_related('owned_projects')
    projects = Project.objects.all().select_related('owner').prefetch_related('project_documents', 'project_teams')
    changelogs = Changelog.objects.all().order_by('-created_at')

    # signups per day (last 30 days)
    signups_by_day = (
        User.objects
        .filter(date_joined__gte=month_ago)
        .annotate(day=TruncDate('date_joined'))
        .values('day')
        .annotate(count=Count('id'))
        .order_by('day')
    )

    # tier breakdown
    tier_breakdown = (
        User.objects
        .values('Tier')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    stats = {
        'total_users': User.objects.count(),
        'total_projects': Project.objects.count(),
        'total_documents': Documents.objects.count(),
        'paid_users': User.objects.exclude(Tier='free').count(),
        'new_users_week': User.objects.filter(date_joined__gte=week_ago).count(),
        'new_users_month': User.objects.filter(date_joined__gte=month_ago).count(),
        'active_projects': Project.objects.filter(updated_at__gte=week_ago).count() if hasattr(Project, 'updated_at') else 0,
    }

    return render(request, 'admin.html', {
        'users': users,
        'projects': projects,
        'changelogs': changelogs,
        'stats': stats,
        'signups_by_day': json.dumps([
            {'day': str(s['day']), 'count': s['count']} for s in signups_by_day
        ]),
        'tier_breakdown': json.dumps([
            {'tier': t['Tier'] or 'free', 'count': t['count']} for t in tier_breakdown
        ]),
    })


# ─── User Management ────────────────────────────────────────

@csrf_exempt
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
    valid_tiers = ('free', 'student', 'team', 'enterprise')
    if tier not in valid_tiers:
        return JsonResponse({'success': False, 'error': f'Invalid tier. Must be one of: {", ".join(valid_tiers)}'}, status=400)

    user.Tier = tier
    user.save(update_fields=['Tier'])
    return JsonResponse({'success': True})


@csrf_exempt
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


@csrf_exempt
@require_POST
@admin_required
@ratelimit(key='ip', rate='5/m', block=True)
def admin_toggle_user_active(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    user = User.objects.filter(id=data.get('user_id')).first()
    if not user:
        return JsonResponse({'success': False, 'error': 'User not found'}, status=404)

    user.is_active = not user.is_active
    user.save(update_fields=['is_active'])
    return JsonResponse({'success': True, 'is_active': user.is_active})


@csrf_exempt
@require_POST
@admin_required
@ratelimit(key='ip', rate='3/m', block=True)
def admin_toggle_superuser(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    user = User.objects.filter(id=data.get('user_id')).first()
    if not user:
        return JsonResponse({'success': False, 'error': 'User not found'}, status=404)

    if user == request.user:
        return JsonResponse({'success': False, 'error': 'Cannot modify your own superuser status'}, status=400)

    user.is_superuser = not user.is_superuser
    user.save(update_fields=['is_superuser'])
    return JsonResponse({'success': True, 'is_superuser': user.is_superuser})


# ─── Project Management ─────────────────────────────────────

@csrf_exempt
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


@csrf_exempt
@require_POST
@admin_required
@ratelimit(key='ip', rate='5/m', block=True)
def admin_transfer_project(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    project = Project.objects.filter(id=data.get('project_id')).first()
    new_owner = User.objects.filter(id=data.get('new_owner_id')).first()

    if not project:
        return JsonResponse({'success': False, 'error': 'Project not found'}, status=404)
    if not new_owner:
        return JsonResponse({'success': False, 'error': 'New owner not found'}, status=404)

    project.owner = new_owner
    project.save(update_fields=['owner'])
    return JsonResponse({'success': True})


# ─── Changelog Management ───────────────────────────────────

@csrf_exempt
@require_POST
@admin_required
@ratelimit(key='ip', rate='5/m', block=True)
def admin_add_changelog(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    required = ['version', 'title', 'description', 'version_type']
    for field in required:
        if not data.get(field):
            return JsonResponse({'success': False, 'error': f'Missing field: {field}'}, status=400)

    if data['version_type'] not in ('major', 'minor', 'patch'):
        return JsonResponse({'success': False, 'error': 'Invalid version type'}, status=400)

    Changelog.objects.create(
        version=data['version'],
        title=data['title'],
        description=data['description'],
        version_type=data['version_type']
    )
    return JsonResponse({'success': True})


@csrf_exempt
@require_POST
@admin_required
@ratelimit(key='ip', rate='5/m', block=True)
def admin_update_changelog(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    updated = Changelog.objects.filter(id=data.get('changelog_id')).update(
        version=data['version'],
        title=data['title'],
        description=data['description'],
        version_type=data['version_type']
    )
    if not updated:
        return JsonResponse({'success': False, 'error': 'Changelog not found'}, status=404)
    return JsonResponse({'success': True})


@csrf_exempt
@require_POST
@admin_required
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


# ─── System / Misc ───────────────────────────────────────────

@csrf_exempt
@require_POST
@admin_required
@ratelimit(key='ip', rate='2/m', block=True)
def admin_broadcast_announcement(request):
    """Placeholder for sending announcements to all users."""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    message = data.get('message', '').strip()
    if not message:
        return JsonResponse({'success': False, 'error': 'Message cannot be empty'}, status=400)

    # TODO: hook into your notification/email system
    # For now just acknowledge
    return JsonResponse({'success': True, 'message': 'Announcement queued', 'recipients': User.objects.count()})