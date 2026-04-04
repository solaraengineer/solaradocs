from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET
from django.http import JsonResponse
from django.shortcuts import render
from django.db.models import Count, Sum, Q, F
from django.db.models.functions import TruncDate, TruncMonth
from django.utils import timezone
from django_ratelimit.decorators import ratelimit
from solaradocs.models import *
from django.core.cache import cache
import json
import string
import random
from datetime import timedelta


def admin_required(view_func):
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
@admin_required
def admin_panel(request):
    now = timezone.now()
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)

    users = User.objects.all().prefetch_related('owned_projects')
    projects = Project.objects.all().select_related('owner').prefetch_related('project_documents', 'project_teams')
    changelogs = Changelog.objects.all().order_by('-created_at')
    promo_codes = PromoCodes.objects.all().order_by('-created_at')

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
        'promo_codes': promo_codes,
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
@ratelimit(key='ip', rate='5/m', block=True)
def admin_broadcast_announcement(request):
    """Set a broadcast alert banner visible to all users, stored in redis with TTL."""
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    title = data.get('title', '').strip()
    if not title:
        return JsonResponse({'success': False, 'error': 'Alert title cannot be empty'}, status=400)

    duration = data.get('duration')
    if duration not in [30, 60, 120, 240, 480]:
        return JsonResponse({'success': False, 'error': 'Invalid duration'}, status=400)

    alert_data = json.dumps({
        'title': title,
        'created_at': timezone.now().isoformat(),
    })
    cache.set('broadcast:alert', alert_data, timeout=duration * 60)

    return JsonResponse({'success': True, 'message': 'Broadcast alert is now live'})


@csrf_exempt
@require_POST
@admin_required
@ratelimit(key='ip', rate='5/m', block=True)
def admin_dismiss_alert(request):
    """Manually dismiss the active broadcast alert."""
    deleted = cache.delete('broadcast:alert')
    if deleted:
        return JsonResponse({'success': True, 'message': 'Alert dismissed'})
    return JsonResponse({'success': True, 'message': 'No active alert to dismiss'})


# ─── Promo Code Management ─────────────────────────────────

PROMO_EXPIRY_DURATIONS = {
    '15m': timedelta(minutes=15),
    '30m': timedelta(minutes=30),
    '1h': timedelta(hours=1),
    '2h': timedelta(hours=2),
    '4h': timedelta(hours=4),
    '24h': timedelta(hours=24),
    '1d': timedelta(days=1),
    '3d': timedelta(days=3),
    '7d': timedelta(days=7),
    'never': None,
}

PROMO_CODE_CHARS = string.ascii_uppercase + string.digits


@csrf_exempt
@require_POST
@admin_required
@ratelimit(key='ip', rate='10/m', block=True)
def admin_create_promo(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    code = data.get('code', '').strip().upper()
    if not code or len(code) > 8 or not all(c in PROMO_CODE_CHARS for c in code):
        return JsonResponse({'success': False, 'error': 'Code must be 1-8 characters, A-Z and 0-9 only'}, status=400)

    tier = data.get('tier', '')
    valid_tiers = [t[0] for t in TIER_CHOICES]
    if tier not in valid_tiers:
        return JsonResponse({'success': False, 'error': f'Invalid tier. Must be one of: {", ".join(valid_tiers)}'}, status=400)

    expiry_key = data.get('expires', 'never')
    if expiry_key not in PROMO_EXPIRY_DURATIONS:
        return JsonResponse({'success': False, 'error': 'Invalid expiry duration'}, status=400)

    duration = PROMO_EXPIRY_DURATIONS[expiry_key]
    expires_at = timezone.now() + duration if duration else None

    left_uses = data.get('left_uses', 1)
    if not isinstance(left_uses, int) or left_uses < 1 or left_uses > 100000:
        return JsonResponse({'success': False, 'error': 'Uses must be between 1 and 100,000'}, status=400)

    if PromoCodes.objects.filter(code=code).exists():
        return JsonResponse({'success': False, 'error': 'Code already exists'}, status=400)

    promo = PromoCodes.objects.create(
        code=code,
        tier=tier,
        expires_at=expires_at,
        left_uses=left_uses,
    )

    return JsonResponse({'success': True, 'id': promo.id})


@csrf_exempt
@require_POST
@admin_required
@ratelimit(key='ip', rate='10/m', block=True)
def admin_delete_promo(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    deleted, _ = PromoCodes.objects.filter(id=data.get('promo_id')).delete()
    if not deleted:
        return JsonResponse({'success': False, 'error': 'Promo code not found'}, status=404)
    return JsonResponse({'success': True})