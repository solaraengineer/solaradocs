from solaradocs.models import *
import json
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET

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
def admin_update_user(request):
    data = json.loads(request.body)
    user = User.objects.get(id=data['user_id'])
    user.Tier = data['tier']
    user.save(update_fields=['Tier'])
    return JsonResponse({'success': True})


@require_POST
def admin_delete_user(request):
    data = json.loads(request.body)
    User.objects.filter(id=data['user_id']).delete()
    return JsonResponse({'success': True})


@require_POST
def admin_delete_project(request):
    data = json.loads(request.body)
    Project.objects.filter(id=data['project_id']).delete()
    return JsonResponse({'success': True})


@require_POST
def admin_add_changelog(request):
    data = json.loads(request.body)
    Changelog.objects.create(
        version=data['version'],
        title=data['title'],
        description=data['description'],
        version_type=data['version_type']
    )
    return JsonResponse({'success': True})


@require_POST
def admin_update_changelog(request):
    data = json.loads(request.body)
    Changelog.objects.filter(id=data['changelog_id']).update(
        version=data['version'],
        title=data['title'],
        description=data['description'],
        version_type=data['version_type']
    )
    return JsonResponse({'success': True})


@require_POST
def admin_delete_changelog(request):
    data = json.loads(request.body)
    Changelog.objects.filter(id=data['changelog_id']).delete()
    return JsonResponse({'success': True})