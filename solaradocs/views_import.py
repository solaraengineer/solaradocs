import json
import logging

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET
from django_ratelimit.decorators import ratelimit

from .models import Project, Contributor, Documents, Teams, TIER_LIMITS
from .views import require_auth_token
from .google_import import (
    get_google_credentials,
    get_picker_access_token,
    validate_picker_doc_ids,
    get_import_job_status,
    get_import_job,
    get_import_state,
    set_import_state,
    set_import_job,
    import_google_docs_task,
)

logger = logging.getLogger(__name__)


def _check_import_permission(request, project):
    if project.owner_id == request.user.id:
        return True

    return Contributor.objects.filter(
        project_id=project.id,
        username=request.user.username,
        role='ADMIN',
    ).exists()


def _get_project_or_error(project_id):
    try:
        return Project.objects.get(id=project_id), None
    except Project.DoesNotExist:
        return None, JsonResponse({'success': False, 'error': 'Project not found'}, status=404)


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='20/m', block=True)
def check_google_auth(request, project_id):
    try:
        project, err = _get_project_or_error(project_id)
        if err:
            return err

        if not _check_import_permission(request, project):
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        creds = get_google_credentials(request.user)

        return JsonResponse({
            'success': True,
            'authenticated': creds is not None,
            'reauth_url': '/accounts/google/login/' if creds is None else None,
        })
    except Exception:
        logger.exception("check_google_auth failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='30/m', block=True)
def picker_config(request, project_id):
    try:
        project, err = _get_project_or_error(project_id)
        if err:
            return err

        if not _check_import_permission(request, project):
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        access_token = get_picker_access_token(request.user)
        if not access_token:
            return JsonResponse({
                'success': False,
                'error': 'Google authentication required',
                'reauth_required': True,
                'reauth_url': '/accounts/google/login/',
            }, status=401)

        api_key = getattr(settings, 'GOOGLE_PICKER_API_KEY', '')
        client_id = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', '') or ''
        app_id = client_id.split('-', 1)[0] if '-' in client_id else ''

        if not api_key or not app_id:
            logger.error("Picker config missing: api_key set=%s, app_id derivable=%s",
                         bool(api_key), bool(app_id))
            return JsonResponse({
                'success': False,
                'error': 'Picker is not configured on the server',
            }, status=500)

        return JsonResponse({
            'success': True,
            'access_token': access_token,
            'api_key': api_key,
            'app_id': app_id,
        })
    except Exception:
        logger.exception("picker_config failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='5/m', block=True)
def start_google_import(request, project_id):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'}, status=400)

    try:
        project, err = _get_project_or_error(project_id)
        if err:
            return err

        if not _check_import_permission(request, project):
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        doc_ids = data.get('doc_ids', [])
        team_id = data.get('team_id')

        if not isinstance(doc_ids, list) or not doc_ids:
            return JsonResponse({'success': False, 'error': 'No documents selected'}, status=400)

        if len(doc_ids) > 50:
            return JsonResponse({'success': False, 'error': 'Maximum 50 documents per import'}, status=400)

        for did in doc_ids:
            if not isinstance(did, str) or not did.strip():
                return JsonResponse({'success': False, 'error': 'Invalid document ID'}, status=400)

        if not isinstance(team_id, int) or team_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid team ID'}, status=400)

        team = Teams.objects.filter(id=team_id, project_id=project_id).first()
        if not team:
            return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

        # MIME validation: under drive.file we only see files the user
        # picked, but Picker happily returns Sheets, Slides, PDFs etc. if
        # the client-side filter is bypassed. Reject anything that isn't
        # a Google Doc before queueing the import task.
        valid, invalid = validate_picker_doc_ids(request.user, doc_ids)
        if valid is None:
            return JsonResponse({
                'success': False,
                'error': 'Google authentication required',
                'reauth_required': True,
            }, status=401)
        if invalid:
            first_reason = next(iter(invalid.values()))
            return JsonResponse({
                'success': False,
                'error': first_reason,
                'invalid': invalid,
            }, status=400)
        if not valid:
            return JsonResponse({'success': False, 'error': 'No valid Google Docs selected'}, status=400)

        tier_config = TIER_LIMITS.get(project.tier.lower(), TIER_LIMITS['free'])
        max_docs = tier_config.get('documents')

        if max_docs is not None:
            current_count = Documents.objects.filter(project_id=project_id).count()
            available_slots = max_docs - current_count
            if len(valid) > available_slots:
                if available_slots <= 0:
                    return JsonResponse({
                        'success': False,
                        'error': f'Document limit ({max_docs}) reached for your tier',
                    }, status=403)
                return JsonResponse({
                    'success': False,
                    'error': f'You can only import {available_slots} more document{"s" if available_slots != 1 else ""} on your tier',
                }, status=403)

        job_entries = []
        ordered_ids = []
        for did in doc_ids:
            if did not in valid:
                continue
            set_import_state(project_id, did, 'pending')
            job_entries.append({'id': did, 'title': valid[did]})
            ordered_ids.append(did)

        set_import_job(project_id, job_entries)

        import_google_docs_task.delay(
            request.user.id, project_id, team_id, ordered_ids
        )

        return JsonResponse({'success': True, 'job_started': True})

    except Exception:
        logger.exception("start_google_import failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_GET
@require_auth_token
@login_required
@ratelimit(key='ip', rate='60/m', block=True)
def import_status(request, project_id):
    try:
        project, err = _get_project_or_error(project_id)
        if err:
            return err

        if not _check_import_permission(request, project):
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        status = get_import_job_status(project_id)
        if status is None:
            return JsonResponse({
                'success': True,
                'has_job': False,
                'docs': [],
                'all_done': True,
                'has_failures': False,
            })

        return JsonResponse({
            'success': True,
            'has_job': True,
            **status,
        })

    except Exception:
        logger.exception("import_status failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)


@require_POST
@require_auth_token
@login_required
@ratelimit(key='ip', rate='5/m', block=True)
def retry_import(request, project_id):
    try:
        project, err = _get_project_or_error(project_id)
        if err:
            return err

        if not _check_import_permission(request, project):
            return JsonResponse({'success': False, 'error': 'Access denied'}, status=403)

        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            data = {}

        team_id = data.get('team_id')
        if not isinstance(team_id, int) or team_id < 1:
            return JsonResponse({'success': False, 'error': 'Invalid team ID'}, status=400)

        team = Teams.objects.filter(id=team_id, project_id=project_id).first()
        if not team:
            return JsonResponse({'success': False, 'error': 'Team not found'}, status=404)

        job_entries = get_import_job(project_id)
        if not job_entries:
            return JsonResponse({'success': False, 'error': 'No import job found'}, status=404)

        retry_ids = []
        for entry in job_entries:
            state, _ = get_import_state(project_id, entry['id'])
            if state != 'done':
                retry_ids.append(entry['id'])
                set_import_state(project_id, entry['id'], 'pending')

        if not retry_ids:
            return JsonResponse({'success': False, 'error': 'No documents to retry'}, status=400)

        tier_config = TIER_LIMITS.get(project.tier.lower(), TIER_LIMITS['free'])
        max_docs = tier_config.get('documents')

        if max_docs is not None:
            current_count = Documents.objects.filter(project_id=project_id).count()
            available_slots = max_docs - current_count
            if len(retry_ids) > available_slots:
                if available_slots <= 0:
                    return JsonResponse({
                        'success': False,
                        'error': f'Document limit ({max_docs}) reached for your tier',
                    }, status=403)
                return JsonResponse({
                    'success': False,
                    'error': f'You can only import {available_slots} more document{"s" if available_slots != 1 else ""} on your tier',
                }, status=403)

        set_import_job(project_id, job_entries)

        import_google_docs_task.delay(
            request.user.id, project_id, team_id, retry_ids
        )

        return JsonResponse({'success': True, 'retrying': len(retry_ids)})

    except Exception:
        logger.exception("retry_import failed")
        return JsonResponse({'success': False, 'error': 'Something went wrong'}, status=500)
