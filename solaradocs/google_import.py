import json
import logging

from celery import shared_task
from django.conf import settings
from django.core.cache import cache
from django.db import transaction
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)

IMPORT_KEY_TTL = 86400


def _doc_key(project_id, google_doc_id):
    return f"import:{project_id}:{google_doc_id}"


def _job_key(project_id):
    return f"import_job:{project_id}"


def set_import_state(project_id, google_doc_id, state, reason=''):
    val = json.dumps({'state': state, 'reason': reason}) if reason else state
    cache.set(_doc_key(project_id, google_doc_id), val, timeout=IMPORT_KEY_TTL)


def get_import_state(project_id, google_doc_id):
    raw = cache.get(_doc_key(project_id, google_doc_id))
    if raw is None:
        return None, ''
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed['state'], parsed.get('reason', '')
        except (json.JSONDecodeError, KeyError, TypeError):
            return raw, ''
    return str(raw), ''


def set_import_job(project_id, doc_entries):
    cache.set(_job_key(project_id), json.dumps(doc_entries), timeout=IMPORT_KEY_TTL)


def get_import_job(project_id):
    raw = cache.get(_job_key(project_id))
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def get_import_job_status(project_id):
    entries = get_import_job(project_id)
    if entries is None:
        return None

    docs = []
    all_done = True
    has_failures = False

    for entry in entries:
        doc_id = entry['id']
        state, reason = get_import_state(project_id, doc_id)
        if state is None:
            state = 'expired'
        if state != 'done':
            all_done = False
        if state == 'failed':
            has_failures = True
        docs.append({
            'doc_id': doc_id,
            'title': entry.get('title', ''),
            'state': state,
            'reason': reason,
        })

    return {
        'docs': docs,
        'all_done': all_done,
        'has_failures': has_failures,
    }


def get_google_credentials(user):
    from allauth.socialaccount.models import SocialToken, SocialApp

    try:
        token_obj = SocialToken.objects.select_related('app', 'account').filter(
            account__user=user,
            account__provider='google',
        ).first()
    except Exception:
        logger.exception("Failed to fetch SocialToken for user %s", user.id)
        return None

    if token_obj is None:
        return None

    app = token_obj.app
    if app is None:
        try:
            app = SocialApp.objects.get(provider='google')
        except SocialApp.DoesNotExist:
            logger.error("No Google SocialApp configured")
            return None

    creds = Credentials(
        token=token_obj.token,
        refresh_token=token_obj.token_secret,
        token_uri='https://oauth2.googleapis.com/token',
        client_id=app.client_id,
        client_secret=app.secret,
    )

    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            token_obj.token = creds.token
            token_obj.save(update_fields=['token'])
        except Exception:
            logger.exception("Failed to refresh Google token for user %s", user.id)
            return None

    return creds


def list_user_google_docs(user, page_size=100):
    creds = get_google_credentials(user)
    if creds is None:
        return None

    try:
        service = build('drive', 'v3', credentials=creds, cache_discovery=False)
        results = service.files().list(
            q="mimeType='application/vnd.google-apps.document'",
            fields='files(id, name, modifiedTime)',
            pageSize=page_size,
            orderBy='modifiedTime desc',
        ).execute()
        return results.get('files', [])
    except HttpError as e:
        logger.error("Google Drive API error listing docs for user %s: %s", user.id, e)
        return None
    except Exception:
        logger.exception("Unexpected error listing Google Docs for user %s", user.id)
        return None


def fetch_google_doc_text(creds, doc_id):
    try:
        service = build('docs', 'v1', credentials=creds, cache_discovery=False)
        doc = service.documents().get(documentId=doc_id).execute()
    except HttpError as e:
        if e.resp.status == 429:
            logger.warning("Rate limited fetching Google Doc %s", doc_id)
            raise
        logger.error("Google Docs API error for doc %s: %s", doc_id, e)
        return None
    except Exception:
        logger.exception("Unexpected error fetching Google Doc %s", doc_id)
        return None

    title = doc.get('title', 'Untitled')
    body = doc.get('body', {})
    content_parts = []

    def walk_elements(elements):
        for element in elements:
            if 'paragraph' in element:
                for para_element in element['paragraph'].get('elements', []):
                    text_run = para_element.get('textRun')
                    if text_run and text_run.get('content'):
                        content_parts.append(text_run['content'])
            if 'table' in element:
                for row in element['table'].get('tableRows', []):
                    for cell in row.get('tableCells', []):
                        walk_elements(cell.get('content', []))
            if 'tableOfContents' in element:
                walk_elements(element['tableOfContents'].get('content', []))

    walk_elements(body.get('content', []))
    text = ''.join(content_parts)
    return title, text


def sanitize_imported_text(text):
    if not text:
        return ''
    text = text.replace('\x00', '')
    max_length = 5_000_000
    if len(text) > max_length:
        text = text[:max_length]
    return text


@shared_task(bind=True, max_retries=1, default_retry_delay=60)
def import_google_docs_task(self, user_id, project_id, team_id, google_doc_ids):
    from .models import Documents, Project, Teams, Audit, User, TIER_LIMITS

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        logger.error("Import task: user %s not found", user_id)
        return

    creds = get_google_credentials(user)
    if creds is None:
        logger.error("Import task: no valid Google credentials for user %s", user_id)
        for doc_id in google_doc_ids:
            set_import_state(project_id, doc_id, 'failed', reason='Google authentication failed')
        return

    try:
        team = Teams.objects.get(id=team_id, project_id=project_id)
    except Teams.DoesNotExist:
        logger.error("Import task: team %s not found in project %s", team_id, project_id)
        for doc_id in google_doc_ids:
            set_import_state(project_id, doc_id, 'failed', reason='Team not found')
        return

    for i, google_doc_id in enumerate(google_doc_ids):
        set_import_state(project_id, google_doc_id, 'in-progress')

        try:
            result = fetch_google_doc_text(creds, google_doc_id)
        except HttpError as e:
            if e.resp.status == 429:
                set_import_state(project_id, google_doc_id, 'failed', reason='Google API rate limit')
                continue
            set_import_state(project_id, google_doc_id, 'failed', reason='Google API error')
            continue
        except Exception:
            logger.exception("Import task: failed to fetch doc %s", google_doc_id)
            set_import_state(project_id, google_doc_id, 'failed', reason='Failed to fetch document')
            continue

        if result is None:
            set_import_state(project_id, google_doc_id, 'failed', reason='Failed to fetch document')
            continue

        title, text = result
        text = sanitize_imported_text(text)

        if not title or not title.strip():
            title = 'Untitled Import'
        title = title.strip()[:255]

        try:
            with transaction.atomic():
                project = Project.objects.select_for_update().get(id=project_id)
                tier_config = TIER_LIMITS.get(project.tier.lower(), TIER_LIMITS['free'])
                max_docs = tier_config.get('documents')

                if max_docs is not None:
                    current_count = Documents.objects.filter(project_id=project_id).count()
                    if current_count >= max_docs:
                        set_import_state(project_id, google_doc_id, 'failed',
                                         reason='Document limit reached')
                        for remaining_id in google_doc_ids[i + 1:]:
                            set_import_state(project_id, remaining_id, 'failed',
                                             reason='Document limit reached')
                        logger.info("Import task: document limit reached at doc %s for project %s",
                                    google_doc_id, project_id)
                        return

                Documents.objects.filter(
                    project_id=project_id,
                    google_doc_id=google_doc_id
                ).delete()

                document = Documents.objects.create(
                    project=project,
                    document_name=title,
                    content=text,
                    team_assigned=team,
                    google_doc_id=google_doc_id,
                )

                if tier_config.get('audit', False):
                    Audit.objects.create(
                        project=project,
                        document=document,
                        user=user,
                        action='import',
                    )

        except Project.DoesNotExist:
            logger.error("Import task: project %s deleted mid-import", project_id)
            for remaining_id in google_doc_ids[i:]:
                set_import_state(project_id, remaining_id, 'failed', reason='Project not found')
            return
        except Exception:
            logger.exception("Import task: DB error creating doc %s in project %s",
                             google_doc_id, project_id)
            set_import_state(project_id, google_doc_id, 'failed', reason='Database error')
            continue

        set_import_state(project_id, google_doc_id, 'done')
        logger.info("Import task: imported doc %s ('%s') into project %s",
                     google_doc_id, title, project_id)
