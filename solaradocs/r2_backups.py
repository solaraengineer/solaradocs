import hashlib
import json
import logging

from celery import shared_task
from django.conf import settings

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def backup_document_to_r2(self, document_id):
    from .models import Documents, Backup

    try:
        doc = Documents.objects.select_related('project').get(id=document_id)
    except Documents.DoesNotExist:
        logger.error(f"Document {document_id} not found, skipping backup")
        return

    if not doc.project.backups_enabled:
        return

    content = doc.content or ''
    checksum = hashlib.sha256(content.encode('utf-8')).hexdigest()

    last_backup = Backup.objects.filter(document=doc).first()
    if last_backup and last_backup.checksum == checksum:
        logger.info(f"Document {document_id} unchanged, skipping backup")
        return

    version = (last_backup.version + 1) if last_backup else 1

    r2_key = f"projects/{doc.project_id}/documents/{doc.id}/v{version}.json"

    payload = json.dumps({
        'document_id': doc.id,
        'document_name': doc.document_name,
        'project_id': doc.project_id,
        'project_name': doc.project.project_name,
        'content': content,
        'version': version,
        'checksum': checksum,
    }, ensure_ascii=False)

    payload_bytes = payload.encode('utf-8')

    try:
        settings.R2_CLIENT.put_object(
            Bucket=settings.R2_BUCKET_NAME,
            Key=r2_key,
            Body=payload_bytes,
            ContentType='application/json',
        )
    except Exception as exc:
        logger.error(f"R2 upload failed for document {document_id}: {exc}")
        raise self.retry(exc=exc)

    Backup.objects.create(
        project=doc.project,
        document=doc,
        r2_key=r2_key,
        version=version,
        size_bytes=len(payload_bytes),
        checksum=checksum,
    )

    logger.info(f"Backup v{version} created for document {document_id} ({len(payload_bytes)} bytes)")


def restore_document_from_backup(backup_id):
    from .models import Backup

    backup = Backup.objects.select_related('document').get(id=backup_id)

    response = settings.R2_CLIENT.get_object(
        Bucket=settings.R2_BUCKET_NAME,
        Key=backup.r2_key,
    )

    payload = json.loads(response['Body'].read().decode('utf-8'))
    content = payload['content']

    doc = backup.document
    doc.content = content
    doc.save(update_fields=['content'])

    logger.info(f"Document {doc.id} restored to backup v{backup.version}")
    return content


def get_document_backups(document_id, limit=20):
    from .models import Backup
    return Backup.objects.filter(document_id=document_id).values(
        'id', 'version', 'size_bytes', 'checksum', 'created_at'
    )[:limit]


@shared_task
def cleanup_old_backups(keep_per_document=10):
    from .models import Backup, Documents

    for doc in Documents.objects.all():
        backups = Backup.objects.filter(document=doc).order_by('-created_at')
        old_backups = backups[keep_per_document:]

        for backup in old_backups:
            try:
                settings.R2_CLIENT.delete_object(
                    Bucket=settings.R2_BUCKET_NAME,
                    Key=backup.r2_key,
                )
            except Exception as exc:
                logger.error(f"Failed to delete R2 object {backup.r2_key}: {exc}")

            backup.delete()

    logger.info("Backup cleanup complete")