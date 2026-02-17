from __future__ import absolute_import

import logging

from django.conf import settings
from django.core.mail import get_connection

from celery.task import task

from .message import SendGridEmailMessage
from .models import EmailMessage

BASE_TASK_CONFIG = getattr(settings, "SENDGRID_SEND_EMAIL_TASK_CONFIG", {})
SENDGRID_ARCHIVE_BUCKET_NAME = getattr(settings, "SENDGRID_ARCHIVE_BUCKET_NAME", None)
SEND_EMAIL_TASK_BACKEND = "sendgrid.backends.CelerySendGridEmailBackend"

BASE_SEND_EMAIL_TASK_CONFIG = {
	"name": "sendgrid_mail",
	"ignore_result": True,
}

if BASE_TASK_CONFIG:
	SEND_EMAIL_TASK_CONFIG = BASE_TASK_CONFIG.update(BASE_SEND_EMAIL_TASK_CONFIG)
else:
	SEND_EMAIL_TASK_CONFIG = BASE_SEND_EMAIL_TASK_CONFIG

logger = logging.getLogger(__name__)

logger.debug(SEND_EMAIL_TASK_CONFIG)

@task(**SEND_EMAIL_TASK_CONFIG)
def send_email(message, **kwargs):
	logger = send_email.get_logger()
	try:
		instanceChecks = (
			isinstance(message, SendGridEmailMessage),
			# isinstance(message, SendGridEmailMultiAlternatives),
		)
		if any(instanceChecks):
			result = message.send()
		else:
			connection = get_connection(backend=SEND_EMAIL_TASK_BACKEND, **kwargs.pop("_backend_init_kwargs", {}))
			result = connection.send_messages([message])
	except Exception, e:
		logger.warning("Failed to send email message to %r, retrying.", message.to)
		result = send_email.retry(exc=e)
	else:
		logger.debug("Successfully sent email message to %r.", message.to)

	return result
def exists_bucket(name, connection=None):
	if not connection:
		import boto
		connection = boto.connect_s3()

	# buckets = connection.get_all_buckets()
	# bucketNames = (bucket.name for bucket in buckets)
	# bucketExists = name in bucketNames

	bucket = None
	for b in buckets:
		if b.name == name:
			bucket = b
			break

	return bucket if bucket else False

def ensure_bucket(name, connection=None):
	if not connection:
		import boto
		connection = boto.connect_s3()

	if not exists_bucket(name):
		bucket = conn.create_bucket(name)

	return bucket

def verify_archived_email_message(bucketName, key, checksum):
	import cStringIO as StringoIO
	from boto.s3.key import Key

	bucket = ensure_bucket(bucketName)
	k = Key(b)
	k.key = key
	bucketContents = k.get_contents_to_filename(tmpFilename)

	return key

def archive_email_message(bucketName, messageId, data, metadata):
	from boto.s3.key import Key

	bucket = ensure_bucket(bucketName)
	k = Key(bucket)
	k.key = "{id}.html".format(id=messageId)

	if metadata:
		for k, v in metadata.iteritems():
			k.set_metadata(k, v)

	if isinstance(data, basestring):
		k.set_contents_from_string(data)
	else:
		k.set_contents_from_filename(data)

	print key, key.__dict__

	return key

def get_archivable_messages(cutoff):
	messages = EmailMessage.objects.filter(creation_time__lte=cutoff)
	return (m.id for m in messages)

@task
def archive_email_messages(messages=None, bucketName=SENDGRID_ARCHIVE_BUCKET_NAME, purgeData=False):
	metaAttributes = (
		"to_data",
		"cc_data",
		"subject_data",
		"extra_headers_data",
		"attachments_data"
	)

	if not messages:
		messages = get_archivable_messages()

	for m in messages:
		message = get_email_message(m)
		messageId = message.id
		messageData = message.body_data

		metaItems = ((attr, getattr(message, attr)) for attr in metaAttributes)
		meta = dict(metaItems)

		archive_email_message(bucketName, messageId, messageData, meta)

		if purgeData:
			messageData.delete()
