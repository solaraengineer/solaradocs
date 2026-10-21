from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from django.utils import timezone
from solaradocs.views_emails import send_welcome_email

User = get_user_model()

@receiver(post_save, sender=User)
def welcome_email_signal(sender, instance, created, **kwargs):
    if created:
        send_welcome_email.delay(instance.username, instance.email)


@receiver(pre_save, sender=User)
def revoke_api_tokens_on_password_change(sender, instance, **kwargs):
    if not instance.pk:
        return
    try:
        old = sender.objects.only('password').get(pk=instance.pk)
    except sender.DoesNotExist:
        return
    if old.password == instance.password:
        return
    from solaradocs.models import UserApiToken
    UserApiToken.objects.filter(user_id=instance.pk, revoked_at__isnull=True).update(revoked_at=timezone.now())
