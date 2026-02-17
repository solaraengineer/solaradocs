from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from solaradocs.views_emails import send_welcome_email

User = get_user_model()

@receiver(post_save, sender=User)
def welcome_email_signal(sender, instance, created, **kwargs):
    if created:
        send_welcome_email.delay(instance.username, instance.email)