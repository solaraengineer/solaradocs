from celery import shared_task
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings


@shared_task
def send_welcome_email(username, email):
    html = render_to_string('emails/welcome.html', {
        'username': username,
    })
    send_mail(
        subject='Welcome to Solara Docs',
        message='',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        html_message=html,
        fail_silently=True,
    )


@shared_task
def send_subscription_email(email, username, tier, price, renews_at):
    html = render_to_string('emails/subscription.html', {
        'username': username,
        'tier': tier,
        'price': price,
        'renews_at': renews_at,
    })
    send_mail(
        subject=f'Subscription Confirmed  {tier.title()} Plan',
        message='',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        html_message=html,
        fail_silently=True,
    )


@shared_task
def send_cancellation_email(email, username, tier):
    html = render_to_string('emails/cancellation.html', {
        'username': username,
        'tier': tier,
    })
    send_mail(
        subject='Subscription Cancelled  Solara Docs',
        message='',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        html_message=html,
        fail_silently=True,
    )
@shared_task
def send_password_reset_email(email, username, code):
    html = render_to_string('reset_code.html', {
        'username': username,
        'code': code,
    })
    send_mail(
        subject='Password Reset Code - Solara Docs',
        message=f'Your password reset code is: {code}',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        html_message=html,
        fail_silently=True,
    )