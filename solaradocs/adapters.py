from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.account.utils import user_email, user_username
from allauth.core.exceptions import ImmediateHttpResponse
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.http import JsonResponse
from django.shortcuts import redirect
import requests
from solaradocs.views import generate_auth_token, require_auth_token, verify_auth_token

User = get_user_model()


class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):

    def _check_rate_limit(self, request):
        ip_address = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', ''))
        if ',' in ip_address:
            ip_address = ip_address.split(',')[0].strip()

        cache_key = f"oauth_ratelimit_{ip_address}"
        request_count = cache.get(cache_key, 0)

        if request_count >= 10:
            return True

        cache.set(cache_key, request_count + 1, timeout=60)
        return False

    def pre_social_login(self, request, sociallogin):
        if self._check_rate_limit(request):
            raise ImmediateHttpResponse(
                JsonResponse({'success': False, 'error': 'Too many requests'}, status=429)
            )

        if sociallogin.is_existing:
            return

        email = user_email(sociallogin.user)
        if not email:
            return

        try:
            existing_user = User.objects.get(email__iexact=email)
            sociallogin.connect(request, existing_user)
        except User.DoesNotExist:
            pass

    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)
        extra_data = sociallogin.account.extra_data

        if extra_data:
            if not user.first_name and extra_data.get('given_name'):
                user.first_name = extra_data.get('given_name', '')

            if not user.last_name and extra_data.get('family_name'):
                user.last_name = extra_data.get('family_name', '')

            if not user.email and extra_data.get('email'):
                user.email = extra_data.get('email', '')

            if not user_username(user):
                email = extra_data.get('email', '')
                if email:
                    base_username = email.split('@')[0]
                    username = base_username
                    counter = 1
                    while User.objects.filter(username=username).exists():
                        username = f"{base_username}{counter}"
                        counter += 1
                    user.username = username

        return user

    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form)
        return user


    def on_authentication_error(self, request, provider_id, error=None, exception=None, extra_context=None):
        if isinstance(exception, requests.exceptions.Timeout):
            raise ImmediateHttpResponse(redirect('/login/?oauth_error=timeout'))
        elif isinstance(exception, requests.exceptions.ConnectionError):
            raise ImmediateHttpResponse(redirect('/login/?oauth_error=connection'))
        elif isinstance(exception, requests.exceptions.RequestException):
            raise ImmediateHttpResponse(redirect('/login/?oauth_error=request'))

    def authentication_error(self, request, provider_id, error=None, exception=None, extra_context=None):
        self.on_authentication_error(request, provider_id, error, exception, extra_context)
        super().authentication_error(request, provider_id, error, exception, extra_context)

    def get_connect_redirect_url(self, request, socialaccount):
        return '/dashboard/'
