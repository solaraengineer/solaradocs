import os
import stripe
from django.http import JsonResponse
from django.utils import timezone

class WardentSecretMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.secret = os.environ.get("WARDENT_SECRET")
        self.stripe_webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")
        self.excluded_prefixes = [
            "/metrics",
        ]

    def __call__(self, request):
        if any(request.path.startswith(p) for p in self.excluded_prefixes):
            return self.get_response(request)

        if request.path == "/webhook/stripe/":
            sig = request.headers.get("Stripe-Signature")
            if sig:
                try:
                    stripe.Webhook.construct_event(
                        request.body,
                        sig,
                        self.stripe_webhook_secret,
                    )
                    return self.get_response(request)
                except (stripe.error.SignatureVerificationError, ValueError):
                    return JsonResponse({"error": "Invalid Stripe signature"}, status=403)
            return JsonResponse({"error": "Forbidden"}, status=403)

        if request.headers.get("X-Wardent-Secret") != self.secret:
            return JsonResponse({"error": "Forbidden"}, status=403)

        request.META['HTTP_HOST'] = 'solaradocs.net'
        request.META['HTTP_X_FORWARDED_PROTO'] = 'https'
        request.META['wsgi.url_scheme'] = 'https'
        return self.get_response(request)


class ApiTokenAuthMiddleware:
    _LAST_USED_THROTTLE_SECONDS = 60

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        auth = request.headers.get('Authorization', '')
        if auth.startswith('Bearer sdtk_'):
            raw = auth[7:].strip()
            from solaradocs.models import UserApiToken
            token_hash = UserApiToken.hash_token(raw)
            tok = (UserApiToken.objects
                   .select_related('user', 'project')
                   .filter(token_hash=token_hash)
                   .first())
            if tok is not None and tok.is_valid():
                request.user = tok.user
                request.api_token = tok
                request._dont_enforce_csrf_checks = True
                last = tok.last_used_at
                if last is None or (timezone.now() - last).total_seconds() > self._LAST_USED_THROTTLE_SECONDS:
                    UserApiToken.objects.filter(pk=tok.pk).update(last_used_at=timezone.now())
        return self.get_response(request)
