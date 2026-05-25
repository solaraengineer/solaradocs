import os
import stripe
from django.http import JsonResponse

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