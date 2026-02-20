from django.conf import settings
from django.http import HttpResponseForbidden


class WardentMiddleware:
    """
    Rejects any request that didn't come through Wardent.
    Wardent attaches X-Wardent-Secret to every forwarded request.
    If the header is missing or doesn't match, the request is killed.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        secret = request.headers.get("X-Wardent-Secret")
        if secret != settings.WARDENT_SECRET:
            return HttpResponseForbidden()
        return self.get_response(request)
