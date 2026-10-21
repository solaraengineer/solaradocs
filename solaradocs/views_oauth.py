"""OAuth 2.1 endpoints for MCP clients (Claude.ai web connector, etc.).

Flow:
    1. Client hits MCP URL with no / invalid Bearer → MCP server returns 401
       with WWW-Authenticate: Bearer resource_metadata="...".
    2. Client fetches /.well-known/oauth-protected-resource (RFC 9728) →
       learns the authorization server.
    3. Client fetches /.well-known/oauth-authorization-server (RFC 8414) →
       learns the registration / authorize / token endpoints.
    4. Client POSTs to /oauth/register (RFC 7591 DCR) → gets client_id.
    5. Client opens browser to /oauth/authorize → user logs in + consents.
    6. Client POSTs code + PKCE verifier to /oauth/token → gets an
       sdtk_... access token (same shape as the Create API Token UI issues).

This module currently covers steps 2-3 (metadata). Steps 4-6 land in a
follow-up change.
"""

import base64
import hashlib
import json
import secrets
from datetime import timedelta
from urllib.parse import urlencode, urlparse

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.cache import cache_control
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.http import require_GET, require_POST, require_http_methods


OAUTH_CODE_TTL_SECONDS = 10 * 60
MAX_REDIRECT_URIS_PER_CLIENT = 8
_ACCESS_LEVEL_SET = {'READ', 'WRITE', 'DELETE'}
_EXPIRES_CHOICES = {'7', '30', '90', 'never'}


def _origin() -> str:
    """Public origin of this solaradocs instance.

    Pulled from settings so dev / staging / prod all serve the right
    URLs in their metadata documents without touching code.
    """
    return getattr(settings, 'OAUTH_ISSUER', 'https://solaradocs.net').rstrip('/')


def _oauth_error(error: str, description: str, status: int = 400) -> JsonResponse:
    return JsonResponse(
        {'error': error, 'error_description': description},
        status=status,
    )


def _is_valid_redirect(uri: str) -> bool:
    """Only HTTPS or http://localhost (dev-friendly). No fragments."""
    try:
        p = urlparse(uri)
    except Exception:
        return False
    if '#' in uri:
        return False
    if p.scheme == 'https':
        return bool(p.netloc)
    if p.scheme == 'http':
        host = (p.hostname or '').lower()
        return host in {'localhost', '127.0.0.1', '::1'}
    return False


def _pkce_matches(verifier: str, challenge: str) -> bool:
    """RFC 7636: S256 = base64url(sha256(verifier)) with no padding."""
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return secrets.compare_digest(expected, challenge)


@require_GET
@cache_control(max_age=300, public=True)
def oauth_protected_resource_metadata(request):
    """RFC 9728 §3 — Protected Resource Metadata.

    Tells OAuth clients which authorization server(s) issue tokens for
    this resource. The resource identifier is the MCP endpoint URL;
    the authorization server is this same origin.
    """
    origin = _origin()
    return JsonResponse({
        'resource': f'{origin}/mcp',
        'authorization_servers': [origin],
        'bearer_methods_supported': ['header'],
        'scopes_supported': ['mcp'],
    })


@require_GET
@cache_control(max_age=300, public=True)
def oauth_authorization_server_metadata(request):
    """RFC 8414 — Authorization Server Metadata.

    Advertises the endpoints a client needs to complete the OAuth
    authorization-code flow with PKCE. token_endpoint_auth_methods_supported
    is ['none'] because MCP clients are public clients (no client secret);
    PKCE is the security floor.
    """
    origin = _origin()
    return JsonResponse({
        'issuer': origin,
        'authorization_endpoint': f'{origin}/oauth/authorize',
        'token_endpoint': f'{origin}/oauth/token',
        'registration_endpoint': f'{origin}/oauth/register',
        'scopes_supported': ['mcp'],
        'response_types_supported': ['code'],
        'response_modes_supported': ['query'],
        'grant_types_supported': ['authorization_code'],
        'code_challenge_methods_supported': ['S256'],
        'token_endpoint_auth_methods_supported': ['none'],
    })


# ────────────────────────────────────────────────────────────────────────────
# Dynamic Client Registration (RFC 7591)
# ────────────────────────────────────────────────────────────────────────────

@csrf_exempt
@require_POST
def oauth_register(request):
    """RFC 7591 — register a new public client (no secret).

    Expected body: ``{"client_name": "...", "redirect_uris": [...]}``.
    Returns ``{"client_id": "...", ...}``. No auth required by spec —
    PKCE on the authorize/token exchange is the security floor.
    """
    from .models import OAuthClient
    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except (ValueError, UnicodeDecodeError):
        return _oauth_error('invalid_client_metadata', 'Body must be JSON')

    if not isinstance(payload, dict):
        return _oauth_error('invalid_client_metadata', 'Body must be a JSON object')

    redirect_uris = payload.get('redirect_uris') or []
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return _oauth_error('invalid_redirect_uri', 'redirect_uris required (non-empty list)')
    if len(redirect_uris) > MAX_REDIRECT_URIS_PER_CLIENT:
        return _oauth_error('invalid_redirect_uri', f'Too many redirect_uris (max {MAX_REDIRECT_URIS_PER_CLIENT})')
    for uri in redirect_uris:
        if not isinstance(uri, str) or not _is_valid_redirect(uri):
            return _oauth_error('invalid_redirect_uri', f'Rejected redirect_uri: {uri!r}')

    client_name = (payload.get('client_name') or '').strip()[:200]

    client_id = secrets.token_urlsafe(24)
    OAuthClient.objects.create(
        client_id=client_id,
        client_name=client_name,
        redirect_uris=redirect_uris,
    )
    return JsonResponse({
        'client_id': client_id,
        'client_name': client_name,
        'redirect_uris': redirect_uris,
        'token_endpoint_auth_method': 'none',
        'grant_types': ['authorization_code'],
        'response_types': ['code'],
        'scope': 'mcp',
    }, status=201)


# ────────────────────────────────────────────────────────────────────────────
# Authorization endpoint — consent screen + code issuance
# ────────────────────────────────────────────────────────────────────────────

def _redirect_with_error(redirect_uri: str, error: str, description: str, state: str) -> HttpResponseRedirect:
    params = {'error': error, 'error_description': description}
    if state:
        params['state'] = state
    sep = '&' if '?' in redirect_uri else '?'
    return HttpResponseRedirect(f'{redirect_uri}{sep}{urlencode(params)}')


@require_http_methods(['GET', 'POST'])
@login_required
@csrf_protect
def oauth_authorize(request):
    """OAuth authorization endpoint.

    GET: validate query params, show consent screen.
    POST: user clicked approve/deny; on approve, mint an auth code and
    301 back to the client's redirect_uri with ?code=...&state=....
    """
    from .models import OAuthClient

    # Params come from GET on first visit; POST re-submits them as hidden fields.
    src = request.POST if request.method == 'POST' else request.GET
    client_id = src.get('client_id', '')
    redirect_uri = src.get('redirect_uri', '')
    response_type = src.get('response_type', '')
    scope = src.get('scope', 'mcp')
    state = src.get('state', '')
    code_challenge = src.get('code_challenge', '')
    code_challenge_method = src.get('code_challenge_method', '')

    # Validate client + redirect_uri BEFORE any error-redirect (per spec:
    # if these are bad, show the error on our page, don't bounce to a
    # redirect that might be attacker-controlled).
    client = OAuthClient.objects.filter(client_id=client_id).first()
    if client is None:
        return render(request, 'oauth_error.html', {
            'error': 'invalid_client',
            'description': 'Unknown client_id. Re-run dynamic client registration.',
        }, status=400)
    if redirect_uri not in client.redirect_uris:
        return render(request, 'oauth_error.html', {
            'error': 'invalid_redirect_uri',
            'description': 'redirect_uri is not registered for this client.',
        }, status=400)

    # From here on, errors ride the redirect_uri so the client sees them.
    if response_type != 'code':
        return _redirect_with_error(redirect_uri, 'unsupported_response_type',
                                    'Only response_type=code is supported', state)
    if code_challenge_method != 'S256':
        return _redirect_with_error(redirect_uri, 'invalid_request',
                                    'code_challenge_method must be S256', state)
    if not code_challenge or len(code_challenge) < 43 or len(code_challenge) > 128:
        return _redirect_with_error(redirect_uri, 'invalid_request',
                                    'code_challenge required (43-128 chars)', state)

    # Tier gate: MCP / API-token issuance requires Personal plan or above.
    # Blocking at the consent screen so Claude.ai's OAuth flow fails with
    # a clear "upgrade required" page instead of silently issuing an sdtk_
    # that would then 402 on every subsequent request anyway.
    from .models import user_has_mcp
    if not user_has_mcp(request.user):
        return render(request, 'oauth_upgrade_required.html', {
            'client_name': client.client_name or 'An MCP client',
        }, status=402)

    if request.method == 'GET':
        return render(request, 'oauth_consent.html', {
            'client': client,
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': response_type,
            'scope': scope,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method,
        })

    # POST — user clicked approve or deny
    if src.get('deny'):
        return _redirect_with_error(redirect_uri, 'access_denied', 'User denied', state)

    access_level = src.get('access_level', 'READ')
    expires = src.get('expires', '30')
    if access_level not in _ACCESS_LEVEL_SET:
        return _redirect_with_error(redirect_uri, 'invalid_request', 'Invalid access_level', state)
    if expires not in _EXPIRES_CHOICES:
        return _redirect_with_error(redirect_uri, 'invalid_request', 'Invalid expires', state)

    code = secrets.token_urlsafe(32)
    cache.set(
        f'oauth_code:{code}',
        {
            'user_id': request.user.id,
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'code_challenge': code_challenge,
            'scope': scope,
            'access_level': access_level,
            'expires': expires,
            'client_name': client.client_name,
        },
        timeout=OAUTH_CODE_TTL_SECONDS,
    )

    params = {'code': code}
    if state:
        params['state'] = state
    sep = '&' if '?' in redirect_uri else '?'
    return HttpResponseRedirect(f'{redirect_uri}{sep}{urlencode(params)}')


# ────────────────────────────────────────────────────────────────────────────
# Token endpoint — exchange auth code for an sdtk_ access token
# ────────────────────────────────────────────────────────────────────────────

@csrf_exempt
@require_POST
def oauth_token(request):
    """RFC 6749 §4.1.3 — authorization_code grant with PKCE.

    Validates the code + PKCE, pops the code from cache (one-time use),
    then mints a UserApiToken whose raw ``sdtk_...`` value becomes the
    access_token. MCP server already honors ``Authorization: Bearer sdtk_``
    so no changes needed there.
    """
    from .models import UserApiToken, OAuthClient

    grant_type = request.POST.get('grant_type', '')
    if grant_type != 'authorization_code':
        return _oauth_error('unsupported_grant_type', 'Only authorization_code is supported')

    code = request.POST.get('code', '')
    redirect_uri = request.POST.get('redirect_uri', '')
    client_id = request.POST.get('client_id', '')
    code_verifier = request.POST.get('code_verifier', '')
    if not all([code, redirect_uri, client_id, code_verifier]):
        return _oauth_error('invalid_request', 'code, redirect_uri, client_id, code_verifier required')
    if len(code_verifier) < 43 or len(code_verifier) > 128:
        return _oauth_error('invalid_grant', 'code_verifier must be 43-128 chars')

    cache_key = f'oauth_code:{code}'
    entry = cache.get(cache_key)
    if entry is None:
        return _oauth_error('invalid_grant', 'Unknown or expired code', status=400)
    # One-shot — remove before validation can short-circuit.
    cache.delete(cache_key)

    if entry['client_id'] != client_id:
        return _oauth_error('invalid_grant', 'client_id does not match the code')
    if entry['redirect_uri'] != redirect_uri:
        return _oauth_error('invalid_grant', 'redirect_uri does not match the code')
    if not _pkce_matches(code_verifier, entry['code_challenge']):
        return _oauth_error('invalid_grant', 'PKCE verifier failed')

    from django.contrib.auth import get_user_model
    from .models import user_has_mcp
    User = get_user_model()
    user = User.objects.filter(id=entry['user_id']).first()
    if user is None:
        return _oauth_error('invalid_grant', 'User no longer exists')
    # Second line of defense: user may have downgraded in the 10-min
    # window between consent and token exchange. Refuse to mint a token
    # that'd just 402 on first use.
    if not user_has_mcp(user):
        return _oauth_error('invalid_grant', 'User tier no longer includes API / MCP access')

    client = OAuthClient.objects.filter(client_id=client_id).first()
    if client is not None:
        client.last_used_at = timezone.now()
        client.save(update_fields=['last_used_at'])

    expires_days = entry['expires']
    expires_at = None
    expires_in = None
    if expires_days != 'never':
        days = int(expires_days)
        expires_at = timezone.now() + timedelta(days=days)
        expires_in = days * 86400

    name_from_client = entry.get('client_name') or client_id[:16]
    raw = UserApiToken.generate_raw_token()
    UserApiToken.objects.create(
        user=user,
        project=None,
        name=f'OAuth: {name_from_client}'[:100],
        token_hash=UserApiToken.hash_token(raw),
        token_prefix=raw[:10],
        access_level=entry['access_level'],
        expires_at=expires_at,
    )

    body = {
        'access_token': raw,
        'token_type': 'Bearer',
        'scope': entry.get('scope', 'mcp'),
    }
    if expires_in is not None:
        body['expires_in'] = expires_in
    return JsonResponse(body)
