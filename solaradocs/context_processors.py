def past_due_banner(request):
    """Expose `show_past_due_banner` to every template.

    Templates without a shared base can each render the banner via
    `{% include "partials/past_due_banner.html" %}` and the include is a no-op
    when the user isn't logged in / isn't past due.
    """
    user = getattr(request, 'user', None)
    show = bool(
        user
        and getattr(user, 'is_authenticated', False)
        and getattr(user, 'subscription_status', None) == 'past_due'
    )
    return {'show_past_due_banner': show}
