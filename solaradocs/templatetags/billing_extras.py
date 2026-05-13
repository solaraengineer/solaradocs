from django import template

register = template.Library()


@register.filter
def cents_to_dollars(amount):
    """Format an integer cents value as a dollar string (no currency sign).

    50    -> "0.50"
    1600  -> "16.00"
    -100  -> "-1.00"
    None  -> "0.00"
    """
    try:
        cents = int(amount)
    except (TypeError, ValueError):
        return '0.00'
    sign = '-' if cents < 0 else ''
    cents = abs(cents)
    return f'{sign}{cents // 100}.{cents % 100:02d}'
