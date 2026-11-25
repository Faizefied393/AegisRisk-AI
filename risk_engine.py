"""Transparent demonstration policy; not a calibrated risk probability."""
import math


def score(cvss, epss, kev, criticality, exposed):
    values = [(cvss, 0, 10), (epss, 0, 1), (criticality, 1, 5)]
    complete = all(isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and lo <= v <= hi for v, lo, hi in values) and type(kev) is bool and type(exposed) is bool
    total = round(15*cvss/10 + 25*epss + 35*kev + 3*criticality + 10*exposed, 2) if complete else None
    if kev is True and exposed is True:
        priority = 'P1'
    elif total is not None and total >= 80:
        priority = 'P1'
    elif kev is True or (total is not None and total >= 60):
        priority = 'P2'
    elif total is None:
        priority = 'Review'
    else:
        priority = 'P3' if total >= 35 else 'P4'
    return total, priority
