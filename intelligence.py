"""Public intelligence lookups with explicit unavailable states."""
from datetime import datetime, timezone
import requests

KEV_URL = 'https://raw.githubusercontent.com/CISAGov/kev-data/develop/known_exploited_vulnerabilities.json'
EPSS_URL = 'https://api.first.org/data/v1/epss'


def fetch(cves):
    cves = sorted(set(cves))
    kev, epss, errors = None, {}, []
    try:
        r = requests.get(KEV_URL, timeout=15)
        r.raise_for_status()
        records = r.json()['vulnerabilities']
        if not isinstance(records, list) or not records:
            raise ValueError('Empty KEV catalog')
        kev = {v['cveID'] for v in records}
    except (requests.RequestException, ValueError, KeyError, TypeError) as e:
        errors.append(f'KEV unavailable: {type(e).__name__}')
    for i in range(0, len(cves), 50):
        batch = cves[i:i+50]
        try:
            r = requests.get(EPSS_URL, params={'cve': ','.join(batch)}, timeout=15)
            r.raise_for_status()
            for record in r.json()['data']:
                p = float(record['epss'])
                if record['cve'] in batch and 0 <= p <= 1:
                    epss[record['cve']] = p
        except (requests.RequestException, ValueError, KeyError, TypeError) as e:
            errors.append(f'EPSS batch unavailable: {type(e).__name__}')
    return kev, epss, errors, datetime.now(timezone.utc).isoformat()
