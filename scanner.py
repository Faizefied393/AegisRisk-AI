"""Parse exported Trivy JSON without executing anything from it."""
import re


def parse_scan(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get('Results'), list):
        raise ValueError('Expected Trivy JSON with a Results array.')
    rows = {}
    for result in payload['Results']:
        if not isinstance(result, dict):
            raise ValueError('Invalid scan result')
        for v in result.get('Vulnerabilities') or []:
            if not isinstance(v, dict):
                raise ValueError('Invalid vulnerability record')
            cve = str(v.get('VulnerabilityID', ''))
            if not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve):
                continue
            scores = v.get('CVSS') or {}
            cvss = None
            for source in ['nvd', *sorted(scores)]:
                entry = scores.get(source) or {}
                s = entry.get('V3Score')
                if s is not None:
                    cvss = s
                    break
            row = dict(asset=str(payload.get('ArtifactName') or 'unknown'), target=str(result.get('Target', 'unknown')), cve=cve, package=str(v.get('PkgName', 'unknown')), installed=str(v.get('InstalledVersion', 'unknown')), fixed=str(v.get('FixedVersion') or ''), cvss=cvss)
            rows[(row['asset'], row['target'], cve, row['package'], row['installed'])] = row
    return list(rows.values())
