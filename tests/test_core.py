import json
from pathlib import Path
from unittest.mock import patch
import requests
from scanner import parse_scan
from risk_engine import score
from intelligence import fetch
from advisor import advise


def test_maximum():
    assert score(10,1,True,5,True)==(100,'P1')


def test_missing():
    assert score(None,None,True,5,True)==(None,'P1')
    assert score(None,None,None,5,True)==(None,'Review')


def test_demo():
    rows=parse_scan(json.loads(Path('data/demo.json').read_text()))
    assert len(rows)==2 and rows[0]['cvss']==10


def test_dedup():
    p=json.loads(Path('data/demo.json').read_text()); p['Results']*=2
    assert len(parse_scan(p))==2


def test_invalid():
    import pytest
    with pytest.raises(ValueError):
        parse_scan({})


def test_network_failure():
    with patch('intelligence.requests.get',side_effect=requests.Timeout):
        kev,epss,errors,_=fetch(['CVE-2021-44228'])
    assert kev is None and epss=={} and len(errors)==2


def test_ai_failure():
    with patch('advisor.requests.post',side_effect=requests.Timeout):
        answer,label=advise(dict(cve='CVE-2021-44228',asset='demo',priority='P1'))
    assert 'P1' in answer and label=='Deterministic fallback'
