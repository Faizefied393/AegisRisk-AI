import json
from pathlib import Path
import pandas as pd
import streamlit as st
from scanner import parse_scan
from intelligence import fetch
from risk_engine import score
from advisor import advise, fallback

st.set_page_config(page_title='AegisRisk AI', layout='wide')
st.title('AegisRisk AI | Exposure intelligence')
st.caption('Local portfolio prototype • analyst-reviewed decisions • no automated remediation')
mode = st.radio('Input', ['Offline synthetic demo', 'Trivy JSON upload'])
upload = st.file_uploader('Trivy JSON', type='json') if mode != 'Offline synthetic demo' else None
if mode != 'Offline synthetic demo' and upload is None:
    st.stop()
try:
    payload = json.loads((Path(__file__).parent/'data/demo.json').read_text()) if upload is None else json.loads(upload.getvalue())
    rows = parse_scan(payload)
except (ValueError, TypeError, KeyError, AttributeError) as e:
    st.error(f'Invalid scan: {e}'); st.stop()
if not rows:
    st.info('No CVE findings in this scan. Non-CVE identifiers are outside this prototype scope.'); st.stop()
if len(rows) > 500:
    st.error('Prototype limit: 500 findings per scan.'); st.stop()
st.sidebar.header('Asset context (applies to entire scan)')
criticality = st.sidebar.slider('Business criticality', 1, 5, 5)
exposure = st.sidebar.selectbox('Internet exposure', ['Unknown','Internet-facing','Internal'], index=1 if upload is None else 0)
exposed = {'Unknown':None,'Internet-facing':True,'Internal':False}[exposure]
confirmed = st.sidebar.checkbox('Confirm business criticality', value=upload is None)

@st.cache_data(ttl=3600, show_spinner='Retrieving public intelligence…')
def cached_fetch(cves):
    return fetch(cves)

if upload is None:
    kev, epss = {'CVE-2021-44228'}, {'CVE-2021-44228':0.95,'CVE-2023-38545':0.02}
    st.warning('Synthetic scan and illustrative intelligence values. Not current threat intelligence.')
else:
    kev, epss = None, {}
    if st.checkbox('Fetch public KEV and EPSS (sends CVE IDs only to FIRST)'):
        kev, epss, errors, stamp = cached_fetch(tuple(sorted({r['cve'] for r in rows})))
        st.caption(f'Public feed retrieval (UTC; cached up to one hour): {stamp}')
        for error in errors:
            st.warning(error)
for r in rows:
    r['kev'] = None if kev is None else r['cve'] in kev
    r['epss'] = epss.get(r['cve'])
    r['criticality'] = criticality if confirmed else None
    r['exposed'] = exposed
    r['score'], r['priority'] = score(r['cvss'], r['epss'], r['kev'], r['criticality'], exposed)
    r['source'] = 'synthetic' if upload is None else 'uploaded scan; public enrichment if enabled'
rows.sort(key=lambda r: (['P1','P2','Review','P3','P4'].index(r['priority']), -(r['score'] or 0)))
df = pd.DataFrame(rows)
cols = st.columns(4)
for col, label, value in zip(cols,['Findings','P1 immediate','Known exploited','Incomplete assessments'],[len(rows),sum(r['priority']=='P1' for r in rows),sum(r['kev'] is True for r in rows),sum(r['score'] is None for r in rows)]):
    col.metric(label,value)
st.bar_chart(df['priority'].value_counts())
st.subheader('Remediation queue')
selected = st.multiselect('Filter priority', ['P1','P2','Review','P3','P4'], default=['P1','P2','Review','P3','P4'])
query = st.text_input('Search CVE or package').lower()
filtered = [r for r in rows if r['priority'] in selected and query in (r['cve']+' '+r['package']).lower()]
st.dataframe(pd.DataFrame(filtered), hide_index=True)
# Prevent spreadsheet formula interpretation of untrusted string fields.
def safe_cell(v):
    return "'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')) else v
st.download_button('Export filtered remediation CSV', pd.DataFrame([{k:safe_cell(v) for k,v in r.items()} for r in filtered]).to_csv(index=False), 'remediation.csv','text/csv')
if filtered:
    index = st.selectbox('Inspect finding', range(len(filtered)), format_func=lambda i:f"{filtered[i]['cve']} | {filtered[i]['package']} | {filtered[i]['target']}")
    row = filtered[index]
    st.json(row)
    st.info(fallback(row))
    if st.button('Generate local AI draft'):
        answer, label = advise(row)
        st.caption(label); st.write(answer)
