# Architecture and threat model
Trivy JSON → scanner.py → intelligence.py + manual asset context → risk_engine.py → app.py → CSV and optional advisor.py.
Trust boundaries: uploaded records, public intelligence and AI responses are untrusted. No shell commands or remediation tools are available to the model. Public requests have timeouts; missing inputs are explicit. CSV formula prefixes are escaped. Run on loopback only; production would need authentication, stronger upload limits, audit logs and independent assessment.
