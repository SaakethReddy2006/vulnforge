# VulnForge – Web Application VAPT & Evidence Platform

VulnForge is an automated, evidence-based security assessment platform built in Python. It provides centralized target authorization, custom HTTP security inspection, SHA-256 fingerprint deduplication, analyst triaging workflows, remediation retests, and PDF executive reporting.

## Key Features & Architecture
- **Scope Enforcement & SSRF Safeguards:** Enforces strict target domain allowlists prior to dispatching pre-flight requests.
- **Fingerprint-Based Deduplication:** Computes unique SHA-256 hashes (`target_id + endpoint + vuln_name + evidence`) to suppress duplicate findings across scan runs.
- **Analyst Triage Pipeline:** Supports human-in-the-loop triaging (`Unverified`, `Confirmed Vulnerability`, `False Positive`, `Needs Manual Testing`) with custom rationale tracking.
- **Remediation Retest Lifecycle:** Automatically re-evaluates specific target endpoints and logs immutable audit trails (`Fixed` vs. `Still Present`).
- **Programmatic PDF Reporting:** Generates CISO-ready PDF reports containing scope metadata, severity color-coding, raw evidence, and remediation guides.

## Tech Stack
- **Language:** Python 3.10+
- **Frontend Dashboard:** Streamlit
- **HTTP Engine:** HTTPX
- **Storage:** SQLite3 (Relational Schema)
- **Reporting Engine:** ReportLab

## Quickstart Setup
```bash
# 1. Clone repository & install dependencies
pip install -r requirements.txt

# 2. Launch dashboard
streamlit run app.py