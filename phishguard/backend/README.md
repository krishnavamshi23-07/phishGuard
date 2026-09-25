# PhishGuard Backend Service

A high-performance security API providing automated threat analysis for suspicious URLs and deceptive emails.

---

## Capabilities

- **URL Intelligence**: Multi-stage inspection combining heuristic rules, known threat feeds, and predictive machine learning models.
- **Email Content Inspection**: Linguistic analysis for social engineering tactics, urgency escalation, and credential solicitation.
- **Incident Reporting**: Secure submission pipeline for user-reported phishing campaigns and emerging indicators of compromise.

---

## Multi-Layer Detection Architecture

The backend implements a comprehensive defensive strategy:

- **Structural Heuristics**: Examines domain naming conventions, typo-squatting indicators, character distribution, and path patterns.
- **Threat Intelligence**: Validates target destinations against active threat databases and community-verified phishing lists.
- **Predictive Classification**: Uses trained classification models to identify structural patterns characteristic of fraudulent sites.
- **Composite Risk Rating**: Produces a unified severity assessment accompanied by plain-language explanations for security teams.

---

## Quick Start

### 1. Prerequisites
- Python 3.10+
- Virtual environment tool (`venv`)

### 2. Setup & Installation
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Run the Service
```bash
uvicorn app.main:app --reload --port 8000
```

Interactive documentation is available at `/docs` once the server is started.
