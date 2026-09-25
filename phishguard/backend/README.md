# PhishGuard Backend (FastAPI + SQLModel + Scikit-Learn)

High-performance, layered anti-phishing threat intelligence API combining:
1. **Rule-Based Heuristic Scorer** (`services/url_rules.py`): In-memory blocklists, brand typosquatting, raw IP detection, subdomain count, high-threat TLDs, and domain age analysis.
2. **Reputation Blocklists** (`services/url_reputation.py`): Google Safe Browsing v4 Threat API and PhishTank verified phishing database.
3. **Machine Learning URL Classifier** (`services/url_ml.py`): URL feature extraction (entropy, character ratios, slashes, tokens) driving a Random Forest model.
4. **Score Fusion**:
   ```
   final_score = 0.40 * ml_probability + 0.30 * (rule_score / 100) + 0.30 * (1.0 if blocklist_hit else 0.0)
   risk_score = round(final_score * 100)
   ```

---

## 1. Installation

### Prerequisites
- Python 3.10+
- PostgreSQL (or SQLite for local prototyping)

### Install dependencies
```bash
cd phishguard/backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

---

## 2. Configuration & Environment Variables

Create a `.env` file in `phishguard/backend/`:
```env
DATABASE_URL=postgresql://phishguard_user:password@localhost:5432/phishguard_db
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_key_here
PHISHTANK_API_KEY=your_phishtank_key_here
ML_MODEL_PATH=models/rf_phishing_model.joblib
RATE_LIMIT_PER_MINUTE=60
```

---

## 3. Training & Placing the ML Model

### Dataset Reference
The URL classifier is trained on features extracted from public datasets:
- **Kaggle Malicious and Phishing URLs Dataset**: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
- **UCI Machine Learning Phishing Websites Dataset**: https://archive.ics.uci.edu/dataset/327/phishing+websites

### Train the Model
Run the built-in training pipeline:
```bash
python -m app.services.train_url_model
```
This trains a Random Forest Classifier evaluating 11 lexical URL features (Shannon entropy, dot count, subdomain depth, IP usage, digit ratios, security keywords) and exports the artifact to:
```
phishguard/backend/models/rf_phishing_model.joblib
```

> **Note:** If the model file is not present, `services/url_ml.py` gracefully falls back to calibrated feature weighting so the API remains fully operational.

---

## 4. Running the Server

Start the FastAPI application with Uvicorn:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
Interactive Swagger Documentation will be available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

---

## 5. API Endpoints

### `POST /api/analyze_url`
**Request:**
```json
{
  "url": "https://paypal-security-update.com/login"
}
```
**Response:**
```json
{
  "risk_score": 94,
  "verdict": "likely_phishing",
  "reasons": [
    "Domain is on known phishing blocklist",
    "ML model predicts phishing (probability 0.94)",
    "Domain impersonates recognized brand 'paypal'",
    "Domain is less than 30 days old"
  ],
  "details": {
    "rule_score": 95,
    "ml_probability": 0.94,
    "blocklist_hit": true,
    "domain": "paypal-security-update.com",
    "domain_age_days": 8
  }
}
```

### `POST /api/analyze_email`
**Request:**
```json
{
  "subject": "Urgent: Verify your account",
  "body": "Dear customer, your account will be suspended within 24 hours..."
}
```
**Response:**
```json
{
  "phishing_likelihood": "high",
  "score": 85,
  "patterns_found": [
    "Uses urgent or threatening language",
    "Requests credentials or sensitive info",
    "Generic greeting"
  ]
}
```

### `POST /api/report`
**Request:**
```json
{
  "type": "url",
  "content": "https://fake-login-bank.xyz",
  "notes": "Phishing portal requesting credit card CVV"
}
```
**Response:**
```json
{
  "success": true
}
```
