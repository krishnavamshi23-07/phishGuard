# PhishGuard — Layered Anti-Phishing Platform

PhishGuard is a production-ready, all-in-one anti-phishing defense platform designed to protect users from modern credential theft, lookalike domains, and social engineering attacks.

It uses a **layered detection approach**:
1. **Rule-Based Heuristic Scorer** (`services/url_rules`): Checks in-memory blocklists, raw IP usage, excessive subdomains, brand typosquatting via Levenshtein distance, suspicious security tokens (`login`, `secure`, `verify`), high-risk TLDs, and domain registration age.
2. **Reputation & Blocklist Checks** (`services/url_reputation`): Integrates Google Safe Browsing v4 Threat API (`SOCIAL_ENGINEERING`, `MALWARE`) and the PhishTank community database.
3. **Machine Learning Classifier** (`services/url_ml`): Lexical feature extraction (Shannon entropy, dot count, character length, digit-to-letter ratios, path depth) evaluated against a Random Forest model trained on public phishing benchmarks.
4. **Score Fusion**:
   ```text
   final_score = 0.40 * ml_probability + 0.30 * (rule_score / 100) + 0.30 * (1.0 if blocklist_hit else 0.0)
   risk_score = round(final_score * 100)
   ```
   - `risk_score >= 70` &rarr; **`likely_phishing`**
   - `40 <= risk_score < 70` &rarr; **`suspicious`**
   - `risk_score < 40` &rarr; **`safe`**

---

## Project Structure

```text
/
├── phishguard/
│   ├── backend/
│   │   ├── app/
│   │   │   ├── main.py                  # FastAPI entry point, CORS, Rate Limiting
│   │   │   ├── config.py                # Pydantic BaseSettings & environment variables
│   │   │   ├── models.py                # SQLModel / SQLAlchemy database models
│   │   │   ├── schemas.py               # Pydantic input / output contracts
│   │   │   ├── routers/
│   │   │   │   ├── urls.py              # POST /api/analyze_url
│   │   │   │   ├── emails.py            # POST /api/analyze_email
│   │   │   │   └── reports.py           # POST /api/report
│   │   │   └── services/
│   │   │       ├── url_rules.py         # Heuristic rule analysis & feature extraction
│   │   │       ├── url_ml.py            # Random Forest ML model inference
│   │   │       ├── url_reputation.py    # Google Safe Browsing & PhishTank lookups
│   │   │       ├── email_rules.py       # Email urgency, credential & generic greeting heuristics
│   │   │       └── train_url_model.py   # Model training & joblib export pipeline
│   │   ├── requirements.txt
│   │   └── README.md
│   ├── frontend/
│   │   ├── app/
│   │   │   ├── page.tsx                 # Home + URL Scanner
│   │   │   ├── email-checker/page.tsx   # Email Threat Checker
│   │   │   ├── report/page.tsx          # Threat Report submission
│   │   │   └── learn/page.tsx           # Educational Awareness & Safety Tips
│   │   ├── components/
│   │   │   └── Navbar.tsx               # Navigation header
│   │   ├── package.json
│   │   └── README.md
│   └── README.md
├── src/                                 # Interactive AI Studio Live Web Engine & UI
│   ├── services/antiPhishingEngine.ts  # Layered detection engine (Rules, Reputation, ML, Fusion)
│   ├── components/                      # Modular React components (UrlChecker, EmailChecker, etc.)
│   └── App.tsx                          # Full-stack frontend
├── server.ts                            # Full-stack Node/Express server serving /api & UI
├── package.json
└── README.md
```

---

## Step-by-Step Setup

### 1. Database Creation (PostgreSQL)
Create the database and user for PhishGuard:
```bash
# Connect to PostgreSQL CLI
psql -U postgres

# Create user and database
CREATE USER phishguard_user WITH PASSWORD 'password';
CREATE DATABASE phishguard_db OWNER phishguard_user;
GRANT ALL PRIVILEGES ON DATABASE phishguard_db TO phishguard_user;
\q
```

### 2. Backend Setup (FastAPI)
```bash
cd phishguard/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the API server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
FastAPI interactive documentation will be available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

### 3. Frontend Setup (Next.js)
```bash
cd phishguard/frontend
npm install
npm run dev
```
Open `http://localhost:3000` to interact with the dashboard.

---

## Environment Variables

Configure `.env` in `phishguard/backend/`:
```env
# PostgreSQL connection string
DATABASE_URL=postgresql://phishguard_user:password@localhost:5432/phishguard_db

# External Threat Feeds (Optional)
GOOGLE_SAFE_BROWSING_API_KEY=""
PHISHTANK_API_KEY=""

# Model artifact path
ML_MODEL_PATH=models/rf_phishing_model.joblib

# Rate Limiter
RATE_LIMIT_PER_MINUTE=60
```

---

## Training and Plugging in the ML Model

The URL classifier evaluates 11 extracted lexical features:
1. `url_length`: Total character count
2. `num_dots`: Number of dot delimiters
3. `num_hyphens`: Number of hyphens in hostname
4. `num_slashes`: Path depth
5. `has_ip`: Flag for numeric IP address
6. `has_at_symbol`: Flag for `@` token obfuscation
7. `digit_ratio`: Density of numeric characters
8. `suspicious_keywords_count`: Security and auth keywords detected
9. `is_https`: TLS encryption flag
10. `entropy`: Shannon entropy measuring character randomness
11. `subdomain_count`: Depth of subdomain nesting

To train and export the model:
```bash
cd phishguard/backend
python -m app.services.train_url_model
```
This produces `models/rf_phishing_model.joblib` which is automatically loaded by `services/url_ml.py`.

---

## Live Interactive Preview in AI Studio

This workspace includes a Node.js + Express full-stack runtime on port 3000 (`server.ts`) that serves:
- `POST /api/analyze_url`: URL scan with exact requested JSON schema
- `POST /api/analyze_email`: Email threat scanner with likelihood & pattern detection
- `POST /api/report`: Threat report submission
- `GET /api/scans/recent`: Recent community scan feed
- `GET /api/reports`: Community threat reports
- Live UI with URL scanner gauge, email checker, interactive phishing simulator, and REST API playground.
