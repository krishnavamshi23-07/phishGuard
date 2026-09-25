# PhishGuard Frontend (Next.js 14 App Router + Tailwind CSS)

Clean, responsive security dashboard for anti-phishing threat intelligence.

## Features
- **URL Scanner (`/`)**: Hero section, quick presets, risk score gauge (0-100), verdict badges, and layered detection breakdowns.
- **Email Threat Checker (`/email-checker`)**: Subject & body analysis for coercive language, credential theft lures, and generic salutations.
- **Threat Reporting (`/report`)**: Community submission form to report malicious links or phishing emails.
- **Security Education (`/learn`)**: Educational guide on detecting domain lookalikes, email spoofing, and defensive best practices.

## Running Locally

### Install dependencies
```bash
cd phishguard/frontend
npm install
```

### Run dev server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.
Ensure the backend API is running on [http://localhost:8000](http://localhost:8000) or proxies `/api`.
