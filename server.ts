import express, { Request, Response, NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import {
  analyzeUrl,
  analyzeEmailContent,
  globalPhishGuardStore,
} from './src/services/antiPhishingEngine.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = parseInt(process.env.PORT || '3000', 10);

app.use(express.json({ limit: '2mb' }));

// Simple in-memory sliding window rate limiter
const rateLimitMap = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 60; // 60 requests/minute per IP

function rateLimiter(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip || req.socket.remoteAddress || 'unknown-client';
  const now = Date.now();
  const clientRecord = rateLimitMap.get(ip);

  if (!clientRecord || now > clientRecord.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return next();
  }

  if (clientRecord.count >= MAX_REQUESTS_PER_WINDOW) {
    res.status(429).json({
      error: 'Too Many Requests',
      message: 'Rate limit exceeded. Please wait a minute before making more requests.',
      retryAfterSeconds: Math.ceil((clientRecord.resetTime - now) / 1000),
    });
    return;
  }

  clientRecord.count++;
  next();
}

// -------------------------------------------------------------
// API Endpoints
// -------------------------------------------------------------

// -------------------------------------------------------------
// Authentication Store & Brute-Force Defense
// -------------------------------------------------------------

interface StoredUser {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  role: 'SecOps Analyst' | 'Security Engineer' | 'User';
  scansCount: number;
}

// Initial registered authorized users
const registeredUsers: Map<string, StoredUser> = new Map([
  [
    'analyst@phishguard.io',
    {
      id: 'usr_secops_99',
      name: 'Alex Vance',
      email: 'analyst@phishguard.io',
      passwordHash: 'Security2026!#',
      role: 'SecOps Analyst',
      scansCount: 42,
    },
  ],
  [
    'admin@phishguard.sec',
    {
      id: 'usr_admin_01',
      name: 'Sarah Connor',
      email: 'admin@phishguard.sec',
      passwordHash: 'CyberDefense!2026',
      role: 'Security Engineer',
      scansCount: 88,
    },
  ],
]);

// Brute force tracking: maps email -> failed attempts and lockout expiration
const failedLoginAttempts = new Map<string, { count: number; lockedUntil: number }>();

function validatePasswordPolicy(password: string): { valid: boolean; reason?: string } {
  if (!password || password.length < 8) {
    return { valid: false, reason: 'Password must be at least 8 characters long.' };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, reason: 'Password must include at least one uppercase letter (A-Z).' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, reason: 'Password must include at least one lowercase letter (a-z).' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, reason: 'Password must include at least one number (0-9).' };
  }
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
    return { valid: false, reason: 'Password must include at least one special character (!@#$%^&*).' };
  }
  const weakPasswords = ['1234', '12345', '123456', '12345678', 'password', 'password123', 'admin123', 'phishguard'];
  if (weakPasswords.includes(password.toLowerCase())) {
    return { valid: false, reason: 'This password is too weak and vulnerable to dictionary attacks.' };
  }
  return { valid: true };
}

// -------------------------------------------------------------
// API Endpoints
// -------------------------------------------------------------

// Authentication endpoints
app.post('/api/auth/login', rateLimiter, (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ error: 'Email and password are required' });
    return;
  }

  const normalizedEmail = String(email).trim().toLowerCase();

  // Check brute-force lockout
  const attempt = failedLoginAttempts.get(normalizedEmail);
  if (attempt && attempt.lockedUntil > Date.now()) {
    const remainingMins = Math.ceil((attempt.lockedUntil - Date.now()) / 60000);
    res.status(403).json({
      error: `Account temporarily locked due to excessive failed attempts. Please retry in ${remainingMins} minute(s).`,
    });
    return;
  }

  const user = registeredUsers.get(normalizedEmail);

  // STRICT CREDENTIAL CHECK: Do not allow arbitrary passwords like '1234'
  if (!user || user.passwordHash !== password) {
    const currentCount = (attempt?.count || 0) + 1;
    if (currentCount >= 5) {
      failedLoginAttempts.set(normalizedEmail, { count: currentCount, lockedUntil: Date.now() + 5 * 60 * 1000 });
      res.status(401).json({
        error: 'Too many incorrect password attempts. This account is locked for 5 minutes for security.',
      });
      return;
    } else {
      failedLoginAttempts.set(normalizedEmail, { count: currentCount, lockedUntil: 0 });
      res.status(401).json({
        error: `Invalid email or password. Attempt ${currentCount} of 5 before temporary lockout.`,
      });
      return;
    }
  }

  // Successful login: Clear failed attempts
  failedLoginAttempts.delete(normalizedEmail);

  res.json({
    token: `pg_jwt_${Date.now()}`,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      scansCount: user.scansCount,
    },
  });
});

app.post('/api/auth/register', rateLimiter, (req: Request, res: Response) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    res.status(400).json({ error: 'Name, email, and password are required' });
    return;
  }

  const normalizedEmail = String(email).trim().toLowerCase();

  // Check if user already exists
  if (registeredUsers.has(normalizedEmail)) {
    res.status(409).json({ error: 'An account with this email address already exists. Please log in.' });
    return;
  }

  // Validate strong password policy
  const policyCheck = validatePasswordPolicy(password);
  if (!policyCheck.valid) {
    res.status(400).json({ error: policyCheck.reason });
    return;
  }

  const newUser: StoredUser = {
    id: `usr_${Date.now()}`,
    name: String(name).trim(),
    email: normalizedEmail,
    passwordHash: password,
    role: 'Security Engineer',
    scansCount: 0,
  };

  registeredUsers.set(normalizedEmail, newUser);

  res.json({
    token: `pg_jwt_${Date.now()}`,
    user: {
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
      role: newUser.role,
      scansCount: 0,
    },
  });
});

// Health check
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'PhishGuard Detection API',
    version: '1.0.0',
    layers: ['rule_based_heuristics', 'reputation_blocklists', 'ml_url_classifier'],
    timestamp: new Date().toISOString(),
  });
});

// POST /api/analyze_url
app.post('/api/analyze_url', rateLimiter, async (req: Request, res: Response) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== 'string' || url.trim().length === 0) {
      res.status(400).json({
        error: 'Bad Request',
        message: 'A valid "url" string is required in the request body.',
      });
      return;
    }

    const scanResult = await analyzeUrl(url.trim());
    globalPhishGuardStore.addUrlScan(scanResult);

    // Return the exact required schema
    res.json({
      risk_score: scanResult.risk_score,
      verdict: scanResult.verdict,
      reasons: scanResult.reasons,
      details: scanResult.details,
      id: scanResult.id,
      created_at: scanResult.created_at,
    });
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : 'Analysis failed';
    res.status(400).json({
      error: 'Analysis Error',
      message: errorMessage,
    });
  }
});

// POST /api/analyze_email
app.post('/api/analyze_email', rateLimiter, (req: Request, res: Response) => {
  try {
    const { subject, body } = req.body;
    if (typeof body !== 'string' && typeof subject !== 'string') {
      res.status(400).json({
        error: 'Bad Request',
        message: 'Either email "subject" or "body" must be provided.',
      });
      return;
    }

    const scanResult = analyzeEmailContent(subject || '', body || '');
    globalPhishGuardStore.addEmailScan(scanResult);

    // Return exact required schema
    res.json({
      phishing_likelihood: scanResult.phishing_likelihood,
      score: scanResult.score,
      patterns_found: scanResult.patterns_found,
      id: scanResult.id,
      subject: scanResult.subject,
      body_preview: scanResult.body_preview,
      detailed_findings: scanResult.detailed_findings,
      created_at: scanResult.created_at,
    });
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : 'Analysis failed';
    res.status(500).json({
      error: 'Server Error',
      message: errorMessage,
    });
  }
});

// POST /api/report
app.post('/api/report', rateLimiter, (req: Request, res: Response) => {
  try {
    const { type, content, notes } = req.body;
    if (!type || (type !== 'url' && type !== 'email')) {
      res.status(400).json({
        error: 'Bad Request',
        message: 'Field "type" must be either "url" or "email".',
      });
      return;
    }

    if (!content || typeof content !== 'string' || content.trim().length === 0) {
      res.status(400).json({
        error: 'Bad Request',
        message: 'Field "content" is required.',
      });
      return;
    }

    const report = globalPhishGuardStore.addReport(type, content.trim(), notes?.trim());

    res.json({
      success: true,
      report_id: report.id,
      created_at: report.created_at,
    });
  } catch (err: unknown) {
    const errorMessage = err instanceof Error ? err.message : 'Failed to save report';
    res.status(500).json({
      error: 'Server Error',
      message: errorMessage,
    });
  }
});

// GET /api/recent_scans
app.get('/api/recent_scans', (_req: Request, res: Response) => {
  res.json({
    urls: globalPhishGuardStore.getRecentUrlScans(),
    emails: globalPhishGuardStore.getRecentEmailScans(),
  });
});

// GET /api/reports
app.get('/api/reports', (_req: Request, res: Response) => {
  res.json({
    reports: globalPhishGuardStore.getRecentReports(),
  });
});

// Mount Vite in dev or static files in production
async function startServer() {
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`PhishGuard security engine running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
