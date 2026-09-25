import React, { createContext, useContext, useState, useEffect } from 'react';
import type { User, AuthState, LoginSession } from '../types/auth';

interface AuthContextType extends AuthState {
  login: (email: string, password: string) => Promise<boolean>;
  loginDemo: (role?: 'SecOps Analyst' | 'Security Engineer' | 'User') => void;
  register: (name: string, email: string, password: string) => Promise<boolean>;
  logout: () => void;
  acknowledgeLastLogin: () => void;
  reportAccountCompromise: (reason?: string) => void;
  revokeSession: (sessionId: string) => void;
  revokeAllOtherSessions: () => void;
  simulateAnomalousLogin: () => void;
  resetToStandardLogin: () => void;
}

const DEFAULT_LAST_LOGIN: LoginSession = {
  id: 'sess_prev_01',
  timestamp: new Date(Date.now() - 1000 * 60 * 60 * 14).toISOString(), // 14 hours ago
  formattedTime: 'Yesterday at 9:42 PM',
  ipAddress: '136.24.192.8',
  location: 'Austin, Texas, United States',
  city: 'Austin',
  country: 'United States',
  countryCode: 'US',
  device: 'MacBook Pro (16-inch)',
  browser: 'Chrome 128.0.6613.85',
  os: 'macOS Sonoma',
  isp: 'AT&T Business Fiber (AS7018)',
  isCurrentSession: false,
  isSuspicious: false,
  reviewed: false,
};

const DEFAULT_CURRENT_SESSION: LoginSession = {
  id: 'sess_current_01',
  timestamp: new Date().toISOString(),
  formattedTime: 'Active now',
  ipAddress: '136.24.192.8',
  location: 'Austin, Texas, United States',
  city: 'Austin',
  country: 'United States',
  countryCode: 'US',
  device: 'MacBook Pro (16-inch)',
  browser: 'Chrome 128.0.6613.85',
  os: 'macOS Sonoma',
  isp: 'AT&T Business Fiber (AS7018)',
  isCurrentSession: true,
  isSuspicious: false,
  reviewed: true,
};

const DEFAULT_MOBILE_SESSION: LoginSession = {
  id: 'sess_mobile_02',
  timestamp: new Date(Date.now() - 1000 * 60 * 60 * 48).toISOString(), // 2 days ago
  formattedTime: 'Sep 22, 2026, 3:15 PM',
  ipAddress: '172.56.21.90',
  location: 'Austin, Texas, United States',
  city: 'Austin',
  country: 'United States',
  countryCode: 'US',
  device: 'iPhone 15 Pro',
  browser: 'Mobile Safari 18.0',
  os: 'iOS 18.0',
  isp: 'T-Mobile USA (AS21928)',
  isCurrentSession: false,
  isSuspicious: false,
  reviewed: true,
};

const DEFAULT_DEMO_USER: User = {
  id: 'usr_secops_99',
  name: 'Alex Vance',
  email: 'alex.vance@phishguard.sec',
  role: 'SecOps Analyst',
  scansCount: 42,
  securityStatus: 'review_required',
  lastLoginSession: DEFAULT_LAST_LOGIN,
  activeSessions: [DEFAULT_CURRENT_SESSION, DEFAULT_LAST_LOGIN, DEFAULT_MOBILE_SESSION],
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Registered accounts cache for client-side persistence and fallback
interface RegisteredAccount {
  email: string;
  passwordHash: string;
  name: string;
  role: 'SecOps Analyst' | 'Security Engineer' | 'User';
}

const DEFAULT_ACCOUNTS: Record<string, RegisteredAccount> = {
  'analyst@phishguard.io': {
    email: 'analyst@phishguard.io',
    passwordHash: 'Security2026!#',
    name: 'Alex Vance',
    role: 'SecOps Analyst',
  },
  'admin@phishguard.sec': {
    email: 'admin@phishguard.sec',
    passwordHash: 'CyberDefense!2026',
    name: 'Sarah Connor',
    role: 'Security Engineer',
  },
};

function getRegisteredAccounts(): Record<string, RegisteredAccount> {
  try {
    const raw = localStorage.getItem('phishguard_registered_accounts');
    if (!raw) {
      localStorage.setItem('phishguard_registered_accounts', JSON.stringify(DEFAULT_ACCOUNTS));
      return DEFAULT_ACCOUNTS;
    }
    return { ...DEFAULT_ACCOUNTS, ...JSON.parse(raw) };
  } catch {
    return DEFAULT_ACCOUNTS;
  }
}

function saveRegisteredAccount(acc: RegisteredAccount): void {
  try {
    const current = getRegisteredAccounts();
    current[acc.email.toLowerCase()] = acc;
    localStorage.setItem('phishguard_registered_accounts', JSON.stringify(current));
  } catch {
    // storage error
  }
}

/**
 * Validates enterprise password complexity rules
 */
export function validatePasswordRules(password: string): { isValid: boolean; error?: string } {
  if (!password || password.trim().length === 0) {
    return { isValid: false, error: 'Password cannot be blank.' };
  }
  if (password.length < 8) {
    return { isValid: false, error: 'Password must be at least 8 characters long.' };
  }
  if (!/[A-Z]/.test(password)) {
    return { isValid: false, error: 'Password must contain at least one uppercase letter (A-Z).' };
  }
  if (!/[a-z]/.test(password)) {
    return { isValid: false, error: 'Password must contain at least one lowercase letter (a-z).' };
  }
  if (!/[0-9]/.test(password)) {
    return { isValid: false, error: 'Password must contain at least one number (0-9).' };
  }
  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
    return { isValid: false, error: 'Password must contain at least one special character (!@#$%^&*).' };
  }
  const disallowed = ['1234', '12345', '123456', '12345678', 'password', 'password123', 'qwerty', 'admin'];
  if (disallowed.includes(password.toLowerCase().trim())) {
    return { isValid: false, error: 'Weak passwords such as "1234" are strictly disallowed.' };
  }
  return { isValid: true };
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [authState, setAuthState] = useState<AuthState>(() => {
    try {
      const stored = localStorage.getItem('phishguard_auth');
      if (stored) {
        const parsed = JSON.parse(stored);
        // Ensure user has lastLoginSession structure
        const userWithSession: User = {
          ...DEFAULT_DEMO_USER,
          ...parsed.user,
          lastLoginSession: parsed.user?.lastLoginSession || DEFAULT_LAST_LOGIN,
          activeSessions: parsed.user?.activeSessions || [DEFAULT_CURRENT_SESSION, DEFAULT_LAST_LOGIN],
          securityStatus: parsed.user?.securityStatus || 'review_required',
        };
        return {
          user: userWithSession,
          isAuthenticated: true,
          token: parsed.token || 'phishguard_jwt_token',
        };
      }
    } catch {
      // Local storage fallback
    }
    return {
      user: null,
      isAuthenticated: false,
      token: null,
    };
  });

  useEffect(() => {
    try {
      if (authState.isAuthenticated && authState.user) {
        localStorage.setItem(
          'phishguard_auth',
          JSON.stringify({ user: authState.user, token: authState.token })
        );
      } else {
        localStorage.removeItem('phishguard_auth');
      }
    } catch {
      // storage error
    }
  }, [authState]);

  const login = async (email: string, password: string): Promise<boolean> => {
    const trimmedEmail = email.trim().toLowerCase();
    const trimmedPassword = password.trim();

    // 1. Client-side input validation: Reject empty or weak inputs immediately
    if (!trimmedEmail) {
      throw new Error('Please enter your email address.');
    }
    if (!trimmedPassword) {
      throw new Error('Please enter your password.');
    }
    if (trimmedPassword.length < 8) {
      throw new Error('Invalid password: Password must be at least 8 characters.');
    }
    if (['1234', '12345', '123456', '12345678', 'password'].includes(trimmedPassword.toLowerCase())) {
      throw new Error('Access denied: Weak or common passwords like "1234" are rejected.');
    }

    // 2. Query authentication server
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: trimmedEmail, password: trimmedPassword }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Invalid email or password.');
      }

      const fullUser: User = {
        ...DEFAULT_DEMO_USER,
        ...data.user,
        lastLoginSession: DEFAULT_LAST_LOGIN,
        activeSessions: [DEFAULT_CURRENT_SESSION, DEFAULT_LAST_LOGIN],
        securityStatus: 'review_required',
      };

      setAuthState({
        user: fullUser,
        isAuthenticated: true,
        token: data.token,
      });

      return true;
    } catch (err: unknown) {
      // If error came directly from the server validation, bubble it up immediately
      if (err instanceof Error && !err.message.includes('fetch') && !err.message.includes('Network')) {
        throw err;
      }

      // 3. Fallback client-side credential verification (offline mode)
      const accounts = getRegisteredAccounts();
      const matched = accounts[trimmedEmail];

      if (!matched || matched.passwordHash !== trimmedPassword) {
        throw new Error('Invalid email or password. Access denied.');
      }

      const fullUser: User = {
        ...DEFAULT_DEMO_USER,
        id: `usr_${Date.now()}`,
        name: matched.name,
        email: matched.email,
        role: matched.role,
        lastLoginSession: DEFAULT_LAST_LOGIN,
        activeSessions: [DEFAULT_CURRENT_SESSION, DEFAULT_LAST_LOGIN],
        securityStatus: 'review_required',
      };

      setAuthState({
        user: fullUser,
        isAuthenticated: true,
        token: `offline_token_${Date.now()}`,
      });

      return true;
    }
  };

  const loginDemo = (role: 'SecOps Analyst' | 'Security Engineer' | 'User' = 'SecOps Analyst') => {
    const demoUser: User = {
      ...DEFAULT_DEMO_USER,
      role,
      lastLoginSession: { ...DEFAULT_LAST_LOGIN, reviewed: false },
      securityStatus: 'review_required',
    };
    setAuthState({
      user: demoUser,
      isAuthenticated: true,
      token: 'demo_token_secops',
    });
  };

  const register = async (name: string, email: string, password: string): Promise<boolean> => {
    const trimmedEmail = email.trim().toLowerCase();
    const trimmedPassword = password.trim();

    // 1. Enforce password complexity policy
    const policy = validatePasswordRules(trimmedPassword);
    if (!policy.isValid) {
      throw new Error(policy.error || 'Password does not meet enterprise security requirements.');
    }

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), email: trimmedEmail, password: trimmedPassword }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Failed to create account.');
      }

      // Save to client accounts cache
      saveRegisteredAccount({
        email: trimmedEmail,
        passwordHash: trimmedPassword,
        name: name.trim(),
        role: 'Security Engineer',
      });

      const newUser: User = {
        id: data.user.id,
        name: data.user.name,
        email: data.user.email,
        role: 'Security Engineer',
        scansCount: 0,
        securityStatus: 'normal',
        lastLoginSession: DEFAULT_CURRENT_SESSION,
        activeSessions: [DEFAULT_CURRENT_SESSION],
      };

      setAuthState({
        user: newUser,
        isAuthenticated: true,
        token: data.token,
      });

      return true;
    } catch (err: unknown) {
      if (err instanceof Error && !err.message.includes('fetch') && !err.message.includes('Network')) {
        throw err;
      }

      // Client-side registration fallback
      saveRegisteredAccount({
        email: trimmedEmail,
        passwordHash: trimmedPassword,
        name: name.trim(),
        role: 'Security Engineer',
      });

      const newUser: User = {
        id: `usr_${Date.now()}`,
        name: name.trim(),
        email: trimmedEmail,
        role: 'Security Engineer',
        scansCount: 0,
        securityStatus: 'normal',
        lastLoginSession: DEFAULT_CURRENT_SESSION,
        activeSessions: [DEFAULT_CURRENT_SESSION],
      };

      setAuthState({
        user: newUser,
        isAuthenticated: true,
        token: `offline_token_${Date.now()}`,
      });

      return true;
    }
  };

  const logout = () => {
    setAuthState({
      user: null,
      isAuthenticated: false,
      token: null,
    });
  };

  const acknowledgeLastLogin = () => {
    if (!authState.user) return;
    const updatedUser: User = {
      ...authState.user,
      securityStatus: 'normal',
      lastLoginSession: {
        ...authState.user.lastLoginSession,
        reviewed: true,
      },
    };
    setAuthState((prev) => ({
      ...prev,
      user: updatedUser,
    }));
  };

  const reportAccountCompromise = (reason?: string) => {
    if (!authState.user) return;
    // Quarantine all other sessions and flag compromise status
    const onlyCurrent = authState.user.activeSessions.filter((s) => s.isCurrentSession);
    const updatedUser: User = {
      ...authState.user,
      securityStatus: 'compromise_flagged',
      activeSessions: onlyCurrent,
      lastLoginSession: {
        ...authState.user.lastLoginSession,
        isSuspicious: true,
        suspicionReason: reason || 'Unrecognized location and client reported by account holder',
        reviewed: true,
      },
    };
    setAuthState((prev) => ({
      ...prev,
      user: updatedUser,
    }));
  };

  const revokeSession = (sessionId: string) => {
    if (!authState.user) return;
    const remaining = authState.user.activeSessions.filter((s) => s.id !== sessionId);
    setAuthState((prev) => ({
      ...prev,
      user: prev.user ? { ...prev.user, activeSessions: remaining } : null,
    }));
  };

  const revokeAllOtherSessions = () => {
    if (!authState.user) return;
    const currentOnly = authState.user.activeSessions.filter((s) => s.isCurrentSession);
    setAuthState((prev) => ({
      ...prev,
      user: prev.user ? { ...prev.user, activeSessions: currentOnly } : null,
    }));
  };

  const simulateAnomalousLogin = () => {
    if (!authState.user) return;
    const anomalousSession: LoginSession = {
      id: `sess_anom_${Date.now()}`,
      timestamp: new Date(Date.now() - 1000 * 60 * 45).toISOString(), // 45 mins ago
      formattedTime: 'Today at 3:18 AM (45 mins ago)',
      ipAddress: '185.220.101.5',
      location: 'Frankfurt am Main, Hessen, Germany',
      city: 'Frankfurt',
      country: 'Germany',
      countryCode: 'DE',
      device: 'Unknown Linux Workstation (x86_64)',
      browser: 'Firefox 115.0 (Tor Exit Node detected)',
      os: 'Linux (Ubuntu 22.04)',
      isp: 'Tor Transit Relay ASN / DataCamp GmbH',
      isCurrentSession: false,
      isSuspicious: true,
      suspicionReason: 'Impossible travel anomaly: 5,400 miles from normal sign-in location within 2 hours. Tor Exit Relay detected.',
      reviewed: false,
    };

    setAuthState((prev) => ({
      ...prev,
      user: prev.user
        ? {
            ...prev.user,
            securityStatus: 'review_required',
            lastLoginSession: anomalousSession,
            activeSessions: [DEFAULT_CURRENT_SESSION, anomalousSession, ...prev.user.activeSessions.filter(s => !s.isCurrentSession)],
          }
        : null,
    }));
  };

  const resetToStandardLogin = () => {
    if (!authState.user) return;
    setAuthState((prev) => ({
      ...prev,
      user: prev.user
        ? {
            ...prev.user,
            securityStatus: 'review_required',
            lastLoginSession: { ...DEFAULT_LAST_LOGIN, reviewed: false },
            activeSessions: [DEFAULT_CURRENT_SESSION, DEFAULT_LAST_LOGIN, DEFAULT_MOBILE_SESSION],
          }
        : null,
    }));
  };

  return (
    <AuthContext.Provider
      value={{
        ...authState,
        login,
        loginDemo,
        register,
        logout,
        acknowledgeLastLogin,
        reportAccountCompromise,
        revokeSession,
        revokeAllOtherSessions,
        simulateAnomalousLogin,
        resetToStandardLogin,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

