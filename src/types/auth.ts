export interface LoginSession {
  id: string;
  timestamp: string;
  formattedTime: string;
  ipAddress: string;
  location: string;
  city: string;
  country: string;
  countryCode: string;
  device: string;
  browser: string;
  os: string;
  isp: string;
  isCurrentSession: boolean;
  isSuspicious: boolean;
  suspicionReason?: string;
  reviewed: boolean;
}

export interface User {
  id: string;
  name: string;
  email: string;
  role: 'SecOps Analyst' | 'Security Engineer' | 'User';
  avatar?: string;
  scansCount: number;
  lastLoginSession: LoginSession;
  activeSessions: LoginSession[];
  securityStatus: 'normal' | 'review_required' | 'compromise_flagged';
}

export interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  token: string | null;
}

