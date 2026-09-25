import React, { useState, useMemo } from 'react';
import {
  ShieldCheck,
  Lock,
  Mail,
  User as UserIcon,
  ArrowRight,
  Eye,
  EyeOff,
  Shield,
  Layers,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const LoginPage: React.FC = () => {
  const { login, register } = useAuth();
  const [isRegisterMode, setIsRegisterMode] = useState(false);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Real-time password strength checks
  const passwordChecks = useMemo(() => {
    return {
      hasLength: password.length >= 8,
      hasUpper: /[A-Z]/.test(password),
      hasLower: /[a-z]/.test(password),
      hasNumber: /[0-9]/.test(password),
      hasSpecial: /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password),
      isNotCommon: !['1234', '12345', '123456', '12345678', 'password', 'qwerty'].includes(
        password.toLowerCase().trim()
      ),
    };
  }, [password]);

  const passwordScore = useMemo(() => {
    let score = 0;
    if (passwordChecks.hasLength) score++;
    if (passwordChecks.hasUpper) score++;
    if (passwordChecks.hasLower) score++;
    if (passwordChecks.hasNumber) score++;
    if (passwordChecks.hasSpecial) score++;
    if (passwordChecks.isNotCommon) score++;
    return score;
  }, [passwordChecks]);

  const strengthLabel = useMemo(() => {
    if (!password) return { text: 'Empty', color: 'bg-slate-700' };
    if (passwordScore <= 2) return { text: 'Weak', color: 'bg-rose-500' };
    if (passwordScore <= 4) return { text: 'Moderate', color: 'bg-amber-500' };
    return { text: 'Strong', color: 'bg-emerald-500' };
  }, [password, passwordScore]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    const trimmedEmail = email.trim();
    const trimmedPassword = password.trim();

    if (!trimmedEmail || !trimmedPassword) {
      setError('Please provide both work email and password.');
      return;
    }

    if (isRegisterMode) {
      if (!name.trim()) {
        setError('Please enter your full name.');
        return;
      }

      // Check password policy before submitting
      if (
        !passwordChecks.hasLength ||
        !passwordChecks.hasUpper ||
        !passwordChecks.hasLower ||
        !passwordChecks.hasNumber ||
        !passwordChecks.hasSpecial ||
        !passwordChecks.isNotCommon
      ) {
        setError(
          'Password does not meet enterprise security requirements. Must be 8+ chars with uppercase, lowercase, number, and special character.'
        );
        return;
      }
    } else {
      // Login mode validation
      if (trimmedPassword.length < 8) {
        setError('Invalid password: Minimum 8 characters required.');
        return;
      }
      if (['1234', '12345', '123456', '12345678', 'password'].includes(trimmedPassword.toLowerCase())) {
        setError('Access Denied: Weak passwords such as "1234" are rejected. Use authorized credentials.');
        return;
      }
    }

    setLoading(true);

    try {
      if (isRegisterMode) {
        await register(name.trim(), trimmedEmail, trimmedPassword);
        setSuccessMsg('Account created successfully! Redirecting...');
      } else {
        await login(trimmedEmail, trimmedPassword);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center px-4 sm:px-6 lg:px-8 relative overflow-hidden font-sans selection:bg-indigo-500 selection:text-white py-12">
      {/* Ambient Glows */}
      <div className="absolute top-1/4 -left-48 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 -right-48 w-96 h-96 bg-emerald-600/10 rounded-full blur-3xl pointer-events-none" />

      {/* Main Container */}
      <div className="w-full max-w-md space-y-6 relative z-10">
        {/* Header Branding */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-indigo-500 via-blue-600 to-emerald-500 p-0.5 shadow-xl shadow-indigo-500/25 mx-auto">
            <div className="w-full h-full bg-slate-950 rounded-[14px] flex items-center justify-center">
              <ShieldCheck className="w-7 h-7 text-emerald-400" />
            </div>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            PhishGuard Portal
          </h1>
          <p className="text-slate-400 text-xs sm:text-sm">
            Strict Enterprise Authentication &amp; Threat Defense
          </p>
        </div>

        {/* Auth Card */}
        <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-6 sm:p-7 shadow-2xl backdrop-blur-sm space-y-5">
          {/* Toggle between Login and Register */}
          <div className="grid grid-cols-2 p-1 bg-slate-950 rounded-lg border border-slate-800 text-xs font-medium">
            <button
              type="button"
              onClick={() => {
                setIsRegisterMode(false);
                setError(null);
                setSuccessMsg(null);
              }}
              className={`py-1.5 rounded-md transition-all cursor-pointer ${
                !isRegisterMode
                  ? 'bg-slate-800 text-white shadow-sm font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setIsRegisterMode(true);
                setError(null);
                setSuccessMsg(null);
              }}
              className={`py-1.5 rounded-md transition-all cursor-pointer ${
                isRegisterMode
                  ? 'bg-slate-800 text-white shadow-sm font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Create Account
            </button>
          </div>

          {/* Error Banner */}
          {error && (
            <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/40 text-rose-300 text-xs flex items-start space-x-2 animate-shake">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Success Banner */}
          {successMsg && (
            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 text-xs flex items-start space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {isRegisterMode && (
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wide mb-1">
                  Full Name
                </label>
                <div className="relative flex items-center">
                  <UserIcon className="w-4 h-4 text-slate-500 absolute left-3" />
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Jane Doe"
                    className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                  />
                </div>
              </div>
            )}

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wide mb-1">
                Work Email
              </label>
              <div className="relative flex items-center">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@organization.com"
                  className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-1">
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wide">
                  Password
                </label>
                {password && (
                  <span className="text-[10px] text-slate-400 flex items-center space-x-1">
                    <span>Strength:</span>
                    <strong
                      className={
                        strengthLabel.text === 'Strong'
                          ? 'text-emerald-400'
                          : strengthLabel.text === 'Moderate'
                          ? 'text-amber-400'
                          : 'text-rose-400'
                      }
                    >
                      {strengthLabel.text}
                    </strong>
                  </span>
                )}
              </div>

              <div className="relative flex items-center">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3" />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-10 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 text-slate-500 hover:text-slate-300 cursor-pointer"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>

              {/* Password Strength Meter (Visual Bars) */}
              <div className="mt-2 grid grid-cols-4 gap-1.5">
                {[1, 2, 3, 4].map((step) => (
                  <div
                    key={step}
                    className={`h-1 rounded-full transition-all ${
                      passwordScore >= step * 1.25 ? strengthLabel.color : 'bg-slate-800'
                    }`}
                  />
                ))}
              </div>

              {/* Immediate Feedback for Weak/Invalid Passwords */}
              {password.length > 0 && !passwordChecks.isNotCommon && (
                <div className="mt-1.5 flex items-center space-x-1.5 text-[11px] text-rose-400">
                  <XCircle className="w-3.5 h-3.5 shrink-0" />
                  <span>Disallowed: Common weak password sequence detected.</span>
                </div>
              )}
              {password.length > 0 && password.length < 8 && passwordChecks.isNotCommon && (
                <div className="mt-1.5 flex items-center space-x-1.5 text-[11px] text-amber-400">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  <span>Must be at least 8 characters ({password.length}/8).</span>
                </div>
              )}

              {/* Real-time Requirements Checklist in Register Mode */}
              {isRegisterMode && (
                <div className="mt-2.5 p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 text-[11px] space-y-1">
                  <div className="text-slate-400 font-semibold text-[10px] uppercase">
                    Security Requirements:
                  </div>
                  <div className="grid grid-cols-2 gap-1 text-slate-300">
                    <span className={`flex items-center space-x-1 ${passwordChecks.hasLength ? 'text-emerald-400' : 'text-slate-500'}`}>
                      {passwordChecks.hasLength ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3 text-rose-500" />}
                      <span>8+ characters</span>
                    </span>
                    <span className={`flex items-center space-x-1 ${passwordChecks.hasUpper ? 'text-emerald-400' : 'text-slate-500'}`}>
                      {passwordChecks.hasUpper ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3 text-rose-500" />}
                      <span>Uppercase (A-Z)</span>
                    </span>
                    <span className={`flex items-center space-x-1 ${passwordChecks.hasNumber ? 'text-emerald-400' : 'text-slate-500'}`}>
                      {passwordChecks.hasNumber ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3 text-rose-500" />}
                      <span>Number (0-9)</span>
                    </span>
                    <span className={`flex items-center space-x-1 ${passwordChecks.hasSpecial ? 'text-emerald-400' : 'text-slate-500'}`}>
                      {passwordChecks.hasSpecial ? <CheckCircle2 className="w-3 h-3" /> : <XCircle className="w-3 h-3 text-rose-500" />}
                      <span>Special (!@#$)</span>
                    </span>
                  </div>
                </div>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-sm transition-all shadow-md shadow-indigo-600/30 disabled:opacity-50 flex items-center justify-center space-x-2 cursor-pointer"
            >
              {loading ? (
                <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
              ) : (
                <>
                  <span>{isRegisterMode ? 'Create Secure Account' : 'Authenticate & Enter'}</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>
        </div>

        {/* Security Compliance Badges */}
        <div className="flex items-center justify-center space-x-4 text-[11px] text-slate-500">
          <div className="flex items-center space-x-1">
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
            <span>Brute-Force Protected</span>
          </div>
          <span>&bull;</span>
          <div className="flex items-center space-x-1">
            <Layers className="w-3.5 h-3.5 text-indigo-400" />
            <span>Strict Password Hash</span>
          </div>
          <span>&bull;</span>
          <span>Encrypted Session</span>
        </div>
      </div>
    </div>
  );
};
