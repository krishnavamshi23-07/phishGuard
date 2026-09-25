import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  ShieldAlert,
  ShieldCheck,
  MapPin,
  Clock,
  Laptop,
  Smartphone,
  Globe,
  CheckCircle2,
  AlertTriangle,
  Lock,
  ChevronDown,
  ChevronUp,
  X,
  Radio,
  ExternalLink,
  RotateCcw,
  Sparkles,
  Info,
} from 'lucide-react';

interface LastLoginSecurityReviewProps {
  isOpen?: boolean;
  onClose?: () => void;
  isModal?: boolean;
}

export const LastLoginSecurityReview: React.FC<LastLoginSecurityReviewProps> = ({
  isOpen = true,
  onClose,
  isModal = false,
}) => {
  const {
    user,
    acknowledgeLastLogin,
    reportAccountCompromise,
    revokeSession,
    revokeAllOtherSessions,
    simulateAnomalousLogin,
    resetToStandardLogin,
  } = useAuth();

  const [showAllSessionsModal, setShowAllSessionsModal] = useState(false);
  const [showCompromiseModal, setShowCompromiseModal] = useState(false);
  const [copiedIp, setCopiedIp] = useState(false);

  if (!user || (!isOpen && isModal)) return null;

  const session = user.lastLoginSession;
  const isReviewed = session.reviewed;
  const isCompromised = user.securityStatus === 'compromise_flagged';
  const isSuspicious = session.isSuspicious;

  const handleCopyIp = (ip: string) => {
    navigator.clipboard.writeText(ip);
    setCopiedIp(true);
    setTimeout(() => setCopiedIp(false), 2000);
  };

  const handleConfirmCompromise = () => {
    reportAccountCompromise('Unrecognized login session reported by user during login security review');
    setShowCompromiseModal(false);
  };

  const handleAcknowledge = () => {
    acknowledgeLastLogin();
    if (onClose) onClose();
  };

  const cardContent = (
    <div
      className={`rounded-2xl border transition-all shadow-2xl overflow-hidden ${
        isCompromised
          ? 'bg-rose-950/30 border-rose-500/50 shadow-rose-950/20'
          : isSuspicious
          ? 'bg-amber-950/20 border-amber-500/40 shadow-amber-950/20'
          : 'bg-gradient-to-b from-slate-900 via-slate-900/80 to-slate-950 border-slate-800'
      }`}
    >
      {/* Top Status Header */}
      <div className="px-5 py-3.5 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-3 bg-slate-950/60">
        <div className="flex items-center space-x-3">
          <div
            className={`w-8 h-8 rounded-xl flex items-center justify-center shrink-0 border ${
              isCompromised
                ? 'bg-rose-500/20 border-rose-500/40 text-rose-400 animate-pulse'
                : isSuspicious
                ? 'bg-amber-500/20 border-amber-500/40 text-amber-400 animate-pulse'
                : 'bg-indigo-500/15 border-indigo-500/30 text-indigo-400'
            }`}
          >
            {isCompromised ? (
              <ShieldAlert className="w-4 h-4 text-rose-400" />
            ) : isSuspicious ? (
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            ) : (
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            )}
          </div>

          <div>
            <div className="flex items-center space-x-2">
              <h3 className="text-sm font-bold text-white tracking-tight">
                {isCompromised
                  ? 'Security Incident: Account Lockdown Active'
                  : isSuspicious
                  ? 'Unusual Login Location Detected'
                  : 'Last Login Security Review'}
              </h3>
              <span
                className={`text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full ${
                  isCompromised
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    : isSuspicious
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    : isReviewed
                    ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                    : 'bg-indigo-500/15 text-indigo-300 border border-indigo-500/30'
                }`}
              >
                {isCompromised
                  ? 'Quarantined'
                  : isSuspicious
                  ? 'Action Required'
                  : isReviewed
                  ? 'Verified'
                  : 'Awaiting Review'}
              </span>
            </div>
            <p className="text-xs text-slate-400">
              {isCompromised
                ? 'All unrecognized sessions revoked. Password & MFA rotation recommended.'
                : isSuspicious
                ? 'Sign-in detected from an unexpected network or foreign location.'
                : 'Confirm when and where your account was accessed to guard against unauthorized compromise.'}
            </p>
          </div>
        </div>

        {/* Simulation Toggle, Sessions Drawer & Close */}
        <div className="flex items-center space-x-2">
          {isSuspicious ? (
            <button
              onClick={resetToStandardLogin}
              className="text-[11px] px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 flex items-center space-x-1 transition-colors cursor-pointer"
              title="Reset simulation to known recognized location"
            >
              <RotateCcw className="w-3 h-3 text-slate-400" />
              <span>Reset Demo</span>
            </button>
          ) : (
            <button
              onClick={simulateAnomalousLogin}
              className="text-[11px] px-2.5 py-1 rounded-md bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 flex items-center space-x-1 transition-colors cursor-pointer"
              title="Simulate what happens when an anomalous login occurs"
            >
              <Sparkles className="w-3 h-3 text-amber-400" />
              <span>Simulate Anomaly</span>
            </button>
          )}

          <button
            onClick={() => setShowAllSessionsModal(true)}
            className="text-[11px] px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition-colors cursor-pointer"
          >
            Sessions ({user.activeSessions.length})
          </button>

          {onClose && (
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer ml-1"
              title="Close Review"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

        {/* Suspicious Alert Banner (if anomalous) */}
        {isSuspicious && session.suspicionReason && !isCompromised && (
          <div className="px-5 py-2.5 bg-amber-500/10 border-b border-amber-500/25 flex items-start space-x-2.5 text-xs text-amber-200">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-0.5">
              <span className="font-semibold text-amber-300">Anomalous Sign-in Flag:</span>{' '}
              <span>{session.suspicionReason}</span>
            </div>
          </div>
        )}

        {/* Detailed Telemetry Grid */}
        <div className="p-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Time Telemetry */}
          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1">
            <div className="flex items-center space-x-1.5 text-slate-400 text-[11px] font-semibold uppercase tracking-wider">
              <Clock className="w-3.5 h-3.5 text-indigo-400" />
              <span>When Accessed</span>
            </div>
            <div className="text-sm font-semibold text-white font-mono">
              {session.formattedTime}
            </div>
            <p className="text-[11px] text-slate-400 font-mono">
              {new Date(session.timestamp).toLocaleString()}
            </p>
          </div>

          {/* Location Telemetry */}
          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1">
            <div className="flex items-center space-x-1.5 text-slate-400 text-[11px] font-semibold uppercase tracking-wider">
              <MapPin className="w-3.5 h-3.5 text-rose-400" />
              <span>From Where (Geo)</span>
            </div>
            <div className="text-sm font-semibold text-white truncate" title={session.location}>
              {session.location}
            </div>
            <p className="text-[11px] text-slate-400 flex items-center space-x-1">
              <span>Country Code:</span>
              <span className="font-mono text-slate-300 font-bold bg-slate-800 px-1 rounded">
                {session.countryCode}
              </span>
            </p>
          </div>

          {/* IP Address & Network */}
          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1">
            <div className="flex items-center justify-between text-slate-400 text-[11px] font-semibold uppercase tracking-wider">
              <div className="flex items-center space-x-1.5">
                <Globe className="w-3.5 h-3.5 text-blue-400" />
                <span>IP &amp; Provider</span>
              </div>
              <button
                onClick={() => handleCopyIp(session.ipAddress)}
                className="text-[10px] text-indigo-400 hover:text-indigo-300 cursor-pointer font-sans"
              >
                {copiedIp ? 'Copied!' : 'Copy IP'}
              </button>
            </div>
            <div className="text-sm font-mono font-bold text-indigo-300 truncate">
              {session.ipAddress}
            </div>
            <p className="text-[11px] text-slate-400 truncate" title={session.isp}>
              {session.isp}
            </p>
          </div>

          {/* Device & Client Fingerprint */}
          <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-1">
            <div className="flex items-center space-x-1.5 text-slate-400 text-[11px] font-semibold uppercase tracking-wider">
              <Laptop className="w-3.5 h-3.5 text-emerald-400" />
              <span>Device &amp; Client</span>
            </div>
            <div className="text-sm font-semibold text-white truncate" title={session.device}>
              {session.device}
            </div>
            <p className="text-[11px] text-slate-400 truncate" title={session.browser}>
              {session.browser}
            </p>
          </div>
        </div>

        {/* Action Decision Footer ("Was this you?") */}
        <div className="px-5 py-3.5 bg-slate-950/90 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-2 text-xs text-slate-300">
            <Info className="w-4 h-4 text-indigo-400 shrink-0" />
            <span>
              {isCompromised ? (
                <span className="text-rose-300 font-medium">
                  Incident protocol triggered: Unrecognized access quarantined.
                </span>
              ) : isReviewed ? (
                <span className="text-emerald-300 font-medium">
                  You verified this session as authentic.
                </span>
              ) : (
                <span>
                  Did you access your PhishGuard account from <strong>{session.location}</strong>?
                </span>
              )}
            </span>
          </div>

          <div className="flex items-center space-x-2.5 shrink-0">
            {isCompromised ? (
              <button
                onClick={resetToStandardLogin}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold transition-colors cursor-pointer flex items-center space-x-1.5"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Clear Alert &amp; Re-verify</span>
              </button>
            ) : isReviewed ? (
              <button
                onClick={onClose}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors cursor-pointer"
              >
                Close Review
              </button>
            ) : (
              <>
                <button
                  type="button"
                  onClick={() => setShowCompromiseModal(true)}
                  className="px-4 py-2 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-300 text-xs font-semibold transition-all flex items-center space-x-1.5 cursor-pointer"
                >
                  <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                  <span>No, this was not me</span>
                </button>

                <button
                  type="button"
                  onClick={handleAcknowledge}
                  className="px-5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white text-xs font-semibold shadow-md shadow-emerald-600/20 transition-all flex items-center space-x-1.5 cursor-pointer"
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Yes, this was me</span>
                </button>
              </>
            )}
          </div>
        </div>
      </div>
  );

  return (
    <>
      {isModal ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-fade-in overflow-y-auto">
          <div className="max-w-4xl w-full my-8">
            {cardContent}
          </div>
        </div>
      ) : (
        cardContent
      )}

      {/* Account Compromise Incident Modal */}
      {showCompromiseModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="max-w-lg w-full rounded-2xl bg-slate-900 border border-rose-500/50 p-6 space-y-5 shadow-2xl shadow-rose-950/40">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2.5 text-rose-400">
                <ShieldAlert className="w-5 h-5 text-rose-400" />
                <h3 className="font-bold text-white text-base">Account Security Containment</h3>
              </div>
              <button
                onClick={() => setShowCompromiseModal(false)}
                className="text-slate-400 hover:text-white cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-200 space-y-2">
              <div className="font-semibold text-rose-300 flex items-center space-x-1.5">
                <AlertTriangle className="w-4 h-4 text-rose-400" />
                <span>Suspected Unauthorized Access Reported</span>
              </div>
              <p className="leading-relaxed">
                You indicated that the login from <strong>{session.location}</strong> (IP:{' '}
                <code>{session.ipAddress}</code>) on {session.formattedTime} was not you.
              </p>
            </div>

            <div className="space-y-2.5 text-xs text-slate-300">
              <span className="font-semibold text-white block">Immediate protective actions taken:</span>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-start space-x-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>
                    <strong>Revoke all other sessions:</strong> The unrecognized session and other device tokens will be invalidated immediately.
                  </span>
                </div>
                <div className="flex items-start space-x-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>
                    <strong>Session quarantine:</strong> Only this current workstation session will remain authenticated.
                  </span>
                </div>
                <div className="flex items-start space-x-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>
                    <strong>Incident Logged:</strong> Recorded as an alert in the PhishGuard SecOps threat feed.
                  </span>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                onClick={() => setShowCompromiseModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmCompromise}
                className="px-5 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 active:bg-rose-700 text-white text-xs font-semibold shadow-lg shadow-rose-600/30 cursor-pointer"
              >
                Lock Down Account &amp; Terminate Sessions
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Active Sessions Management Drawer/Modal */}
      {showAllSessionsModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="max-w-2xl w-full rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-5 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2.5">
                <Laptop className="w-5 h-5 text-indigo-400" />
                <h3 className="font-bold text-white text-base">Active &amp; Recent Device Sessions</h3>
              </div>
              <button
                onClick={() => setShowAllSessionsModal(false)}
                className="text-slate-400 hover:text-white cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-400">
              Manage all devices currently authenticated to your PhishGuard account. If you spot an unrecognized
              location or browser, terminate that session immediately.
            </p>

            <div className="space-y-3 max-h-[360px] overflow-y-auto pr-1">
              {user.activeSessions.map((s) => (
                <div
                  key={s.id}
                  className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs ${
                    s.isCurrentSession
                      ? 'bg-indigo-500/10 border-indigo-500/30'
                      : s.isSuspicious
                      ? 'bg-rose-500/10 border-rose-500/30'
                      : 'bg-slate-950 border-slate-800'
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-semibold text-white text-sm">{s.device}</span>
                      {s.isCurrentSession && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                          Current Device
                        </span>
                      )}
                      {s.isSuspicious && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                          Suspicious
                        </span>
                      )}
                    </div>
                    <div className="text-slate-400 flex flex-wrap items-center gap-2">
                      <span>{s.browser}</span>
                      <span>&bull;</span>
                      <span className="font-mono text-indigo-300">{s.ipAddress}</span>
                      <span>&bull;</span>
                      <span>{s.location}</span>
                    </div>
                    <div className="text-[11px] text-slate-500">
                      Accessed: {s.formattedTime}
                    </div>
                  </div>

                  {!s.isCurrentSession && (
                    <button
                      onClick={() => revokeSession(s.id)}
                      className="self-start sm:self-auto px-3 py-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-300 text-xs font-semibold cursor-pointer transition-colors"
                    >
                      Revoke
                    </button>
                  )}
                </div>
              ))}
            </div>

            <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
              <button
                onClick={revokeAllOtherSessions}
                className="text-xs text-rose-400 hover:text-rose-300 font-semibold cursor-pointer"
              >
                Sign out of all other sessions
              </button>

              <button
                onClick={() => setShowAllSessionsModal(false)}
                className="px-5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium cursor-pointer"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
