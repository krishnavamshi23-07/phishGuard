import React, { useState } from 'react';
import {
  Mail,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  AlertTriangle,
  CheckCircle2,
  Lock,
  ExternalLink,
  Sparkles,
  Info,
  ChevronRight,
  LifeBuoy,
} from 'lucide-react';
import type { EmailScanResult } from '../services/antiPhishingEngine';
import { analyzeEmailContent } from '../services/antiPhishingEngine';

export const EmailChecker: React.FC = () => {
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<EmailScanResult | null>(null);

  const sampleEmails = [
    {
      title: 'Urgent Account Suspension (High Risk)',
      subject: 'Urgent: Your Chase Bank Account Will Be Suspended Within 24 Hours',
      body: 'Dear customer,\n\nWe detected unauthorized transaction attempts on your account. To prevent immediate suspension and penalties, you must verify your identity immediately.\n\nPlease confirm your password, social security number (SSN), and update your billing information here: http://secure-chase-auth-login.xyz/verify\n\nFailure to respond within 24 hours will result in permanent account termination.\n\nSincerely,\nSecurity Fraud Department',
    },
    {
      title: 'CEO Wire Transfer / Gift Card Scam (High Risk)',
      subject: 'Confidential Request: Urgent assistance needed today',
      body: 'Hello,\n\nAre you available right now? I am currently stuck in a board meeting and cannot take calls. I need you to execute a confidential wire transfer for our vendor or purchase 5 Apple gift card vouchers for our client incentive program immediately.\n\nKindly transfer the funds and email me the confirmation numbers right away.\n\nThanks,\nChief Executive Officer',
    },
    {
      title: 'Legitimate Calendar Meeting (Safe)',
      subject: 'Quarterly Security Architecture Sync - Thursday 2:00 PM',
      body: 'Hi Alex,\n\nHope your week is going well! Attached is the agenda for our upcoming quarterly security review meeting on Thursday at 2:00 PM. We will go over our firewall updates and multi-factor authentication enrollment statistics.\n\nLet me know if you would like to add any items to the slide deck before Wednesday.\n\nBest regards,\nSarah Miller\nLead SecOps Engineer',
    },
  ];

  const handleScan = async (sampleSub?: string, sampleBody?: string) => {
    const curSub = sampleSub !== undefined ? sampleSub : subject;
    const curBody = sampleBody !== undefined ? sampleBody : body;

    if (!curSub.trim() && !curBody.trim()) {
      setError('Please provide an email subject or body text to analyze.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/analyze_email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject: curSub, body: curBody }),
      });

      if (res.ok) {
        const data = await res.json();
        setResult(data);
      } else {
        throw new Error('API request failed');
      }
    } catch {
      // Local fallback
      const clientResult = analyzeEmailContent(curSub, curBody);
      setResult(clientResult);
    } finally {
      setLoading(false);
    }
  };

  const getLikelihoodBadge = (likelihood: EmailScanResult['phishing_likelihood']) => {
    switch (likelihood) {
      case 'high':
        return (
          <div className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-full bg-rose-500/15 border border-rose-500/30 text-rose-400 font-semibold text-sm">
            <ShieldX className="w-4 h-4 text-rose-400" />
            <span>High Phishing Likelihood</span>
          </div>
        );
      case 'medium':
        return (
          <div className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-full bg-amber-500/15 border border-amber-500/30 text-amber-400 font-semibold text-sm">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            <span>Medium Suspicion</span>
          </div>
        );
      case 'low':
      default:
        return (
          <div className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-semibold text-sm">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Low Risk / Likely Benign</span>
          </div>
        );
    }
  };

  return (
    <div className="space-y-8">
      {/* Header Banner */}
      <div className="rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950 border border-slate-800 p-6 sm:p-8">
        <div className="flex items-center space-x-2 text-indigo-400 text-xs font-semibold uppercase tracking-wider mb-2">
          <Mail className="w-4 h-4" />
          <span>Email Threat Inspection</span>
        </div>
        <h1 className="text-3xl font-extrabold text-white tracking-tight">
          Analyze suspicious emails for social engineering cues
        </h1>
        <p className="mt-2 text-slate-300 text-sm max-w-2xl">
          Paste an email subject and body to uncover deceptive psychological pressure, artificial urgency,
          credential harvesting lures, and spoofed authority signatures.
        </p>

        {/* Sample Templates */}
        <div className="mt-4 pt-4 border-t border-slate-800 flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-400 font-medium">Quick load test email:</span>
          {sampleEmails.map((sample, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => {
                setSubject(sample.subject);
                setBody(sample.body);
                handleScan(sample.subject, sample.body);
              }}
              className="text-xs px-3 py-1 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white transition-colors cursor-pointer"
            >
              {sample.title}
            </button>
          ))}
        </div>
      </div>

      {/* Main Analysis Form */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        <div className="lg:col-span-7 space-y-4">
          <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wide mb-1.5">
                Email Subject
              </label>
              <input
                type="text"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="e.g. Urgent: Account Verification Required Immediately"
                className="w-full px-4 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-white placeholder-slate-500 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wide mb-1.5">
                Email Body Content
              </label>
              <textarea
                rows={9}
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder="Paste the full body text of the email here..."
                className="w-full p-4 rounded-lg bg-slate-950 border border-slate-700 text-white placeholder-slate-500 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 font-mono text-xs leading-relaxed"
              />
            </div>

            {error && (
              <p className="text-xs text-rose-400 flex items-center space-x-1.5">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>{error}</span>
              </p>
            )}

            <div className="flex items-center justify-between pt-2">
              <button
                type="button"
                onClick={() => {
                  setSubject('');
                  setBody('');
                  setResult(null);
                }}
                className="text-xs text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                Clear fields
              </button>
              <button
                type="button"
                onClick={() => handleScan()}
                disabled={loading}
                className="px-6 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-sm transition-all shadow-md shadow-indigo-600/30 disabled:opacity-50 flex items-center space-x-2 cursor-pointer"
              >
                {loading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <span>Analyze Email</span>
                    <ChevronRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Right Column: Scan Result & Safety Tips */}
        <div className="lg:col-span-5 space-y-6">
          {result ? (
            <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-6 shadow-xl">
              {/* Top Verdict Header */}
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                {getLikelihoodBadge(result.phishing_likelihood)}
                <div className="text-right">
                  <div className="text-2xl font-black font-mono text-white">
                    {result.score}
                    <span className="text-xs text-slate-400 font-normal"> / 100</span>
                  </div>
                  <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
                    Threat Score
                  </span>
                </div>
              </div>

              {/* Patterns Detected */}
              <div>
                <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
                  Patterns Detected ({result.patterns_found.length})
                </h2>
                <div className="space-y-2">
                  {result.patterns_found.map((pattern, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 flex items-start space-x-2.5 text-xs text-slate-200"
                    >
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <span>{pattern}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Detailed Breakdown */}
              {result.detailed_findings && result.detailed_findings.length > 0 && (
                <div>
                  <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Behavioral Triggers
                  </h2>
                  <div className="space-y-2">
                    {result.detailed_findings.map((f, i) => (
                      <div
                        key={i}
                        className="p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 text-xs"
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-semibold text-slate-300">{f.category}</span>
                          <span
                            className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                              f.severity === 'high'
                                ? 'bg-rose-500/20 text-rose-300'
                                : 'bg-amber-500/20 text-amber-300'
                            }`}
                          >
                            {f.severity.toUpperCase()}
                          </span>
                        </div>
                        <p className="text-slate-400 text-[11px]">{f.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommended Action Checklist */}
              <div className="p-4 rounded-xl bg-slate-950/90 border border-indigo-500/20 space-y-2">
                <div className="flex items-center space-x-2 text-indigo-400 text-xs font-semibold">
                  <LifeBuoy className="w-4 h-4" />
                  <span>Recommended Action Plan</span>
                </div>
                <ul className="text-xs text-slate-300 space-y-1.5 pl-1">
                  {result.phishing_likelihood === 'high' ? (
                    <>
                      <li className="flex items-start space-x-2 text-rose-300">
                        <span>•</span>
                        <strong>Do NOT click any links</strong> or open attachments in this message.
                      </li>
                      <li className="flex items-start space-x-2">
                        <span>•</span>
                        Never provide passwords, 2FA codes, or SSN via email.
                      </li>
                      <li className="flex items-start space-x-2">
                        <span>•</span>
                        Report to your organization's IT/SecOps team immediately.
                      </li>
                      <li className="flex items-start space-x-2">
                        <span>•</span>
                        Verify directly via the official website by typing the known URL manually.
                      </li>
                    </>
                  ) : result.phishing_likelihood === 'medium' ? (
                    <>
                      <li className="flex items-start space-x-2">
                        <span>•</span>
                        Inspect the sender's full email address and domain closely.
                      </li>
                      <li className="flex items-start space-x-2">
                        <span>•</span>
                        Hover over any links to verify the actual destination domain.
                      </li>
                      <li className="flex items-start space-x-2">
                        <span>•</span>
                        Contact the sender through an alternate, verified channel.
                      </li>
                    </>
                  ) : (
                    <>
                      <li className="flex items-start space-x-2 text-emerald-300">
                        <span>•</span>
                        No high-pressure phishing patterns detected.
                      </li>
                      <li className="flex items-start space-x-2">
                        <span>•</span>
                        Always practice standard hygiene before downloading unexpected files.
                      </li>
                    </>
                  )}
                </ul>
              </div>
            </div>
          ) : (
            /* Empty State Guidance */
            <div className="rounded-xl bg-slate-900/60 border border-slate-800 p-6 space-y-4">
              <div className="flex items-center space-x-2 text-indigo-400 font-semibold text-sm">
                <Info className="w-4 h-4" />
                <span>What our email analyzer looks for:</span>
              </div>
              <div className="space-y-3 text-xs text-slate-300">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="font-semibold text-slate-200 block mb-1">
                    1. False Urgency &amp; Threats
                  </span>
                  Phrases demanding immediate action within 24 hours to prevent account suspension
                  or legal penalty.
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="font-semibold text-slate-200 block mb-1">
                    2. Credential Harvesting Lures
                  </span>
                  Requests asking you to "confirm your password", "verify banking details", or enter
                  sensitive secrets.
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="font-semibold text-slate-200 block mb-1">
                    3. Impersonal Salutations
                  </span>
                  Generic greetings like "Dear Customer" or "Dear User" instead of your registered name.
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="font-semibold text-slate-200 block mb-1">
                    4. Financial Wire Fraud
                  </span>
                  Executive impersonation asking for secret wire transfers, vendor payments, or gift cards.
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
