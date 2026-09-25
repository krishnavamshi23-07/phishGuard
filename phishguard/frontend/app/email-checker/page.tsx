'use client';

import React, { useState } from 'react';
import { Mail, AlertTriangle, ShieldCheck, ShieldAlert, ShieldX, LifeBuoy } from 'lucide-react';

interface EmailScanResult {
  phishing_likelihood: 'low' | 'medium' | 'high';
  score: number;
  patterns_found: string[];
}

export default function EmailCheckerPage() {
  const [subject, setSubject] = useState('');
  const [body, setBody] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<EmailScanResult | null>(null);

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!subject.trim() && !body.trim()) {
      setError('Please provide an email subject or body text.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/analyze_email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subject, body }),
      });

      if (!res.ok) {
        throw new Error('Analysis failed');
      }

      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'An error occurred during analysis.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-extrabold text-white">Email Phishing Checker</h1>
        <p className="text-slate-400 text-sm mt-1">
          Inspect email content for social engineering tricks, credential harvesting, and false urgency.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Form */}
        <div className="lg:col-span-7">
          <form onSubmit={handleAnalyze} className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wide mb-1.5">
                Subject
              </label>
              <input
                type="text"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                placeholder="Urgent: Verify your account immediately"
                className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wide mb-1.5">
                Email Body
              </label>
              <textarea
                rows={8}
                value={body}
                onChange={(e) => setBody(e.target.value)}
                placeholder="Dear customer, your account will be suspended within 24 hours..."
                className="w-full p-3 rounded-lg bg-slate-950 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500 font-mono text-xs"
              />
            </div>

            {error && <p className="text-xs text-rose-400">{error}</p>}

            <button
              type="submit"
              disabled={loading}
              className="px-6 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-sm transition-all shadow-md shadow-indigo-600/30 disabled:opacity-50 cursor-pointer"
            >
              {loading ? 'Analyzing...' : 'Analyze Email'}
            </button>
          </form>
        </div>

        {/* Results */}
        <div className="lg:col-span-5">
          {result ? (
            <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-5">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="text-xs uppercase font-semibold text-slate-400">Likelihood</span>
                <span
                  className={`text-sm font-bold uppercase px-3 py-0.5 rounded-full ${
                    result.phishing_likelihood === 'high'
                      ? 'bg-rose-500/20 text-rose-400'
                      : result.phishing_likelihood === 'medium'
                      ? 'bg-amber-500/20 text-amber-400'
                      : 'bg-emerald-500/20 text-emerald-400'
                  }`}
                >
                  {result.phishing_likelihood}
                </span>
              </div>

              <div>
                <span className="text-xs text-slate-400 uppercase font-medium">Risk Score</span>
                <div className="text-3xl font-extrabold text-white mt-1">
                  {result.score}
                  <span className="text-xs text-slate-500 font-normal"> / 100</span>
                </div>
              </div>

              <div>
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Patterns Detected
                </h3>
                <div className="space-y-2">
                  {result.patterns_found.map((p, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 flex items-start space-x-2"
                    >
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                      <span>{p}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Safety tips */}
              <div className="p-4 rounded-lg bg-slate-950 border border-indigo-500/20 text-xs text-slate-300 space-y-1.5">
                <div className="flex items-center space-x-1.5 text-indigo-400 font-semibold mb-1">
                  <LifeBuoy className="w-4 h-4" />
                  <span>Safety Tips:</span>
                </div>
                <p>&bull; Never send passwords, SSN, or card details over email.</p>
                <p>&bull; Do not click links inside suspicious or unverified emails.</p>
                <p>&bull; Always type the known official web address directly in your browser.</p>
              </div>
            </div>
          ) : (
            <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-400 space-y-2">
              <p className="font-semibold text-slate-300">How Email Analysis Works:</p>
              <p>Our rule-based heuristics scan for high-pressure language, generic greetings ("Dear customer"), requests for credentials, and excessive URL redirections.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
