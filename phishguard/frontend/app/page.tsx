'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  Search,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Layers,
  Sparkles,
  ArrowRight,
  Info,
} from 'lucide-react';

interface ScanResponse {
  risk_score: number;
  verdict: 'safe' | 'suspicious' | 'likely_phishing';
  reasons: string[];
  details: {
    rule_score: number;
    ml_probability: number;
    blocklist_hit: boolean;
    domain: string;
    domain_age_days: number;
  };
}

export default function HomePage() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);

  const sampleUrls = [
    { label: 'Fake PayPal (Phishing)', url: 'https://paypal-security-update.com/login?token=8923a' },
    { label: 'Raw IP Bank Spoof', url: 'http://192.168.1.104/secure-bank-login' },
    { label: 'Legitimate Domain', url: 'https://google.com/search?q=cybersecurity' },
  ];

  const handleScan = async (targetUrl?: string) => {
    const toScan = (targetUrl || url).trim();
    if (!toScan) {
      setError('Please provide a URL to check.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/analyze_url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: toScan }),
      });

      if (!res.ok) {
        throw new Error('Analysis request failed');
      }

      const data = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'An error occurred while scanning.');
    } finally {
      setLoading(false);
    }
  };

  const getVerdictBadge = (verdict: string) => {
    if (verdict === 'likely_phishing') {
      return (
        <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-rose-500/15 border border-rose-500/30 text-rose-400 font-semibold text-xs">
          <ShieldX className="w-3.5 h-3.5" />
          <span>Likely Phishing (High Risk)</span>
        </span>
      );
    }
    if (verdict === 'suspicious') {
      return (
        <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-amber-500/15 border border-amber-500/30 text-amber-400 font-semibold text-xs">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Suspicious Link</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 font-semibold text-xs">
        <ShieldCheck className="w-3.5 h-3.5" />
        <span>Safe / Clean</span>
      </span>
    );
  };

  return (
    <div className="space-y-8">
      {/* Hero */}
      <div className="rounded-2xl bg-gradient-to-b from-slate-900 via-slate-900/60 to-slate-950 border border-slate-800 p-8 sm:p-12 shadow-xl">
        <div className="max-w-3xl space-y-4">
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-medium">
            <Sparkles className="w-3.5 h-3.5" />
            <span>Layered Detection: Rules + Blocklists + Machine Learning</span>
          </div>
          <h1 className="text-4xl font-extrabold text-white tracking-tight leading-tight">
            Check if a link is <span className="text-rose-400">phishing</span>.
          </h1>
          <p className="text-slate-300 text-base">
            Paste any suspicious URL to receive a unified risk score, heuristic explanations,
            and machine-learning threat classification.
          </p>

          {/* Form */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleScan();
            }}
            className="pt-2"
          >
            <div className="flex items-center rounded-xl bg-slate-950 border border-slate-700 overflow-hidden focus-within:border-indigo-500 p-1.5 shadow-lg">
              <Search className="w-5 h-5 text-slate-500 ml-3" />
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com/login"
                className="w-full bg-transparent px-3 py-2.5 text-white placeholder-slate-500 text-sm focus:outline-none"
              />
              <button
                type="submit"
                disabled={loading}
                className="px-6 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-sm transition-all shadow-md shadow-indigo-600/30 disabled:opacity-50 cursor-pointer"
              >
                {loading ? 'Checking...' : 'Check'}
              </button>
            </div>
            {error && <p className="text-rose-400 text-xs mt-2">{error}</p>}
          </form>

          {/* Presets */}
          <div className="flex flex-wrap items-center gap-2 pt-2">
            <span className="text-xs text-slate-400">Try demo URLs:</span>
            {sampleUrls.map((s, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setUrl(s.url);
                  handleScan(s.url);
                }}
                className="text-xs px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:text-white border border-slate-700"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Result Card */}
      {result && (
        <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 sm:p-8 space-y-6 shadow-2xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <span className="text-xs text-slate-400 block mb-1">Target URL</span>
              <p className="font-mono text-sm text-slate-200 break-all">{url}</p>
            </div>
            <div>{getVerdictBadge(result.verdict)}</div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-center">
              <span className="text-xs text-slate-400 block uppercase font-medium">Risk Score</span>
              <span
                className={`text-4xl font-extrabold ${
                  result.risk_score >= 70
                    ? 'text-rose-400'
                    : result.risk_score >= 40
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}
              >
                {result.risk_score}
                <span className="text-xs text-slate-500 font-normal">/100</span>
              </span>
            </div>

            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-center">
              <span className="text-xs text-slate-400 block uppercase font-medium">ML Probability</span>
              <span className="text-2xl font-bold font-mono text-indigo-300">
                {(result.details.ml_probability * 100).toFixed(0)}%
              </span>
            </div>

            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-center">
              <span className="text-xs text-slate-400 block uppercase font-medium">Rule Score</span>
              <span className="text-2xl font-bold font-mono text-amber-300">
                {result.details.rule_score}/100
              </span>
            </div>

            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-center">
              <span className="text-xs text-slate-400 block uppercase font-medium">Blocklist Hit</span>
              <span
                className={`text-2xl font-bold font-mono ${
                  result.details.blocklist_hit ? 'text-rose-400' : 'text-emerald-400'
                }`}
              >
                {result.details.blocklist_hit ? 'YES' : 'NO'}
              </span>
            </div>
          </div>

          {/* Reasons */}
          <div className="space-y-3">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Identified Reasons &amp; Signals ({result.reasons.length})
            </h2>
            <div className="space-y-2">
              {result.reasons.map((reason, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs sm:text-sm text-slate-300 flex items-start space-x-2"
                >
                  <Info className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
                  <span>{reason}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Quick Links Section */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4">
        <Link
          href="/email-checker"
          className="p-5 rounded-xl bg-slate-900 border border-slate-800 hover:border-indigo-500/50 transition-all group"
        >
          <h3 className="font-semibold text-white text-sm group-hover:text-indigo-300 flex items-center justify-between">
            <span>Email Phishing Checker</span>
            <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-indigo-400" />
          </h3>
          <p className="text-xs text-slate-400 mt-2">
            Analyze suspicious email subjects and body text for psychological urgency triggers.
          </p>
        </Link>

        <Link
          href="/report"
          className="p-5 rounded-xl bg-slate-900 border border-slate-800 hover:border-indigo-500/50 transition-all group"
        >
          <h3 className="font-semibold text-white text-sm group-hover:text-indigo-300 flex items-center justify-between">
            <span>Report Suspicious Content</span>
            <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-indigo-400" />
          </h3>
          <p className="text-xs text-slate-400 mt-2">
            Submit malicious links or lures to contribute to community threat intelligence.
          </p>
        </Link>

        <Link
          href="/learn"
          className="p-5 rounded-xl bg-slate-900 border border-slate-800 hover:border-indigo-500/50 transition-all group"
        >
          <h3 className="font-semibold text-white text-sm group-hover:text-indigo-300 flex items-center justify-between">
            <span>Phishing Defense Guide</span>
            <ArrowRight className="w-4 h-4 text-slate-500 group-hover:text-indigo-400" />
          </h3>
          <p className="text-xs text-slate-400 mt-2">
            Understand how lookalike domains and email spoofing operate, with safety best practices.
          </p>
        </Link>
      </div>
    </div>
  );
}
