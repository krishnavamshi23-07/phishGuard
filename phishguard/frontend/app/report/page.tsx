'use client';

import React, { useState } from 'react';
import { AlertTriangle, CheckCircle2, Globe, Mail, Send } from 'lucide-react';

export default function ReportPage() {
  const [type, setType] = useState<'url' | 'email'>('url');
  const [content, setContent] = useState('');
  const [notes, setNotes] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) {
      setError('Please provide the content to report.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, content, notes }),
      });

      if (!res.ok) {
        throw new Error('Failed to submit threat report.');
      }

      setSuccess(true);
      setContent('');
      setNotes('');
    } catch (err: any) {
      setError(err.message || 'An error occurred.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h1 className="text-3xl font-extrabold text-white">Report Phishing Threat</h1>
        <p className="text-slate-400 text-sm mt-1">
          Submit malicious websites or deceptive emails to contribute to our threat intelligence feeds.
        </p>
      </div>

      <div className="p-6 sm:p-8 rounded-xl bg-slate-900 border border-slate-800 space-y-5">
        {success && (
          <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-start space-x-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
            <span>Thank you! Your threat report has been recorded and queued for blocklist inspection.</span>
          </div>
        )}

        {error && (
          <div className="p-4 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wide mb-2">
              Threat Category
            </label>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => setType('url')}
                className={`py-2 px-4 rounded-lg text-sm font-medium border flex items-center justify-center space-x-2 ${
                  type === 'url'
                    ? 'bg-indigo-600/20 text-indigo-300 border-indigo-500/40'
                    : 'bg-slate-950 border-slate-800 text-slate-400'
                }`}
              >
                <Globe className="w-4 h-4" />
                <span>URL Address</span>
              </button>
              <button
                type="button"
                onClick={() => setType('email')}
                className={`py-2 px-4 rounded-lg text-sm font-medium border flex items-center justify-center space-x-2 ${
                  type === 'email'
                    ? 'bg-indigo-600/20 text-indigo-300 border-indigo-500/40'
                    : 'bg-slate-950 border-slate-800 text-slate-400'
                }`}
              >
                <Mail className="w-4 h-4" />
                <span>Email Message</span>
              </button>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wide mb-1.5">
              Content
            </label>
            <textarea
              rows={4}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder={type === 'url' ? 'https://suspicious-login.com' : 'Paste suspicious email text...'}
              className="w-full p-3 rounded-lg bg-slate-950 border border-slate-700 text-sm text-white font-mono text-xs focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wide mb-1.5">
              Notes (Optional)
            </label>
            <input
              type="text"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="e.g. Looks like a fake bank login page asking for PIN"
              className="w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-sm text-white focus:outline-none focus:border-indigo-500"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-medium text-sm transition-all shadow-md shadow-rose-600/30 disabled:opacity-50 flex items-center justify-center space-x-2 cursor-pointer"
          >
            <Send className="w-4 h-4" />
            <span>{loading ? 'Submitting...' : 'Submit Report'}</span>
          </button>
        </form>
      </div>
    </div>
  );
}
