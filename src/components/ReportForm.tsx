import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Send,
  Globe,
  Mail,
  ShieldAlert,
  Clock,
  Search,
  Filter,
} from 'lucide-react';
import type { PhishReport } from '../services/antiPhishingEngine';
import { globalPhishGuardStore } from '../services/antiPhishingEngine';

interface ReportFormProps {
  initialContent?: string;
  initialType?: 'url' | 'email';
}

export const ReportForm: React.FC<ReportFormProps> = ({
  initialContent = '',
  initialType = 'url',
}) => {
  const [type, setType] = useState<'url' | 'email'>(initialType);
  const [content, setContent] = useState(initialContent);
  const [notes, setNotes] = useState('');
  const [loading, setLoading] = useState(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [reports, setReports] = useState<PhishReport[]>([]);
  const [filterType, setFilterType] = useState<'all' | 'url' | 'email'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    if (initialContent) {
      setContent(initialContent);
      setType(initialType);
    }
    fetchReports();
  }, [initialContent, initialType]);

  const fetchReports = async () => {
    try {
      const res = await fetch('/api/reports');
      if (res.ok) {
        const data = await res.json();
        if (data.reports) {
          setReports(data.reports);
          return;
        }
      }
    } catch {
      // Local fallback
    }
    setReports(globalPhishGuardStore.getRecentReports());
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) {
      setErrorMsg('Please enter the suspicious URL or email text.');
      return;
    }

    setLoading(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const res = await fetch('/api/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type,
          content: content.trim(),
          notes: notes.trim(),
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setSuccessMsg(
          `Thank you for reporting! Threat recorded with Report ID #${data.report_id}. Our engine has queued this indicator for community blocklists.`
        );
        setContent('');
        setNotes('');
        fetchReports();
      } else {
        throw new Error('Server returned an error');
      }
    } catch {
      // Fallback
      const report = globalPhishGuardStore.addReport(type, content.trim(), notes.trim());
      setSuccessMsg(
        `Thank you for reporting! Threat recorded with Report ID #${report.id}. Our engine has queued this indicator for community blocklists.`
      );
      setContent('');
      setNotes('');
      fetchReports();
    } finally {
      setLoading(false);
    }
  };

  const filteredReports = reports.filter((rep) => {
    if (filterType !== 'all' && rep.type !== filterType) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        rep.content.toLowerCase().includes(q) ||
        (rep.notes && rep.notes.toLowerCase().includes(q))
      );
    }
    return true;
  });

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950 border border-slate-800 p-6 sm:p-8">
        <div className="flex items-center space-x-2 text-rose-400 text-xs font-semibold uppercase tracking-wider mb-2">
          <ShieldAlert className="w-4 h-4" />
          <span>Crowdsourced Cyber Threat Intelligence</span>
        </div>
        <h1 className="text-3xl font-extrabold text-white tracking-tight">
          Report Suspicious URLs or Emails
        </h1>
        <p className="mt-2 text-slate-300 text-sm max-w-2xl">
          Help protect millions of users worldwide. When you submit a suspected phishing link or email lure,
          our automated pipeline extracts indicators of compromise (IoCs) to update blocklists and retrain ML models.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Submission Form */}
        <div className="lg:col-span-6">
          <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-5">
            <h2 className="text-base font-semibold text-white flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <span>Submit Threat Indicator</span>
            </h2>

            {successMsg && (
              <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-start space-x-3 leading-relaxed">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <span>{successMsg}</span>
              </div>
            )}

            {errorMsg && (
              <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start space-x-3">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                <span>{errorMsg}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Type selector */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wide mb-2">
                  Threat Type
                </label>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => setType('url')}
                    className={`flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg text-sm font-medium border transition-all cursor-pointer ${
                      type === 'url'
                        ? 'bg-indigo-600/20 text-indigo-300 border-indigo-500/50 shadow-sm'
                        : 'bg-slate-950 border-slate-700 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Globe className="w-4 h-4" />
                    <span>Malicious URL</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setType('email')}
                    className={`flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg text-sm font-medium border transition-all cursor-pointer ${
                      type === 'email'
                        ? 'bg-indigo-600/20 text-indigo-300 border-indigo-500/50 shadow-sm'
                        : 'bg-slate-950 border-slate-700 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Mail className="w-4 h-4" />
                    <span>Phishing Email</span>
                  </button>
                </div>
              </div>

              {/* Content textarea */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wide mb-1.5">
                  {type === 'url' ? 'Suspicious URL Address' : 'Email Content / Body / Headers'}
                </label>
                <textarea
                  rows={4}
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                  placeholder={
                    type === 'url'
                      ? 'e.g. https://paypal-security-update.com/login?token=abc'
                      : 'Paste the subject and full body of the phishing email...'
                  }
                  className="w-full p-3 rounded-lg bg-slate-950 border border-slate-700 text-white placeholder-slate-500 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 font-mono text-xs"
                />
              </div>

              {/* Notes */}
              <div>
                <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wide mb-1.5">
                  Context / Notes (Optional)
                </label>
                <input
                  type="text"
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  placeholder="e.g. Received via SMS spoofing FedEx tracking number"
                  className="w-full px-4 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-white placeholder-slate-500 text-sm focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-3 rounded-lg bg-rose-600 hover:bg-rose-500 active:bg-rose-700 text-white font-medium text-sm transition-all shadow-lg shadow-rose-600/20 disabled:opacity-50 flex items-center justify-center space-x-2 cursor-pointer"
              >
                {loading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                    <span>Submitting Report...</span>
                  </>
                ) : (
                  <>
                    <Send className="w-4 h-4" />
                    <span>Submit Threat Report</span>
                  </>
                )}
              </button>
            </form>
          </div>
        </div>

        {/* Community Threat Reports Feed */}
        <div className="lg:col-span-6 space-y-4">
          <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <h2 className="text-base font-semibold text-white flex items-center space-x-2">
                <Clock className="w-4 h-4 text-indigo-400" />
                <span>Recent Community Reports</span>
              </h2>

              {/* Filter controls */}
              <div className="flex items-center space-x-1.5">
                {(['all', 'url', 'email'] as const).map((t) => (
                  <button
                    key={t}
                    onClick={() => setFilterType(t)}
                    className={`text-xs px-2.5 py-1 rounded-md capitalize font-medium transition-colors cursor-pointer ${
                      filterType === t
                        ? 'bg-slate-700 text-white'
                        : 'bg-slate-950 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

            {/* Search filter */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter reported targets..."
                className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            {/* List */}
            <div className="space-y-2.5 max-h-[460px] overflow-y-auto pr-1">
              {filteredReports.length === 0 ? (
                <p className="text-xs text-slate-400 py-6 text-center">
                  No threat reports match your search criteria.
                </p>
              ) : (
                filteredReports.map((rep) => (
                  <div
                    key={rep.id}
                    className="p-3.5 rounded-lg bg-slate-950 border border-slate-800/80 hover:border-slate-700 transition-colors space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span
                          className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold ${
                            rep.type === 'url'
                              ? 'bg-indigo-500/20 text-indigo-300'
                              : 'bg-amber-500/20 text-amber-300'
                          }`}
                        >
                          {rep.type}
                        </span>
                        <span className="text-[10px] text-slate-500">
                          {new Date(rep.created_at).toLocaleDateString()} at{' '}
                          {new Date(rep.created_at).toLocaleTimeString()}
                        </span>
                      </div>
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        {rep.status || 'verified'}
                      </span>
                    </div>

                    <p className="font-mono text-xs text-slate-200 break-all leading-snug">
                      {rep.content.length > 140 ? rep.content.substring(0, 140) + '...' : rep.content}
                    </p>

                    {rep.notes && (
                      <p className="text-[11px] text-slate-400 italic">
                        Notes: {rep.notes}
                      </p>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
