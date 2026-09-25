import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Search,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ArrowLeft,
  RotateCcw,
  Sparkles,
  Info,
  Globe,
  Database,
} from 'lucide-react';
import type { UrlScanResult } from '../services/antiPhishingEngine';
import { analyzeUrl } from '../services/antiPhishingEngine';
import { useAuth } from '../context/AuthContext';

export type PipelineStep = 'input' | 'layer1' | 'layer2' | 'layer3' | 'verdict';

interface UrlCheckerProps {
  onNavigateToReport?: (prefillUrl: string) => void;
  onOpenSecurityReview?: () => void;
}

export const UrlChecker: React.FC<UrlCheckerProps> = ({
  onNavigateToReport,
  onOpenSecurityReview,
}) => {
  const { user } = useAuth();
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanningStep, setScanningStep] = useState<number>(0);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<UrlScanResult | null>(null);
  const [currentStep, setCurrentStep] = useState<PipelineStep>('input');

  const sampleUrls = [
    { label: 'Fake PayPal (Phishing)', url: 'https://paypal-security-update.com/login?token=8923a' },
    { label: 'Raw IP Bank Spoof', url: 'http://192.168.1.104/secure-bank-login' },
    { label: 'Shortened Link', url: 'https://bit.ly/secure-login-39x' },
    { label: 'Legitimate Domain', url: 'https://google.com/search?q=cybersecurity' },
  ];

  const handleStartInspection = async (targetUrl?: string) => {
    const urlToTest = (targetUrl !== undefined ? targetUrl : urlInput).trim();
    if (!urlToTest) {
      setError('Please enter a website URL to begin inspection.');
      return;
    }

    setLoading(true);
    setError(null);
    setScanningStep(1);

    try {
      await new Promise((r) => setTimeout(r, 200));
      setScanningStep(2);
      await new Promise((r) => setTimeout(r, 200));
      setScanningStep(3);

      let scanData: UrlScanResult;
      const response = await fetch('/api/analyze_url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: urlToTest }),
      });

      if (response.ok) {
        scanData = await response.json();
      } else {
        scanData = await analyzeUrl(urlToTest);
      }

      await new Promise((r) => setTimeout(r, 180));
      setScanningStep(4);

      setResult(scanData);
      setCurrentStep('layer1'); // Immediately guide into Layer 1
    } catch {
      try {
        const clientResult = await analyzeUrl(urlToTest);
        setResult(clientResult);
        setCurrentStep('layer1');
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : 'Invalid URL provided.');
      }
    } finally {
      setLoading(false);
      setScanningStep(0);
    }
  };

  const handleReset = () => {
    setResult(null);
    setUrlInput('');
    setCurrentStep('input');
    setError(null);
  };

  const getVerdictTheme = (verdict: UrlScanResult['verdict']) => {
    switch (verdict) {
      case 'likely_phishing':
        return {
          label: 'Likely Phishing (High Threat)',
          badgeClass: 'text-rose-400 bg-rose-500/15 border-rose-500/30',
          textClass: 'text-rose-400',
          bgClass: 'bg-rose-950/20 border-rose-500/40',
          icon: ShieldX,
        };
      case 'suspicious':
        return {
          label: 'Suspicious Activity Detected',
          badgeClass: 'text-amber-400 bg-amber-500/15 border-amber-500/30',
          textClass: 'text-amber-400',
          bgClass: 'bg-amber-950/20 border-amber-500/40',
          icon: ShieldAlert,
        };
      case 'safe':
      default:
        return {
          label: 'Safe & Legitimate',
          badgeClass: 'text-emerald-400 bg-emerald-500/15 border-emerald-500/30',
          textClass: 'text-emerald-400',
          bgClass: 'bg-emerald-950/20 border-emerald-500/40',
          icon: ShieldCheck,
        };
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Subtle Account Security Notice if review pending */}
      {user && !user.lastLoginSession.reviewed && (
        <div className="rounded-xl bg-slate-900/80 border border-indigo-500/25 px-4 py-2.5 flex items-center justify-between text-xs text-slate-300 shadow-sm">
          <div className="flex items-center space-x-2.5">
            <span className="w-2 h-2 rounded-full bg-indigo-400 animate-pulse shrink-0" />
            <span>
              Last login from <strong className="text-white">{user.lastLoginSession.location}</strong> ({user.lastLoginSession.formattedTime}).
            </span>
          </div>
          {onOpenSecurityReview && (
            <button
              onClick={onOpenSecurityReview}
              className="text-indigo-400 hover:text-indigo-300 font-semibold px-2.5 py-1 rounded bg-indigo-500/10 hover:bg-indigo-500/20 border border-indigo-500/30 transition-colors cursor-pointer shrink-0"
            >
              Review Access
            </button>
          )}
        </div>
      )}

      {/* Stepper Navigation Bar (Displayed during inspection) */}
      {result && currentStep !== 'input' && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-3 sm:p-4 shadow-xl">
          <div className="flex items-center justify-between gap-1 overflow-x-auto">
            <button
              onClick={() => setCurrentStep('layer1')}
              className={`flex-1 min-w-[130px] p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                currentStep === 'layer1'
                  ? 'bg-indigo-600/25 border-indigo-500 text-white ring-1 ring-indigo-500/40 shadow-sm'
                  : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              <div className="text-[10px] font-mono uppercase font-bold text-indigo-400 flex items-center justify-between">
                <span>Layer 1</span>
                <CheckCircle2 className="w-3 h-3 text-indigo-400" />
              </div>
              <div className="text-xs font-semibold truncate">Rules &amp; Syntax</div>
            </button>

            <button
              onClick={() => setCurrentStep('layer2')}
              className={`flex-1 min-w-[130px] p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                currentStep === 'layer2'
                  ? 'bg-blue-600/25 border-blue-500 text-white ring-1 ring-blue-500/40 shadow-sm'
                  : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              <div className="text-[10px] font-mono uppercase font-bold text-blue-400 flex items-center justify-between">
                <span>Layer 2</span>
                <CheckCircle2 className="w-3 h-3 text-blue-400" />
              </div>
              <div className="text-xs font-semibold truncate">Threat Feeds</div>
            </button>

            <button
              onClick={() => setCurrentStep('layer3')}
              className={`flex-1 min-w-[130px] p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                currentStep === 'layer3'
                  ? 'bg-emerald-600/25 border-emerald-500 text-white ring-1 ring-emerald-500/40 shadow-sm'
                  : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              <div className="text-[10px] font-mono uppercase font-bold text-emerald-400 flex items-center justify-between">
                <span>Layer 3</span>
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
              </div>
              <div className="text-xs font-semibold truncate">ML Classifier</div>
            </button>

            <button
              onClick={() => setCurrentStep('verdict')}
              className={`flex-1 min-w-[130px] p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                currentStep === 'verdict'
                  ? 'bg-purple-600/25 border-purple-500 text-white ring-1 ring-purple-500/40 shadow-sm'
                  : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              <div className="text-[10px] font-mono uppercase font-bold text-purple-400 flex items-center justify-between">
                <span>Verdict</span>
                <Sparkles className="w-3 h-3 text-purple-400" />
              </div>
              <div className="text-xs font-semibold truncate">Final Fusion</div>
            </button>
          </div>
        </div>
      )}

      {/* STEP 0: CLEAN LINK INTAKE SCREEN */}
      {currentStep === 'input' && (
        <div className="space-y-6 pt-4">
          <div className="text-center space-y-2 max-w-xl mx-auto">
            <div className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-semibold">
              <Sparkles className="w-3.5 h-3.5" />
              <span>Multi-Layer Anti-Phishing Pipeline</span>
            </div>
            <h1 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
              Inspect any URL layer-by-layer
            </h1>
            <p className="text-sm text-slate-400">
              Submit a suspicious link to evaluate it step-by-step through heuristic rules, threat databases, and machine learning.
            </p>
          </div>

          <div className="rounded-2xl bg-slate-900 border border-slate-800 p-5 sm:p-6 shadow-2xl space-y-4">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleStartInspection();
              }}
              className="relative flex flex-col sm:flex-row items-stretch sm:items-center bg-slate-950 border border-slate-700/80 rounded-xl overflow-hidden focus-within:border-indigo-500 focus-within:ring-2 focus-within:ring-indigo-500/20 transition-all p-1 gap-2"
            >
              <div className="hidden sm:flex pl-3.5 text-slate-400">
                <Search className="w-5 h-5" />
              </div>
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="Enter URL to inspect (e.g. https://paypal-security-update.com)..."
                className="w-full py-3 px-3.5 bg-transparent text-white placeholder-slate-500 text-sm focus:outline-none"
              />
              <button
                type="submit"
                disabled={loading}
                className="px-6 py-3 rounded-lg bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 text-white font-medium text-sm transition-all shadow-md shadow-indigo-600/30 disabled:opacity-50 flex items-center justify-center space-x-2 shrink-0 cursor-pointer"
              >
                {loading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                    <span>Inspecting Layer {scanningStep}...</span>
                  </>
                ) : (
                  <>
                    <span>Start Inspection</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            {error && (
              <p className="text-xs text-rose-400 flex items-center space-x-1.5 pl-1">
                <ShieldX className="w-4 h-4" />
                <span>{error}</span>
              </p>
            )}

            <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800/80">
              <span className="text-xs text-slate-400 font-medium">Quick test samples:</span>
              {sampleUrls.map((sample, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => {
                    setUrlInput(sample.url);
                    handleStartInspection(sample.url);
                  }}
                  className="text-xs px-2.5 py-1 rounded-md bg-slate-950 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white transition-colors cursor-pointer"
                >
                  {sample.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* STEP 1: LAYER 1 — RULE-BASED HEURISTICS */}
      {result && currentStep === 'layer1' && (
        <div className="rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl overflow-hidden space-y-6">
          <div className="p-6 border-b border-slate-800 bg-slate-950/60 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-mono uppercase font-bold px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  Layer 1 of 4
                </span>
                <span className="text-xs text-slate-400">Heuristics &amp; Syntax Engine</span>
              </div>
              <h2 className="text-xl font-bold text-white">Rule-Based Evaluation</h2>
              <p className="text-xs text-slate-400 font-mono truncate max-w-xl">
                Target: {result.url}
              </p>
            </div>

            <div className="text-right sm:border-l sm:border-slate-800 sm:pl-6 shrink-0">
              <div className="text-3xl font-black font-mono text-indigo-400">
                {result.details.rule_score}
                <span className="text-xs text-slate-500 font-normal"> / 100</span>
              </div>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
                Layer 1 Score
              </span>
            </div>
          </div>

          <div className="p-6 space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-500 uppercase tracking-wider text-[10px] block font-bold">
                  Domain Name
                </span>
                <span className="font-mono text-slate-200 font-semibold text-sm">
                  {result.details.domain}
                </span>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-500 uppercase tracking-wider text-[10px] block font-bold">
                  Domain Registration Age
                </span>
                <span className="font-mono text-slate-200 font-semibold text-sm">
                  {result.details.domain_age_days} days{' '}
                  <span className="text-slate-500 text-xs font-normal">
                    {result.details.domain_age_days < 30 ? '(Newly created)' : '(Established)'}
                  </span>
                </span>
              </div>
            </div>

            <div className="space-y-3">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider block">
                Heuristic Findings &amp; Red Flags
              </span>

              <div className="space-y-2">
                {result.reasons
                  .filter((r) => !r.includes('ML') && !r.includes('Safe Browsing') && !r.includes('PhishTank') && !r.includes('threat feed'))
                  .map((reason, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-xl bg-indigo-500/10 border border-indigo-500/25 text-xs text-indigo-200 flex items-start space-x-2.5"
                    >
                      <AlertTriangle className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
                      <span className="leading-relaxed">{reason}</span>
                    </div>
                  ))}

                {result.reasons.filter((r) => !r.includes('ML') && !r.includes('Safe Browsing') && !r.includes('PhishTank') && !r.includes('threat feed')).length === 0 && (
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs text-emerald-400 flex items-center space-x-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>No heuristic syntax red flags detected for this domain.</span>
                  </div>
                )}
              </div>
            </div>

            {/* Stepper Navigation Footer */}
            <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
              <button
                onClick={handleReset}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-medium transition-colors cursor-pointer flex items-center space-x-1.5"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Scan New Link</span>
              </button>

              <button
                onClick={() => setCurrentStep('layer2')}
                className="px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 text-white text-xs font-semibold shadow-md shadow-indigo-600/30 transition-all cursor-pointer flex items-center space-x-1.5"
              >
                <span>Next: Layer 2 (Threat Reputation)</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* STEP 2: LAYER 2 — THREAT REPUTATION & FEEDS */}
      {result && currentStep === 'layer2' && (
        <div className="rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl overflow-hidden space-y-6">
          <div className="p-6 border-b border-slate-800 bg-slate-950/60 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-mono uppercase font-bold px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
                  Layer 2 of 4
                </span>
                <span className="text-xs text-slate-400">Threat Feeds &amp; Blocklists</span>
              </div>
              <h2 className="text-xl font-bold text-white">Threat Reputation Intelligence</h2>
              <p className="text-xs text-slate-400 font-mono truncate max-w-xl">
                Target: {result.url}
              </p>
            </div>

            <div className="text-right sm:border-l sm:border-slate-800 sm:pl-6 shrink-0">
              <span
                className={`text-sm font-bold font-mono px-3 py-1 rounded-full border ${
                  result.details.blocklist_hit
                    ? 'text-rose-400 bg-rose-500/15 border-rose-500/30'
                    : 'text-emerald-400 bg-emerald-500/15 border-emerald-500/30'
                }`}
              >
                {result.details.blocklist_hit ? 'FLAGGED (+30)' : 'CLEAN (0)'}
              </span>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block mt-1">
                Database Status
              </span>
            </div>
          </div>

          <div className="p-6 space-y-5">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white text-xs">Google Safe Browsing v4</span>
                  <Database className="w-4 h-4 text-blue-400" />
                </div>
                <p className="text-xs text-slate-400">
                  {result.details.reputation_sources?.google_safe_browsing?.flagged
                    ? '⚠️ Identified as social engineering or credential harvesting host.'
                    : '✓ No matches found in global threat lists.'}
                </p>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white text-xs">PhishTank Community Feed</span>
                  <Globe className="w-4 h-4 text-blue-400" />
                </div>
                <p className="text-xs text-slate-400">
                  {result.details.reputation_sources?.phishtank?.flagged
                    ? '⚠️ Confirmed active phishing URL verified by security community.'
                    : '✓ Unlisted in verified phishing campaigns.'}
                </p>
              </div>
            </div>

            {/* Stepper Navigation Footer */}
            <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
              <button
                onClick={() => setCurrentStep('layer1')}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-medium transition-colors cursor-pointer flex items-center space-x-1.5"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Layer 1 (Rules)</span>
              </button>

              <button
                onClick={() => setCurrentStep('layer3')}
                className="px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 active:bg-blue-700 text-white text-xs font-semibold shadow-md shadow-blue-600/30 transition-all cursor-pointer flex items-center space-x-1.5"
              >
                <span>Next: Layer 3 (Machine Learning)</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* STEP 3: LAYER 3 — MACHINE LEARNING CLASSIFIER */}
      {result && currentStep === 'layer3' && (
        <div className="rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl overflow-hidden space-y-6">
          <div className="p-6 border-b border-slate-800 bg-slate-950/60 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-mono uppercase font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  Layer 3 of 4
                </span>
                <span className="text-xs text-slate-400">Lexical Random Forest Model</span>
              </div>
              <h2 className="text-xl font-bold text-white">Machine Learning Classification</h2>
              <p className="text-xs text-slate-400 font-mono truncate max-w-xl">
                Target: {result.url}
              </p>
            </div>

            <div className="text-right sm:border-l sm:border-slate-800 sm:pl-6 shrink-0">
              <div className="text-3xl font-black font-mono text-emerald-400">
                {(result.details.ml_probability * 100).toFixed(0)}%
              </div>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
                Phishing Probability
              </span>
            </div>
          </div>

          <div className="p-6 space-y-5">
            <div className="space-y-3">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider block">
                Lexical Feature Vector (Input to Random Forest)
              </span>

              {result.details.features && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase font-bold">URL Length</span>
                    <span className="font-mono text-slate-200 font-bold text-sm">
                      {result.details.features.url_length} chars
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase font-bold">Shannon Entropy</span>
                    <span className="font-mono text-slate-200 font-bold text-sm">
                      {result.details.features.entropy} bits
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase font-bold">Dot Count</span>
                    <span className="font-mono text-slate-200 font-bold text-sm">
                      {result.details.features.num_dots}
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                    <span className="text-slate-500 block text-[10px] uppercase font-bold">Raw IP Host</span>
                    <span
                      className={`font-mono font-bold text-sm ${
                        result.details.features.has_ip ? 'text-rose-400' : 'text-emerald-400'
                      }`}
                    >
                      {result.details.features.has_ip ? 'YES (High Risk)' : 'NO (Normal)'}
                    </span>
                  </div>
                </div>
              )}
            </div>

            {/* Stepper Navigation Footer */}
            <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
              <button
                onClick={() => setCurrentStep('layer2')}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-medium transition-colors cursor-pointer flex items-center space-x-1.5"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Layer 2 (Feeds)</span>
              </button>

              <button
                onClick={() => setCurrentStep('verdict')}
                className="px-5 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white text-xs font-semibold shadow-md shadow-emerald-600/30 transition-all cursor-pointer flex items-center space-x-1.5"
              >
                <span>Next: Final Verdict &amp; Fusion</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}

      {/* STEP 4: FINAL SYNTHESIS & VERDICT */}
      {result && currentStep === 'verdict' && (
        <div className="rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl overflow-hidden space-y-6">
          {(() => {
            const theme = getVerdictTheme(result.verdict);
            const Icon = theme.icon;
            return (
              <div className={`p-6 sm:p-8 border-b ${theme.bgClass} flex flex-col sm:flex-row sm:items-center justify-between gap-6`}>
                <div className="space-y-2">
                  <div className="flex items-center space-x-2">
                    <span className={`inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-bold border ${theme.badgeClass}`}>
                      <Icon className="w-4 h-4" />
                      <span>{theme.label}</span>
                    </span>
                  </div>
                  <h2 className="text-2xl font-black text-white">Synthesized Defense Verdict</h2>
                  <p className="text-xs text-slate-300 font-mono truncate max-w-xl">
                    {result.url}
                  </p>
                </div>

                <div className="text-right sm:border-l sm:border-slate-800/80 sm:pl-8 shrink-0">
                  <div className="text-4xl sm:text-5xl font-black font-mono text-white">
                    {result.risk_score}
                    <span className="text-sm text-slate-500 font-normal"> / 100</span>
                  </div>
                  <span className="text-[11px] text-slate-400 uppercase tracking-wider block mt-1 font-semibold">
                    Overall Risk Score
                  </span>
                </div>
              </div>
            );
          })()}

          <div className="p-6 space-y-6">
            {/* Multi-Layer Contribution Breakdown */}
            <div className="space-y-3">
              <span className="text-xs font-bold text-slate-300 uppercase tracking-wider block">
                How the Layers Formed This Score
              </span>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                <button
                  type="button"
                  onClick={() => setCurrentStep('layer1')}
                  className="p-3.5 rounded-xl bg-slate-950 hover:bg-slate-800/80 border border-slate-800 text-left transition-colors cursor-pointer space-y-1"
                >
                  <span className="text-indigo-400 font-mono text-[10px] font-bold block uppercase">
                    Layer 1: Rules (30%)
                  </span>
                  <div className="font-semibold text-white">
                    Score: {result.details.rule_score} / 100
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Contributed {Math.round(result.details.rule_score * 0.3)} pts
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => setCurrentStep('layer2')}
                  className="p-3.5 rounded-xl bg-slate-950 hover:bg-slate-800/80 border border-slate-800 text-left transition-colors cursor-pointer space-y-1"
                >
                  <span className="text-blue-400 font-mono text-[10px] font-bold block uppercase">
                    Layer 2: Feeds (30%)
                  </span>
                  <div className="font-semibold text-white">
                    {result.details.blocklist_hit ? 'Flagged (+30)' : 'Clean (0)'}
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Contributed {result.details.blocklist_hit ? '30' : '0'} pts
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => setCurrentStep('layer3')}
                  className="p-3.5 rounded-xl bg-slate-950 hover:bg-slate-800/80 border border-slate-800 text-left transition-colors cursor-pointer space-y-1"
                >
                  <span className="text-emerald-400 font-mono text-[10px] font-bold block uppercase">
                    Layer 3: ML (40%)
                  </span>
                  <div className="font-semibold text-white">
                    Prob: {(result.details.ml_probability * 100).toFixed(0)}%
                  </div>
                  <p className="text-[11px] text-slate-400">
                    Contributed {Math.round(result.details.ml_probability * 40)} pts
                  </p>
                </button>
              </div>
            </div>

            {/* Recommended Action */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2 text-xs">
              <span className="font-bold text-white block">Recommended SecOps Action:</span>
              <p className="text-slate-300 leading-relaxed">
                {result.verdict === 'likely_phishing'
                  ? 'Do not open this URL or submit credentials. If received in an email or SMS, report the incident immediately and add the domain to enterprise perimeter firewalls.'
                  : result.verdict === 'suspicious'
                  ? 'Exercise caution. Verify the domain registrar and sender headers before authenticating.'
                  : 'No active malicious indicators detected across our 4 layers. Standard web browsing safety applies.'}
              </p>
            </div>

            {/* Final Actions Footer */}
            <div className="pt-4 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
              <button
                onClick={() => setCurrentStep('layer3')}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-medium transition-colors cursor-pointer flex items-center space-x-1.5"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Review Layer 3</span>
              </button>

              <div className="flex items-center space-x-2.5">
                {onNavigateToReport && (
                  <button
                    onClick={() => onNavigateToReport(result.url)}
                    className="px-4 py-2 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-300 text-xs font-semibold transition-colors cursor-pointer"
                  >
                    Report URL as Threat
                  </button>
                )}

                <button
                  onClick={handleReset}
                  className="px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 text-white text-xs font-semibold shadow-md shadow-indigo-600/30 transition-all cursor-pointer flex items-center space-x-1.5"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Scan Another URL</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
