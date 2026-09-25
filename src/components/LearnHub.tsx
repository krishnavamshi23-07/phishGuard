import React, { useState } from 'react';
import {
  BookOpen,
  ShieldCheck,
  AlertTriangle,
  Lock,
  Globe,
  Mail,
  CheckCircle2,
  XCircle,
  HelpCircle,
  KeyRound,
  Eye,
  ArrowRight,
  Terminal,
  QrCode,
  Image as ImageIcon,
  Database,
} from 'lucide-react';

interface QuizQuestion {
  id: number;
  scenario: string;
  senderOrUrl: string;
  isPhishing: boolean;
  explanation: string;
  keyFlag: string;
}

const QUIZ_QUESTIONS: QuizQuestion[] = [
  {
    id: 1,
    scenario:
      'You receive an email from "PayPal Security Team" claiming your account has been locked due to suspicious logins from Russia. It asks you to click a button to unlock it within 6 hours.',
    senderOrUrl: 'service@paypal-notice-support.xyz',
    isPhishing: true,
    keyFlag: 'Suspicious TLD (.xyz) and non-official domain',
    explanation:
      'Legitimate PayPal notifications come strictly from @paypal.com. PayPal will never use a random .xyz domain or demand resolution within 6 hours under threat of deletion.',
  },
  {
    id: 2,
    scenario:
      'You receive a password reset notification from GitHub because someone requested a reset. You remember clicking "Forgot Password" 2 minutes ago.',
    senderOrUrl: 'noreply@github.com',
    isPhishing: false,
    keyFlag: 'Authorized official sender domain',
    explanation:
      'The sender domain is @github.com, and this email was explicitly requested by your own actions seconds earlier.',
  },
  {
    id: 3,
    scenario:
      'An SMS message says: "USPS: Your package has an incomplete address and cannot be delivered. Click to verify your house number and pay a $0.35 redelivery fee."',
    senderOrUrl: 'https://usps-redelivery-tracking.top/fee',
    isPhishing: true,
    keyFlag: 'Smishing package lure with lookalike .top domain',
    explanation:
      'This is a classic "smishing" lure. USPS uses usps.com exclusively and does not send texts requesting small card payments to unlock parcel deliveries.',
  },
  {
    id: 4,
    scenario:
      'Your company CEO sends an email asking: "Are you in the office right now? I need you to purchase 4 Apple gift cards for a surprise employee appreciation event today and email the serial codes."',
    senderOrUrl: 'ceo.corporate.exec@gmail.com',
    isPhishing: true,
    keyFlag: 'CEO Gift Card Fraud from personal Gmail address',
    explanation:
      'This is a textbook Business Email Compromise (BEC) scam. Executives never ask employees to purchase retail gift cards via personal Gmail accounts.',
  },
  {
    id: 5,
    scenario:
      'You visit your bank by clicking a link in a text message, and the browser URL bar displays: http://192.241.132.88/chase/login',
    senderOrUrl: 'http://192.241.132.88/chase/login',
    isPhishing: true,
    keyFlag: 'Raw IP address instead of domain & unencrypted HTTP',
    explanation:
      'Legitimate financial institutions NEVER host online banking logins on raw IP addresses or plain HTTP protocols.',
  },
  {
    id: 6,
    scenario:
      'You receive an email with no clickable text links, only a PNG image attachment with a Microsoft logo and a QR code requesting you to scan with your personal phone to re-authenticate your mailbox.',
    senderOrUrl: '[Embedded PNG Image: microsoft-qr-reauth.png]',
    isPhishing: true,
    keyFlag: 'Quishing (QR Code Phishing) designed to bypass perimeter email filters',
    explanation:
      'Attackers use images and QR codes specifically because traditional email text filters cannot parse them easily. Once scanned on a personal phone, the victim is taken to a credential harvester outside corporate network protection.',
  },
];

export const LearnHub: React.FC = () => {
  const [activeQuizIndex, setActiveQuizIndex] = useState(0);
  const [selectedAnswer, setSelectedAnswer] = useState<boolean | null>(null);
  const [score, setScore] = useState(0);
  const [quizFinished, setQuizFinished] = useState(false);

  const currentQ = QUIZ_QUESTIONS[activeQuizIndex];

  const handleAnswer = (ans: boolean) => {
    setSelectedAnswer(ans);
    if (ans === currentQ.isPhishing) {
      setScore((s) => s + 1);
    }
  };

  const handleNext = () => {
    if (activeQuizIndex + 1 < QUIZ_QUESTIONS.length) {
      setActiveQuizIndex((i) => i + 1);
      setSelectedAnswer(null);
    } else {
      setQuizFinished(true);
    }
  };

  const handleResetQuiz = () => {
    setActiveQuizIndex(0);
    setSelectedAnswer(null);
    setScore(0);
    setQuizFinished(false);
  };

  return (
    <div className="space-y-10">
      {/* Header */}
      <div className="rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950 border border-slate-800 p-6 sm:p-8">
        <div className="flex items-center space-x-2 text-indigo-400 text-xs font-semibold uppercase tracking-wider mb-2">
          <BookOpen className="w-4 h-4" />
          <span>Security Awareness &amp; Defense Manual</span>
        </div>
        <h1 className="text-3xl font-extrabold text-white tracking-tight">
          How to Recognize &amp; Neutralize Phishing Attacks
        </h1>
        <p className="mt-2 text-slate-300 text-sm max-w-2xl">
          Phishing remains the #1 entry vector for ransomware, data breaches, and credential theft.
          Learn the hallmarks of deceptive websites, engineered email lures, and test your instincts.
        </p>
      </div>

      {/* Anatomy Diagrams */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Anatomy of Phishing URL */}
        <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
          <div className="flex items-center space-x-2 text-indigo-400">
            <Globe className="w-5 h-5" />
            <h2 className="text-base font-bold text-white">Anatomy of a Fake URL</h2>
          </div>
          <p className="text-xs text-slate-400">
            Attackers design deceptive domains that look legitimate at first glance. Inspect every component:
          </p>

          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 break-all leading-relaxed">
            <span className="text-amber-400">https://</span>
            <span className="text-rose-400 bg-rose-500/10 px-1 rounded">paypal.com</span>
            <span className="text-slate-500">.</span>
            <span className="text-indigo-400 bg-indigo-500/10 px-1 rounded">account-verify-login</span>
            <span className="text-slate-500">.</span>
            <span className="text-rose-400 bg-rose-500/10 px-1 rounded font-bold">xyz</span>
            <span className="text-slate-400">/signin</span>
          </div>

          <div className="space-y-2 text-xs text-slate-300">
            <div className="flex items-start space-x-2">
              <span className="text-rose-400 font-bold">•</span>
              <span>
                <strong>Deceptive Subdomain:</strong> "paypal.com" is merely a subdomain prefix, not the actual destination domain.
              </span>
            </div>
            <div className="flex items-start space-x-2">
              <span className="text-indigo-400 font-bold">•</span>
              <span>
                <strong>Actual Root Host:</strong> "account-verify-login.xyz" is the attacker's actual controlled server.
              </span>
            </div>
            <div className="flex items-start space-x-2">
              <span className="text-amber-400 font-bold">•</span>
              <span>
                <strong>Misleading HTTPS Lock:</strong> The padlock icon only means encryption in transit, NOT that the site owner is trustworthy!
              </span>
            </div>
          </div>
        </div>

        {/* Anatomy of Phishing Email */}
        <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
          <div className="flex items-center space-x-2 text-indigo-400">
            <Mail className="w-5 h-5" />
            <h2 className="text-base font-bold text-white">Anatomy of a Phishing Email</h2>
          </div>
          <p className="text-xs text-slate-400">
            Social engineering relies on cognitive pressure: fear, urgency, authority, or greed.
          </p>

          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 space-y-2">
            <div className="border-b border-slate-800 pb-2">
              <span className="text-slate-400">From: </span>
              <span className="text-white font-medium">Chase Bank Alerts </span>
              <span className="text-rose-400 font-mono text-[11px]">&lt;alerts@chase-secure-auth.top&gt;</span>
            </div>
            <div className="text-rose-300 font-medium">Subject: IMMEDIATE ACTION REQUIRED: Account Suspended</div>
            <p className="text-slate-400 text-[11px] italic">
              "Dear Valued Customer, We have detected unauthorized logins. Click below to verify your SSN and card PIN within 12 hours..."
            </p>
          </div>

          <div className="space-y-2 text-xs text-slate-300">
            <div className="flex items-start space-x-2">
              <span className="text-rose-400 font-bold">•</span>
              <span>
                <strong>Display Name Spoofing:</strong> Friendly name says "Chase Bank", but header domain is "chase-secure-auth.top".
              </span>
            </div>
            <div className="flex items-start space-x-2">
              <span className="text-amber-400 font-bold">•</span>
              <span>
                <strong>Artificial Clock:</strong> Giving a 12-hour ultimatum aims to bypass your rational critical thinking.
              </span>
            </div>
            <div className="flex items-start space-x-2">
              <span className="text-emerald-400 font-bold">•</span>
              <span>
                <strong>Generic Salutation:</strong> Real banks address you by your first and last name.
              </span>
            </div>
          </div>
        </div>

        {/* Anatomy of Image Phishing & Quishing (QR Codes) */}
        <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
          <div className="flex items-center space-x-2 text-purple-400">
            <QrCode className="w-5 h-5" />
            <h2 className="text-base font-bold text-white">Image Phishing &amp; Quishing</h2>
          </div>
          <p className="text-xs text-slate-400">
            Attackers embed malicious text and QR codes into graphics to evade traditional email text filters.
          </p>

          <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 space-y-2">
            <div className="border-b border-slate-800 pb-1.5 flex items-center justify-between text-[11px] text-slate-400">
              <span>Attachment: MFA_Reset.png</span>
              <span className="text-purple-400 font-mono font-bold">[QR Code Payload]</span>
            </div>
            <div className="text-purple-300 font-medium">Lure: "Scan with your phone camera to retain corporate login"</div>
            <p className="text-slate-400 text-[11px] italic">
              Dest: https://login-microsoft-mfa.xyz/auth (Fake 2FA harvest portal)
            </p>
          </div>

          <div className="space-y-2 text-xs text-slate-300">
            <div className="flex items-start space-x-2">
              <span className="text-purple-400 font-bold">•</span>
              <span>
                <strong>Bypasses Email Text Scanners:</strong> Since the phishing URL is inside the QR image rather than email body text, perimeter scanners cannot flag it.
              </span>
            </div>
            <div className="flex items-start space-x-2">
              <span className="text-rose-400 font-bold">•</span>
              <span>
                <strong>Jumps to Unprotected Phones:</strong> Victims scan with personal phones lacking corporate endpoint detection.
              </span>
            </div>
            <div className="flex items-start space-x-2">
              <span className="text-indigo-400 font-bold">•</span>
              <span>
                <strong>Risky Signature Vault Protection:</strong> Storing the image hash prevents repeated exposure across an entire organization.
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Interactive Phishing IQ Quiz */}
      <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6 sm:p-8 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center space-x-2 text-emerald-400 text-xs font-semibold uppercase tracking-wider mb-1">
              <HelpCircle className="w-4 h-4" />
              <span>Interactive Simulator</span>
            </div>
            <h2 className="text-xl font-bold text-white">Test Your Phishing Detection Instincts</h2>
          </div>
          <div className="text-xs font-mono px-3 py-1 rounded-full bg-slate-800 text-slate-300">
            Question {quizFinished ? QUIZ_QUESTIONS.length : activeQuizIndex + 1} of {QUIZ_QUESTIONS.length}
          </div>
        </div>

        {!quizFinished ? (
          <div className="space-y-6">
            {/* Scenario Card */}
            <div className="p-5 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold block">
                Scenario #{currentQ.id}
              </span>
              <p className="text-sm text-slate-200 leading-relaxed">{currentQ.scenario}</p>

              <div className="pt-2">
                <span className="text-xs text-slate-400">Inspected Address / Link:</span>
                <div className="mt-1 font-mono text-xs text-indigo-300 bg-slate-900/80 p-2.5 rounded-lg border border-slate-800 break-all">
                  {currentQ.senderOrUrl}
                </div>
              </div>
            </div>

            {/* Answer Options */}
            {selectedAnswer === null ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <button
                  type="button"
                  onClick={() => handleAnswer(true)}
                  className="py-3.5 px-4 rounded-xl bg-slate-950 border border-rose-500/40 hover:bg-rose-500/10 text-rose-300 font-semibold text-sm transition-all flex items-center justify-center space-x-2 cursor-pointer"
                >
                  <XCircle className="w-4 h-4 text-rose-400" />
                  <span>Flag as Phishing / Scam</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleAnswer(false)}
                  className="py-3.5 px-4 rounded-xl bg-slate-950 border border-emerald-500/40 hover:bg-emerald-500/10 text-emerald-300 font-semibold text-sm transition-all flex items-center justify-center space-x-2 cursor-pointer"
                >
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>Legitimate / Safe</span>
                </button>
              </div>
            ) : (
              /* Feedback Banner */
              <div className="space-y-4">
                <div
                  className={`p-4 rounded-xl border text-xs sm:text-sm space-y-2 ${
                    selectedAnswer === currentQ.isPhishing
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200'
                      : 'bg-rose-500/10 border-rose-500/30 text-rose-200'
                  }`}
                >
                  <div className="flex items-center space-x-2 font-bold text-base">
                    {selectedAnswer === currentQ.isPhishing ? (
                      <>
                        <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                        <span>Correct! You spotted the indicators.</span>
                      </>
                    ) : (
                      <>
                        <XCircle className="w-5 h-5 text-rose-400" />
                        <span>Incorrect. This was {currentQ.isPhishing ? 'a phishing attack' : 'legitimate'}.</span>
                      </>
                    )}
                  </div>
                  <p className="text-slate-300 leading-relaxed">{currentQ.explanation}</p>
                  <div className="text-xs text-indigo-300 font-semibold pt-1">
                    Key indicator: {currentQ.keyFlag}
                  </div>
                </div>

                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={handleNext}
                    className="px-6 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-sm flex items-center space-x-2 cursor-pointer transition-all"
                  >
                    <span>
                      {activeQuizIndex + 1 < QUIZ_QUESTIONS.length
                        ? 'Next Scenario'
                        : 'View Quiz Results'}
                    </span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </div>
        ) : (
          /* Quiz Results */
          <div className="text-center py-8 space-y-4">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-indigo-500/20 text-indigo-300 text-2xl font-bold mb-2">
              {score}/{QUIZ_QUESTIONS.length}
            </div>
            <h2 className="text-2xl font-bold text-white">
              {score === QUIZ_QUESTIONS.length
                ? 'Outstanding! Certified Threat Spotter'
                : score >= 3
                ? 'Great Job! Solid Phishing Awareness'
                : 'Stay Vigilant! Review Safety Tips Below'}
            </h2>
            <p className="text-slate-300 text-sm max-w-md mx-auto">
              You correctly classified {score} out of {QUIZ_QUESTIONS.length} realistic phishing
              threat scenarios.
            </p>
            <button
              onClick={handleResetQuiz}
              className="px-6 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-sm font-medium transition-colors cursor-pointer"
            >
              Retake Quiz
            </button>
          </div>
        )}
      </div>

      {/* Safety Rules Checklist */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
        <h2 className="text-base font-bold text-white flex items-center space-x-2">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <span>The Golden Defense Checklist</span>
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
            <div className="flex items-center space-x-2 text-indigo-400 font-bold">
              <KeyRound className="w-4 h-4" />
              <span>1. Enforce FIDO2 / MFA</span>
            </div>
            <p className="text-slate-300">
              Hardware security keys (YubiKeys) and passkeys cannot be phished even if you enter your credentials on a fake site.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
            <div className="flex items-center space-x-2 text-amber-400 font-bold">
              <Eye className="w-4 h-4" />
              <span>2. Inspect the Root Domain</span>
            </div>
            <p className="text-slate-300">
              Read URLs from right to left before the first slash. Determine the actual domain registrar, not the deceptive subdomain.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5">
            <div className="flex items-center space-x-2 text-emerald-400 font-bold">
              <Lock className="w-4 h-4" />
              <span>3. Use Password Managers</span>
            </div>
            <p className="text-slate-300">
              Password managers will NEVER autofill your passwords on spoofed or typosquatted domains. If autofill fails, pause immediately!
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
