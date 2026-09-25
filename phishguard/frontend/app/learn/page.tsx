import React from 'react';
import { BookOpen, ShieldCheck, AlertTriangle, KeyRound, Globe, Mail } from 'lucide-react';

export default function LearnPage() {
  return (
    <div className="max-w-4xl mx-auto space-y-8">
      <div>
        <h1 className="text-3xl font-extrabold text-white">Phishing Defense &amp; Security Education</h1>
        <p className="text-slate-400 text-sm mt-1">
          Master the fundamentals of identifying deceptive websites, email fraud, and social engineering.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center space-x-2 text-indigo-400">
            <Mail className="w-5 h-5" />
            <h2 className="font-bold text-white text-base">Signs in Suspicious Emails</h2>
          </div>
          <ul className="text-xs text-slate-300 space-y-2">
            <li>&bull; <strong>Artificial Urgency:</strong> Demands action within 24 hours or threatens account deletion.</li>
            <li>&bull; <strong>Display Name Spoofing:</strong> Friendly name says &quot;Bank of America&quot; but header email is from an unverified domain.</li>
            <li>&bull; <strong>Generic Salutations:</strong> Uses &quot;Dear Customer&quot; or &quot;Valued Member&quot; instead of your name.</li>
            <li>&bull; <strong>Requests for Credentials:</strong> Asks for passwords, PIN numbers, or wire transfers.</li>
          </ul>
        </div>

        <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
          <div className="flex items-center space-x-2 text-indigo-400">
            <Globe className="w-5 h-5" />
            <h2 className="font-bold text-white text-base">Signs in Suspicious Websites</h2>
          </div>
          <ul className="text-xs text-slate-300 space-y-2">
            <li>&bull; <strong>Lookalike / Typosquatted Domains:</strong> e.g., <code>paypa1.com</code> or <code>arnazon.com</code>.</li>
            <li>&bull; <strong>Subdomain Tricks:</strong> e.g., <code>paypal.com.verify-login.xyz</code> where the real domain is <code>verify-login.xyz</code>.</li>
            <li>&bull; <strong>Raw IP Addresses:</strong> Hosting login screens on bare IP addresses (e.g. <code>http://192.168.1.1/login</code>).</li>
            <li>&bull; <strong>Misleading HTTPS:</strong> An SSL lock only encrypts transmission, it does not guarantee trustworthiness!</li>
          </ul>
        </div>
      </div>

      {/* Basic Safety Tips */}
      <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
        <h2 className="font-bold text-white text-lg flex items-center space-x-2">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <span>Core Safety Best Practices</span>
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs text-slate-300">
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="font-semibold text-white block">1. Enable Strong MFA / Passkeys</span>
            <p className="text-slate-400">Hardware tokens (FIDO2/WebAuthn) protect against credential theft even if you land on a phishing page.</p>
          </div>
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="font-semibold text-white block">2. Verify Domain Endings</span>
            <p className="text-slate-400">Read domains backwards from the first forward slash to identify the genuine registrar root.</p>
          </div>
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
            <span className="font-semibold text-white block">3. Never Click Unverified Links</span>
            <p className="text-slate-400">When receiving an alert about an account issue, navigate manually to the official site.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
