import React, { useState } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { LoginPage } from './components/LoginPage';
import { Navbar, NavTab } from './components/Navbar';
import { UrlChecker } from './components/UrlChecker';
import { EmailChecker } from './components/EmailChecker';
import { ImagePhishingChecker } from './components/ImagePhishingChecker';
import { ReportForm } from './components/ReportForm';
import { LearnHub } from './components/LearnHub';
import { LastLoginSecurityReview } from './components/LastLoginSecurityReview';
import { ShieldCheck } from 'lucide-react';

function AppContent() {
  const { isAuthenticated } = useAuth();
  const [activeTab, setActiveTab] = useState<NavTab>('url');
  const [reportPrefillUrl, setReportPrefillUrl] = useState<string>('');
  const [showSecurityReviewModal, setShowSecurityReviewModal] = useState<boolean>(false);

  // If user is not authenticated, render clean Login Page
  if (!isAuthenticated) {
    return <LoginPage />;
  }

  const handleNavigateToReport = (url: string) => {
    setReportPrefillUrl(url);
    setActiveTab('report');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-indigo-500 selection:text-white">
      {/* Top Navbar with User Status */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenSecurityReview={() => setShowSecurityReviewModal(true)}
      />

      {/* Main View Area - Clean & uncluttered per tab */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'url' && (
          <UrlChecker
            onNavigateToReport={handleNavigateToReport}
            onOpenSecurityReview={() => setShowSecurityReviewModal(true)}
          />
        )}

        {activeTab === 'email' && <EmailChecker />}

        {activeTab === 'image' && (
          <ImagePhishingChecker onNavigateToReport={() => setActiveTab('report')} />
        )}

        {activeTab === 'report' && (
          <ReportForm
            initialContent={reportPrefillUrl}
            initialType="url"
          />
        )}

        {activeTab === 'learn' && <LearnHub />}
      </main>

      {/* Dedicated Last Login Security Review Modal */}
      <LastLoginSecurityReview
        isModal={true}
        isOpen={showSecurityReviewModal}
        onClose={() => setShowSecurityReviewModal(false)}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 text-slate-500 text-xs py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span className="font-semibold text-slate-300">PhishGuard Security Portal</span>
            <span>&bull;</span>
            <span>4-Tier Defense Pipeline</span>
          </div>

          <div className="flex items-center space-x-6 text-slate-400">
            <button
              onClick={() => setActiveTab('url')}
              className="hover:text-slate-200 transition-colors cursor-pointer"
            >
              URL Scanner
            </button>
            <button
              onClick={() => setActiveTab('email')}
              className="hover:text-slate-200 transition-colors cursor-pointer"
            >
              Email Checker
            </button>
            <button
              onClick={() => setActiveTab('image')}
              className="hover:text-slate-200 transition-colors cursor-pointer text-indigo-400"
            >
              Image Phishing
            </button>
            <button
              onClick={() => setActiveTab('learn')}
              className="hover:text-slate-200 transition-colors cursor-pointer"
            >
              Learn Phishing
            </button>
            <button
              onClick={() => setActiveTab('report')}
              className="hover:text-slate-200 transition-colors cursor-pointer"
            >
              Report Threat
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
