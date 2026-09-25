import React from 'react';
import {
  ShieldCheck,
  Mail,
  AlertTriangle,
  BookOpen,
  Shield,
  Layers,
  LogOut,
  User as UserIcon,
  Image as ImageIcon,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export type NavTab = 'url' | 'email' | 'image' | 'report' | 'learn';

interface NavbarProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  onOpenSecurityReview?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  onOpenSecurityReview,
}) => {
  const { user, logout } = useAuth();

  return (
    <header className="sticky top-0 z-50 bg-slate-950/85 backdrop-blur-md border-b border-slate-800 text-slate-100">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Brand */}
          <div
            onClick={() => setActiveTab('url')}
            className="flex items-center space-x-3 cursor-pointer group"
          >
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500 via-blue-600 to-emerald-500 p-0.5 shadow-lg shadow-indigo-500/20 group-hover:scale-105 transition-transform">
              <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
                <ShieldCheck className="w-5 h-5 text-emerald-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-white via-slate-200 to-indigo-200 bg-clip-text text-transparent">
                  PhishGuard
                </span>
                <span className="text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 hidden sm:inline-block">
                  Defense Engine
                </span>
              </div>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="flex items-center space-x-1 sm:space-x-1.5">
            <button
              onClick={() => setActiveTab('url')}
              className={`flex items-center space-x-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-all cursor-pointer ${
                activeTab === 'url'
                  ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <Shield className="w-4 h-4" />
              <span>URL Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('email')}
              className={`flex items-center space-x-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-all cursor-pointer ${
                activeTab === 'email'
                  ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <Mail className="w-4 h-4" />
              <span className="hidden sm:inline">Email Checker</span>
            </button>

            <button
              onClick={() => setActiveTab('image')}
              className={`flex items-center space-x-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-all cursor-pointer ${
                activeTab === 'image'
                  ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <ImageIcon className="w-4 h-4" />
              <span>Image Phishing</span>
            </button>

            <button
              onClick={() => setActiveTab('learn')}
              className={`flex items-center space-x-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-all cursor-pointer ${
                activeTab === 'learn'
                  ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <BookOpen className="w-4 h-4" />
              <span>Learn Phishing</span>
            </button>

            <button
              onClick={() => setActiveTab('report')}
              className={`flex items-center space-x-1.5 px-3 py-2 rounded-lg text-sm font-medium transition-all cursor-pointer ${
                activeTab === 'report'
                  ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <AlertTriangle className="w-4 h-4" />
              <span className="hidden sm:inline">Report</span>
            </button>
          </nav>

          {/* User Profile / Logout */}
          <div className="flex items-center space-x-2.5">
            {user && (
              <div className="flex items-center space-x-2 pl-2 border-l border-slate-800">
                {user.securityStatus === 'compromise_flagged' ? (
                  <button
                    onClick={onOpenSecurityReview}
                    className="px-2.5 py-1 rounded-full bg-rose-500/20 text-rose-300 border border-rose-500/40 text-[10px] font-bold uppercase animate-pulse flex items-center space-x-1 cursor-pointer hover:bg-rose-500/30 transition-colors"
                    title="Account lockdown active. Click to view security containment."
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
                    <span>Lockdown</span>
                  </button>
                ) : !user.lastLoginSession.reviewed ? (
                  <button
                    onClick={onOpenSecurityReview}
                    className="px-2.5 py-1 rounded-full bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 text-[10px] font-medium hidden sm:flex items-center space-x-1.5 cursor-pointer hover:bg-indigo-500/25 transition-colors shadow-sm"
                    title="Click to review last login access"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-ping" />
                    <span>Review Access</span>
                  </button>
                ) : null}

                <button
                  onClick={onOpenSecurityReview}
                  className="w-8 h-8 rounded-full bg-gradient-to-tr from-indigo-600 to-emerald-500 flex items-center justify-center text-xs font-bold text-white shadow-sm hover:scale-105 transition-transform cursor-pointer"
                  title="View Account & Security Details"
                >
                  {user.name.charAt(0)}
                </button>
                <div
                  onClick={onOpenSecurityReview}
                  className="hidden xl:block text-left cursor-pointer hover:opacity-80 transition-opacity"
                  title="View Account & Security Details"
                >
                  <div className="text-xs font-medium text-slate-200 leading-none">{user.name}</div>
                  <div className="text-[10px] text-indigo-400 font-mono">{user.role}</div>
                </div>
                <button
                  onClick={logout}
                  title="Sign out of portal"
                  className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 text-xs font-semibold transition-all cursor-pointer shadow-sm"
                >
                  <LogOut className="w-3.5 h-3.5 text-rose-400" />
                  <span className="hidden sm:inline">Sign Out</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
