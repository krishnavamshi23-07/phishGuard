import type { Metadata } from 'next';
import './globals.css';
import { Navbar } from '../components/Navbar';

export const metadata: Metadata = {
  title: 'PhishGuard - Layered Anti-Phishing Defense',
  description: 'Production-ready anti-phishing website combining rule heuristics, blocklist reputation, and machine learning.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-indigo-500 selection:text-white flex flex-col">
        <Navbar />
        <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {children}
        </main>
        <footer className="border-t border-slate-900 bg-slate-950/80 text-slate-500 text-xs py-6 text-center">
          PhishGuard Security Engine &bull; Layered Anti-Phishing System
        </footer>
      </body>
    </html>
  );
}
