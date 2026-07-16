import { Link } from 'react-router-dom';

export default function Landing() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 to-gray-900 flex flex-col items-center justify-center p-6 text-white">
      <div className="max-w-4xl text-center">
        <div className="text-6xl mb-4">🛡️</div>
        <h1 className="text-5xl md:text-6xl font-extrabold bg-gradient-to-r from-blue-400 to-indigo-400 bg-clip-text text-transparent">
          Faro-Detect
        </h1>
        <p className="text-xl md:text-2xl text-gray-300 mt-4">
          Cameroon's AI-Powered Scam Detection Engine
        </p>
        <p className="text-gray-400 mt-2 max-w-2xl mx-auto">
          Protect yourself from Mobile Money scams, phishing links, and fake notifications.
        </p>
        <div className="mt-8 flex flex-col sm:flex-row gap-4 justify-center">
          <Link
            to="/register"
            className="px-8 py-3 bg-blue-600 hover:bg-blue-500 rounded-xl font-semibold transition shadow-lg shadow-blue-600/30"
          >
            Get Started
          </Link>
          <Link
            to="/login"
            className="px-8 py-3 bg-white/10 hover:bg-white/20 rounded-xl font-semibold transition border border-white/10"
          >
            Sign In
          </Link>
        </div>
        <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6 text-left">
          <div className="bg-white/5 p-4 rounded-xl border border-white/10">
            <h3 className="font-bold text-blue-400">🔍 Detect Scams</h3>
            <p className="text-sm text-gray-400">Instantly analyze suspicious SMS messages.</p>
          </div>
          <div className="bg-white/5 p-4 rounded-xl border border-white/10">
            <h3 className="font-bold text-blue-400">🛡️ Protect Users</h3>
            <p className="text-sm text-gray-400">Stop OTP theft and Mobile Money fraud.</p>
          </div>
          <div className="bg-white/5 p-4 rounded-xl border border-white/10">
            <h3 className="font-bold text-blue-400">📊 Track History</h3>
            <p className="text-sm text-gray-400">View all your past scans in one place.</p>
          </div>
        </div>
        <div className="mt-8 text-xs text-gray-600 border-t border-white/5 pt-6">
          Built with ❤️ for Cameroon · Presidential ICT Prize 2026
        </div>
      </div>
    </div>
  );
}
