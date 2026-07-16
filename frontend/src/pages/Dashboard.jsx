import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const API_URL = "https://faro-detect-api-1.onrender.com";

export default function Dashboard() {
  const [message, setMessage] = useState('');
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [userEmail, setUserEmail] = useState('User');
  const navigate = useNavigate();

  const token = localStorage.getItem('access_token');

  useEffect(() => {
    if (!token) {
      navigate('/login');
    }
  }, [token, navigate]);

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    navigate('/login');
  };

  const scanMessage = async () => {
    if (!message) return alert('Please paste a message.');
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ message })
      });
      const data = await res.json();
      if (res.ok) setResult(data);
      else alert('Error: ' + (data.detail || 'Scan failed'));
    } catch {
      alert('Network error.');
    }
    setLoading(false);
  };

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/scan/history`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (res.ok) setHistory(data);
    } catch {
      setHistory([]);
    }
    setLoading(false);
  };

  const getStatusColor = (status) => {
    if (status === 'Safe' || status === 'SAFE') return 'bg-emerald-600';
    if (status === 'Warning' || status === 'SUSPICIOUS') return 'bg-yellow-600';
    return 'bg-red-600';
  };

  // If no token, redirect
  if (!token) {
    return null;
  }

  return (
    <div className="min-h-screen bg-gray-900 p-4">
      <div className="max-w-3xl mx-auto bg-gray-800 p-6 md:p-8 rounded-3xl shadow-2xl border border-gray-700">
        {/* Header */}
        <div className="flex justify-between items-center pb-4 border-b border-gray-700 mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white">🛡️ Faro-Detect</h1>
            <p className="text-xs text-gray-400">Welcome, <span className="text-blue-400 font-semibold">{userEmail}</span></p>
          </div>
          <button 
            onClick={handleLogout} 
            className="text-sm bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg text-white font-medium transition"
          >
            Logout
          </button>
        </div>

        {/* Scan Input */}
        <div className="mb-5">
          <label className="block text-sm font-medium text-gray-300 mb-2">
            📝 Paste suspicious SMS / Message
          </label>
          <textarea
            rows="4"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="e.g., URGENT: Your MTN MoMo account has been suspended..."
            className="w-full p-4 bg-gray-700 rounded-xl border border-gray-600 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500 transition resize-none"
          />
        </div>

        <button 
          onClick={scanMessage} 
          disabled={loading} 
          className="w-full py-4 bg-blue-600 hover:bg-blue-500 rounded-xl font-bold text-lg text-white transition shadow-lg shadow-blue-600/30 flex items-center justify-center gap-2 disabled:opacity-50"
        >
          {loading ? '⏳ Scanning...' : '🔍 Scan Message'}
        </button>

        {/* Result Card */}
        {result && (
          <div className="mt-6 p-5 rounded-xl bg-gray-700 border border-gray-600">
            <h3 className="font-bold text-lg mb-3 text-white">📊 Scan Result</h3>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="bg-gray-600 p-3 rounded-lg">
                <p className="text-gray-300 text-xs uppercase">Risk Score</p>
                <p className="text-2xl font-mono font-bold text-yellow-400">{result.risk_score}%</p>
              </div>
              <div className="bg-gray-600 p-3 rounded-lg">
                <p className="text-gray-300 text-xs uppercase">Status</p>
                <span className={`mt-1 inline-block px-4 py-1 rounded-full text-xs font-bold text-white ${getStatusColor(result.status)}`}>
                  {result.status}
                </span>
              </div>
              <div className="col-span-2 bg-gray-600 p-3 rounded-lg">
                <p className="text-gray-300 text-xs uppercase">Category</p>
                <p className="font-semibold text-white">{result.scam_category || 'N/A'}</p>
              </div>
              <div className="col-span-2 bg-gray-600 p-3 rounded-lg">
                <p className="text-gray-300 text-xs uppercase">Reason</p>
                <p className="text-white text-sm break-words">{result.reason || 'No details'}</p>
              </div>
            </div>
          </div>
        )}

        {/* History */}
        <div className="mt-8">
          <button 
            onClick={fetchHistory} 
            disabled={loading} 
            className="text-sm text-blue-400 hover:text-blue-300 transition disabled:opacity-50"
          >
            📜 View Scan History
          </button>
          <div className="mt-3 space-y-2 max-h-60 overflow-y-auto pr-1 text-sm">
            {history.length === 0 && (
              <p className="text-gray-500 italic text-xs">No scans yet.</p>
            )}
            {history.map((item, idx) => (
              <div key={idx} className="bg-gray-700 p-3 rounded-lg flex justify-between items-center border border-gray-600">
                <span className="truncate w-3/4 text-gray-300">{item.message.substring(0, 40)}...</span>
                <span className={`text-xs px-3 py-1 rounded-full font-bold ${
                  item.status === 'SAFE' ? 'bg-emerald-600/30 text-emerald-300' : 'bg-red-600/30 text-red-300'
                }`}>
                  {item.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="mt-8 text-center text-xs text-gray-600 border-t border-gray-700 pt-6">
          Built with ❤️ for Cameroon · Presidential ICT Prize 2026
        </div>
      </div>
    </div>
  );
}        body: JSON.stringify({ message })
      });
      const data = await res.json();
      if (res.ok) setResult(data);
      else alert('Error: ' + (data.detail || 'Scan failed'));
    } catch {
      alert('Network error.');
    }
    setLoading(false);
  };

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/scan/history`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (res.ok) setHistory(data);
    } catch {
      setHistory([]);
    }
    setLoading(false);
  };

  const getStatusColor = (status) => {
    if (status === 'Safe' || status === 'SAFE') return 'bg-emerald-600';
    if (status === 'Warning' || status === 'SUSPICIOUS') return 'bg-yellow-600';
    return 'bg-red-600';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 to-gray-900 flex items-center justify-center p-4">
      <div className="w-full max-w-3xl bg-white/5 backdrop-blur-2xl p-6 md:p-8 rounded-3xl border border-white/10 shadow-2xl">
        <div className="flex justify-between items-center pb-4 border-b border-white/10 mb-6">
          <div>
            <h1 className="text-2xl font-bold text-white">🛡️ Faro-Detect</h1>
            <p className="text-xs text-gray-400">Welcome, <span className="text-blue-300 font-semibold">{userEmail}</span></p>
          </div>
          <button onClick={handleLogout} className="text-sm bg-red-600/30 px-4 py-2 rounded-lg border border-red-500/30 text-red-300 hover:bg-red-600/50 transition">
            Logout
          </button>
        </div>

        <div className="mb-5">
          <label className="block text-sm font-medium text-gray-300 mb-2">📝 Paste suspicious SMS / Message</label>
          <textarea
            rows="4"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            placeholder="e.g., URGENT: Your MTN MoMo account has been suspended..."
            className="w-full p-4 bg-white/5 rounded-xl border border-white/10 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition resize-none"
          />
        </div>
        <button onClick={scanMessage} disabled={loading} className="w-full py-4 bg-blue-600 hover:bg-blue-500 rounded-xl font-bold text-lg transition shadow-lg shadow-blue-600/30 flex items-center justify-center gap-2 disabled:opacity-50">
          {loading ? '⏳ Scanning...' : '🔍 Scan Message'}
        </button>

        {result && (
          <div className="mt-6 p-5 rounded-xl bg-white/5 border border-white/10">
            <h3 className="font-bold text-lg mb-3 text-gray-200">📊 Scan Result</h3>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="bg-white/5 p-3 rounded-lg">
                <p className="text-gray-400 text-xs uppercase">Risk Score</p>
                <p className="text-2xl font-mono font-bold text-yellow-400">{result.risk_score}%</p>
              </div>
              <div className="bg-white/5 p-3 rounded-lg">
                <p className="text-gray-400 text-xs uppercase">Status</p>
                <span className={`mt-1 inline-block px-4 py-1 rounded-full text-xs font-bold text-white ${getStatusColor(result.status)}`}>
                  {result.status}
                </span>
              </div>
              <div className="col-span-2 bg-white/5 p-3 rounded-lg">
                <p className="text-gray-400 text-xs uppercase">Category</p>
                <p className="font-semibold text-white">{result.scam_category || 'N/A'}</p>
              </div>
              <div className="col-span-2 bg-white/5 p-3 rounded-lg">
                <p className="text-gray-400 text-xs uppercase">Reason</p>
                <p className="text-white text-sm break-words">{result.reason || 'No details'}</p>
              </div>
            </div>
          </div>
        )}

        <div className="mt-8">
          <button onClick={fetchHistory} disabled={loading} className="text-sm text-blue-400 hover:text-blue-300 transition disabled:opacity-50">
            📜 View Scan History
          </button>
          <div className="mt-3 space-y-2 max-h-60 overflow-y-auto pr-1 text-sm">
            {history.length === 0 && <p className="text-gray-500 italic text-xs">No scans yet.</p>}
            {history.map((item, idx) => (
              <div key={idx} className="bg-white/5 p-3 rounded-lg flex justify-between items-center border border-white/5">
                <span className="truncate w-3/4 text-gray-300">{item.message.substring(0, 40)}...</span>
                <span className={`text-xs px-3 py-1 rounded-full font-bold ${item.status === 'SAFE' ? 'bg-emerald-600/30 text-emerald-300' : 'bg-red-600/30 text-red-300'}`}>
                  {item.status}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="mt-8 text-center text-xs text-gray-600 border-t border-white/5 pt-6">
          Built with ❤️ for Cameroon · Presidential ICT Prize 2026
        </div>
      </div>
    </div>
  );
}
