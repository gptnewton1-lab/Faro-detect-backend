import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const API_URL = "https://faro-detect-api-1.onrender.com";

export default function Dashboard() {
  const [message, setMessage] = useState('');
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const token = localStorage.getItem('access_token');

  useEffect(() => {
    if (!token) navigate('/login');
  }, [token, navigate]);

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    navigate('/login');
  };

  const scanMessage = async () => {
    if (!message) return alert('Paste a message');
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ message })
      });
      const data = await res.json();
      if (res.ok) setResult(data);
      else alert(data.detail || 'Scan failed');
    } catch { alert('Network error'); }
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
    } catch { setHistory([]); }
    setLoading(false);
  };

  if (!token) return null;

  return (
    <div className="min-h-screen bg-gray-900 text-white p-4">
      <div className="max-w-3xl mx-auto bg-gray-800 p-6 rounded-2xl shadow-xl">
        <div className="flex justify-between items-center border-b border-gray-700 pb-4 mb-6">
          <h1 className="text-2xl font-bold">🛡️ Faro-Detect</h1>
          <button onClick={handleLogout} className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg text-sm">Logout</button>
        </div>

        <textarea
          rows="4"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Paste suspicious message here..."
          className="w-full p-3 bg-gray-700 rounded-lg border border-gray-600 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
        />
        <button
          onClick={scanMessage}
          disabled={loading}
          className="w-full mt-4 bg-blue-600 hover:bg-blue-700 py-3 rounded-lg font-bold disabled:opacity-50"
        >
          {loading ? 'Scanning...' : '🔍 Scan'}
        </button>

        {result && (
          <div className="mt-6 p-4 bg-gray-700 rounded-lg">
            <h3 className="font-bold mb-2">Result</h3>
            <p>Risk: <span className="text-yellow-400 font-bold">{result.risk_score}%</span></p>
            <p>Status: <span className={`inline-block px-3 py-1 rounded-full text-xs font-bold ${result.status === 'Safe' || result.status === 'SAFE' ? 'bg-green-500' : result.status === 'Warning' || result.status === 'SUSPICIOUS' ? 'bg-yellow-500' : 'bg-red-500'}`}>{result.status}</span></p>
            <p>Category: {result.scam_category || 'N/A'}</p>
            <p>Reason: {result.reason || 'No details'}</p>
          </div>
        )}

        <button onClick={fetchHistory} className="mt-6 text-blue-400 hover:underline text-sm">📜 History</button>
        <div className="mt-3 space-y-2 max-h-60 overflow-y-auto">
          {history.length === 0 && <p className="text-gray-500 text-sm">No scans yet</p>}
          {history.map((item, i) => (
            <div key={i} className="bg-gray-700 p-3 rounded-lg flex justify-between">
              <span className="truncate w-3/4">{item.message.substring(0, 40)}...</span>
              <span className={`text-xs px-2 py-1 rounded-full ${item.status === 'SAFE' ? 'bg-green-600' : 'bg-red-600'}`}>{item.status}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
