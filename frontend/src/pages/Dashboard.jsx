import { useState, useEffect } from 'react'; // React hooks for local state and side effects

const API_URL = "https://faro-detect-api-1.onrender.com"; // Base URL of the deployed backend

export default function Dashboard() {
  const [message, setMessage] = useState(''); // Text currently typed/pasted into the textarea
  const [result, setResult] = useState(null); // Result of the most recent scan
  const [history, setHistory] = useState([]); // List of past scans
  const [loadingScan, setLoadingScan] = useState(false); // Separate loading flag for the scan button
  const [loadingHistory, setLoadingHistory] = useState(false); // Separate loading flag for the history button
  const [token, setToken] = useState(() => localStorage.getItem('access_token')); // Read token once into state so we control when it changes

  useEffect(() => {
    if (!token) {
      window.location.href = '/login'; // No token at all -> straight to login
    }
  }, [token]); // Re-check whenever token changes (e.g. after we clear it on 401)

  const handleLogout = () => {
    localStorage.removeItem('access_token'); // Clear the stored token
    setToken(null); // Triggers the effect above, which redirects to /login
  };

  // Central place to handle an expired/invalid session so every fetch behaves the same way
  const handleUnauthorized = () => {
    alert('Your session has expired. Please log in again.'); // Tell the user why they're being logged out
    handleLogout(); // Reuse the same logout path
  };

  // Safely parses a fetch Response as JSON, returning null instead of throwing
  // on empty bodies or non-JSON error pages (e.g. a 502 from the host).
  const safeJson = async (res) => {
    try {
      return await res.json();
    } catch {
      return null; // Body wasn't valid JSON — caller treats this as "no data"
    }
  };

  const scanMessage = async () => {
    if (!message.trim()) return alert('Paste a message'); // Guard against empty/whitespace-only input
    setLoadingScan(true); // Disable the button and show the loading label
    setResult(null); // Clear any previous result so old data can't flash while the new scan runs
    try {
      const res = await fetch(`${API_URL}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ message })
      });
      if (res.status === 401) { // Token expired or invalid
        handleUnauthorized(); // Log the user out cleanly instead of leaving the UI stuck
        return;
      }
      const data = await safeJson(res); // Parse safely — never throws
      if (res.ok && data) {
        setResult(data); // Show the scan result
      } else {
        alert(data?.detail || 'Scan failed'); // Fall back to a generic message if there's no detail field
      }
    } catch {
      alert('Network error'); // Covers the fetch itself failing (offline, DNS, etc.)
    }
    setLoadingScan(false); // Always re-enable the button, success or failure
  };

  const fetchHistory = async () => {
    setLoadingHistory(true); // Disable the button while loading
    try {
      const res = await fetch(`${API_URL}/scan/history`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.status === 401) { // Token expired or invalid
        handleUnauthorized(); // Same clean logout path
        return;
      }
      const data = await safeJson(res); // Parse safely — never throws
      if (res.ok && Array.isArray(data)) {
        setHistory(data); // Only accept a real array, never partial/malformed data
      } else {
        setHistory([]); // Fail safe to an empty list rather than leaving stale data
      }
    } catch {
      setHistory([]); // Network failure — show empty rather than crashing
    }
    setLoadingHistory(false); // Always re-enable the button
  };

  if (!token) return null; // Nothing to render while we're redirecting to /login

  // Maps a scan status to a Tailwind color class in one place instead of repeating ternaries
  const statusColor = (status) => {
    if (status === 'SAFE') return 'bg-green-500';
    if (status === 'SUSPICIOUS') return 'bg-yellow-500';
    if (status === 'SCAM') return 'bg-red-500';
    return 'bg-gray-500'; // Fallback for any unexpected/unknown status value
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 to-gray-900 text-white p-4">
      <div className="max-w-3xl mx-auto bg-white/10 backdrop-blur-lg p-6 rounded-2xl shadow-2xl border border-white/10">
        <div className="flex justify-between items-center border-b border-white/10 pb-4 mb-6">
          <h1 className="text-2xl font-bold">🛡️ Faro-Detect</h1>
          <button onClick={handleLogout} className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg text-sm">Logout</button>
        </div>

        <textarea
          rows="4"
          value={message}
          onChange={(e) => setMessage(e.target.value)} // Keeps the textarea a controlled input
          placeholder="Paste suspicious message here..."
          className="w-full p-3 bg-white/10 rounded-lg border border-white/10 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
        />
        <button
          onClick={scanMessage}
          disabled={loadingScan} // Prevents double-submitting while a scan is in flight
          className="w-full mt-4 bg-blue-600 hover:bg-blue-700 py-3 rounded-lg font-bold disabled:opacity-50"
        >
          {loadingScan ? 'Scanning...' : '🔍 Scan'}
        </button>

        {result && (
          <div className="mt-6 p-4 bg-white/10 rounded-lg">
            <h3 className="font-bold mb-2">Result</h3>
            <p>Risk: <span className="text-yellow-400 font-bold">{result.risk_score}%</span></p>
            <p>Status: <span className={`inline-block px-3 py-1 rounded-full text-xs font-bold ${statusColor(result.status)}`}>{result.status}</span></p>
            <p>Category: {result.scam_category || 'N/A'}</p>
            <p>Reason: {result.reason || 'No details'}</p>
          </div>
        )}

        <button
          onClick={fetchHistory}
          disabled={loadingHistory} // Prevents piling up requests on repeated taps
          className="mt-6 text-blue-400 hover:underline text-sm disabled:opacity-50"
        >
          {loadingHistory ? 'Loading...' : '📜 History'}
        </button>
        <div className="mt-3 space-y-2 max-h-60 overflow-y-auto">
          {history.length === 0 && <p className="text-gray-400 text-sm">No scans yet</p>}
          {history.map((item) => (
            <div key={item.id ?? `${item.timestamp}-${item.message}`} className="bg-white/10 p-3 rounded-lg flex justify-between">
              <span className="truncate w-3/4">{(item.message ?? '').substring(0, 40)}...</span>
              <span className={`text-xs px-2 py-1 rounded-full ${statusColor(item.status)}`}>{item.status}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
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
    <div className="min-h-screen bg-gradient-to-br from-blue-900 to-gray-900 text-white p-4">
      <div className="max-w-3xl mx-auto bg-white/10 backdrop-blur-lg p-6 rounded-2xl shadow-2xl border border-white/10">
        <div className="flex justify-between items-center border-b border-white/10 pb-4 mb-6">
          <h1 className="text-2xl font-bold">🛡️ Faro-Detect</h1>
          <button onClick={handleLogout} className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg text-sm">Logout</button>
        </div>

        <textarea
          rows="4"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Paste suspicious message here..."
          className="w-full p-3 bg-white/10 rounded-lg border border-white/10 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
        />
        <button
          onClick={scanMessage}
          disabled={loading}
          className="w-full mt-4 bg-blue-600 hover:bg-blue-700 py-3 rounded-lg font-bold disabled:opacity-50"
        >
          {loading ? 'Scanning...' : '🔍 Scan'}
        </button>

        {result && (
          <div className="mt-6 p-4 bg-white/10 rounded-lg">
            <h3 className="font-bold mb-2">Result</h3>
            <p>Risk: <span className="text-yellow-400 font-bold">{result.risk_score}%</span></p>
            <p>Status: <span className={`inline-block px-3 py-1 rounded-full text-xs font-bold ${result.status === 'Safe' || result.status === 'SAFE' ? 'bg-green-500' : result.status === 'Warning' || result.status === 'SUSPICIOUS' ? 'bg-yellow-500' : 'bg-red-500'}`}>{result.status}</span></p>
            <p>Category: {result.scam_category || 'N/A'}</p>
            <p>Reason: {result.reason || 'No details'}</p>
          </div>
        )}

        <button onClick={fetchHistory} className="mt-6 text-blue-400 hover:underline text-sm">📜 History</button>
        <div className="mt-3 space-y-2 max-h-60 overflow-y-auto">
          {history.length === 0 && <p className="text-gray-400 text-sm">No scans yet</p>}
          {history.map((item, i) => (
            <div key={i} className="bg-white/10 p-3 rounded-lg flex justify-between">
              <span className="truncate w-3/4">{item.message.substring(0, 40)}...</span>
              <span className={`text-xs px-2 py-1 rounded-full ${item.status === 'SAFE' ? 'bg-green-600' : 'bg-red-600'}`}>{item.status}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
          }  };

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
