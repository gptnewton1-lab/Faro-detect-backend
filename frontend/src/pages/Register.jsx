import { useState } from 'react';
import { Link } from 'react-router-dom';

const API_URL = "https://faro-detect-api-1.onrender.com";

export default function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleRegister = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (res.ok) {
        const loginRes = await fetch(`${API_URL}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        const loginData = await loginRes.json();
        if (loginRes.ok) {
          localStorage.setItem('access_token', loginData.access_token);
          window.location.href = '/dashboard';
        } else {
          window.location.href = '/login';
        }
      } else {
        setError(data.detail || 'Registration failed');
      }
    } catch {
      setError('Server error. Is backend running?');
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
      <div className="bg-gray-800 p-8 rounded-2xl w-full max-w-md shadow-xl">
        <div className="text-center mb-6">
          <h1 className="text-3xl font-bold text-white">🛡️ Faro-Detect</h1>
          <p className="text-gray-400 text-sm mt-1">Create your account</p>
        </div>
        <form onSubmit={handleRegister} className="space-y-4">
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full p-3 bg-gray-700 rounded-lg border border-gray-600 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full p-3 bg-gray-700 rounded-lg border border-gray-600 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
            required
          />
          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 bg-blue-600 hover:bg-blue-700 rounded-lg font-semibold text-white transition disabled:opacity-50"
          >
            {loading ? 'Creating...' : 'Create Account'}
          </button>
          {error && <p className="text-red-400 text-sm text-center">{error}</p>}
        </form>
        <p className="text-center text-gray-400 text-sm mt-4">
          Already have an account? <Link to="/login" className="text-blue-400 hover:underline">Sign In</Link>
        </p>
      </div>
    </div>
  );
                                                                                                        }
