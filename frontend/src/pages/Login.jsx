import { useState } from 'react'; // Local state for the form fields, error, and loading flag
import { Link } from 'react-router-dom'; // Client-side link to the register page

const API_URL = "https://faro-detect-api-1.onrender.com"; // Base URL of the deployed backend

export default function Login() {
  const [email, setEmail] = useState(''); // Controlled input value for email
  const [password, setPassword] = useState(''); // Controlled input value for password
  const [error, setError] = useState(''); // Holds any login error message to show the user
  const [loading, setLoading] = useState(false); // Disables the button and swaps its label while logging in

  const handleLogin = async (e) => {
    e.preventDefault(); // Stops the browser doing a full page reload on submit
    setLoading(true); // Show "Signing in..." and disable the button
    setError(''); // Clear any previous error before trying again
    try {
      const res = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }) // Note: backend's OAuth2PasswordRequestForm expects form-encoded "username"/"password", see note below
      });
      const data = await res.json(); // Parse the JSON response body
      if (res.ok) {
        localStorage.setItem('access_token', data.access_token); // Save the token for future authenticated requests
        window.location.href = '/dashboard'; // Send the user to the dashboard on success
      } else {
        setError(data.detail || 'Login failed'); // Show the backend's error detail, or a generic fallback
      }
    } catch {
      setError('Server error. Is backend running?'); // Covers network failure / server unreachable
    }
    setLoading(false); // Always re-enable the button, success or failure
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 to-gray-900 flex items-center justify-center p-4">
      <div className="bg-white/10 backdrop-blur-lg p-8 rounded-2xl w-full max-w-md shadow-2xl border border-white/10">
        <div className="text-center mb-6">
          <h1 className="text-4xl font-bold text-white">🛡️ Faro-Detect</h1>
          <p className="text-gray-300 text-sm mt-1">Sign in to your account</p>
        </div>
        <form onSubmit={handleLogin} className="space-y-4">
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full p-3 bg-white/10 rounded-lg border border-white/10 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full p-3 bg-white/10 rounded-lg border border-white/10 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
            required
          />
          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 bg-blue-600 hover:bg-blue-700 rounded-lg font-semibold text-white transition disabled:opacity-50"
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
          {error && <p className="text-red-400 text-sm text-center">{error}</p>}
        </form>
        <p className="text-center text-gray-400 text-sm mt-4">
          Don't have an account? <Link to="/register" className="text-blue-400 hover:underline">Register</Link>
        </p>
      </div>
    </div>
  );
}
      <div className="bg-white/10 backdrop-blur-lg p-8 rounded-2xl w-full max-w-md shadow-2xl border border-white/10">
        <div className="text-center mb-6">
          <h1 className="text-4xl font-bold text-white">🛡️ Faro-Detect</h1>
          <p className="text-gray-300 text-sm mt-1">Sign in to your account</p>
        </div>
        <form onSubmit={handleLogin} className="space-y-4">
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full p-3 bg-white/10 rounded-lg border border-white/10 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full p-3 bg-white/10 rounded-lg border border-white/10 text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
            required
          />
          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 bg-blue-600 hover:bg-blue-700 rounded-lg font-semibold text-white transition disabled:opacity-50"
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
          {error && <p className="text-red-400 text-sm text-center">{error}</p>}
        </form>
        <p className="text-center text-gray-400 text-sm mt-4">
          Don't have an account? <Link to="/register" className="text-blue-400 hover:underline">Register</Link>
        </p>
      </div>
    </div>
  );
}    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
      <div className="bg-gray-800 p-8 rounded-2xl w-full max-w-md shadow-xl">
        <div className="text-center mb-6">
          <h1 className="text-3xl font-bold text-white">🛡️ Faro-Detect</h1>
          <p className="text-gray-400 text-sm mt-1">Sign in to your account</p>
        </div>
        <form onSubmit={handleLogin} className="space-y-4">
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
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
          {error && <p className="text-red-400 text-sm text-center">{error}</p>}
        </form>
        <p className="text-center text-gray-400 text-sm mt-4">
          Don't have an account? <Link to="/register" className="text-blue-400 hover:underline">Register</Link>
        </p>
      </div>
    </div>
  );
}
