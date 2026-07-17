import { useState } from 'react'; // Local state for the form fields, error, and loading flag
import { Link } from 'react-router-dom'; // Client-side link to the login page

const API_URL = "https://faro-detect-api-1.onrender.com"; // Base URL of the deployed backend

export default function Register() {
  const [email, setEmail] = useState(''); // Controlled input value for email
  const [password, setPassword] = useState(''); // Controlled input value for password
  const [error, setError] = useState(''); // Holds any registration error message to show the user
  const [loading, setLoading] = useState(false); // Disables the button and swaps its label while registering

  const handleRegister = async (e) => {
    e.preventDefault(); // Stops the browser doing a full page reload on submit
    setLoading(true); // Show "Creating account..." and disable the button
    setError(''); // Clear any previous error before trying again
    try {
      const res = await fetch(`${API_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }, // /auth/register takes plain JSON, this part was correct
        body: JSON.stringify({ email, password })
      });
      const data = await res.json(); // Parse the registration response body
      if (res.ok) {
        // FIX: the backend's /auth/login endpoint expects form-encoded data (OAuth2PasswordRequestForm),
        // not JSON — sending JSON here would make auto-login silently fail after every successful signup.
        const formBody = new URLSearchParams();
        formBody.append('username', email); // Backend reads the email from "username" by OAuth2 convention
        formBody.append('password', password);
        const loginRes = await fetch(`${API_URL}/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, // Must match the encoding used above
          body: formBody
        });
        const loginData = await loginRes.json(); // Parse the login response body
        if (loginRes.ok) {
          localStorage.setItem('access_token', loginData.access_token); // Save the token for authenticated requests
          window.location.href = '/dashboard'; // Straight into the app since registration + login both succeeded
        } else {
          window.location.href = '/login'; // Registered fine, but auto-login failed — let them log in manually
        }
      } else {
        setError(data.detail || 'Registration failed'); // Show the backend's error detail, or a generic fallback
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
          <p className="text-gray-300 text-sm mt-1">Create your account</p>
        </div>
        <form onSubmit={handleRegister} className="space-y-4">
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
