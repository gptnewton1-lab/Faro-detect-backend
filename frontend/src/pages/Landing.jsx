import { Link } from 'react-router-dom';

export default function Landing() {
  return (
    <div className="min-h-screen bg-gray-900 text-white flex flex-col items-center justify-center p-6">
      <h1 className="text-5xl font-bold">🛡️ Faro-Detect</h1>
      <p className="text-xl text-gray-400 mt-2">Cameroon's Scam Detector</p>
      <div className="mt-6 flex gap-4">
        <Link to="/register" className="bg-blue-600 hover:bg-blue-700 px-6 py-3 rounded-lg font-semibold">Get Started</Link>
        <Link to="/login" className="bg-gray-700 hover:bg-gray-600 px-6 py-3 rounded-lg font-semibold">Sign In</Link>
      </div>
    </div>
  );
}
