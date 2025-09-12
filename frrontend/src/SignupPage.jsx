import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { UserAuth } from "./context/AuthContext";

const SignupPage = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const { signUpNewUser, signInWithGoogle } = UserAuth(); // ✅ Google wala include
  const navigate = useNavigate();

  const handleSignIn = async (e) => {
    e.preventDefault();
    setLoading(true);

    const { success, error } = await signUpNewUser(email, password);

    if (!success) {
      setError(error.message || "Failed to sign up");
      setTimeout(() => setError(null), 3000);
    } else {
      navigate("/");
    }

    setLoading(false);
  };

  const handleGoogleSignIn = async () => {
    const { success, error } = await signInWithGoogle();

    if (!success) {
      setError(error || "Google sign-in failed");
      setTimeout(() => setError(null), 3000);
    }
    // Supabase Google login redirect karega automatically,
    // uspe "Redirect URL" apko Supabase project settings > Authentication me add karna hoga.
  };

  return (
    <div
        className="relative flex flex-col justify-center items-center overflow-hidden font-sans bg-cover bg-center min-h-screen min-w-full bg-no-repeat"
        style={{
          backgroundImage: `url('https://i.postimg.cc/BvLfHqf5/magical-mystical-landscape-wallpaper-purple-tones-1.jpg')`,
        }}
      >
    <div className="flex min-h-[90%] w-[85%] bg-magenta-800/90 backdrop-blur-lg rounded-2xl mt-28 mx-auto">
      {/* Left side */}
      <div className="hidden md:flex w-1/2 items-center justify-center bg-magenta-800/90 backdrop-blur-md">
  <img 
    src="https://i.postimg.cc/59rfdtkm/generated-image-6.png" 
    alt="Side Banner" 
    className="max-h-[90%] max-w-[90%] object-contain rounded-2xl" 
  />
</div>


      {/* Right side */}
      <div className="flex w-full border-l md:w-1/2 items-center justify-center p-10 min-h-[95%]">
        <div className="bg-purple/20 backdrop-blur-md shadow-2xl p-8 w-full max-w-md">
          <h2 className="text-3xl font-bold text-center text-white mb-6">
            Sign Up
          </h2>

          <form onSubmit={handleSignIn} className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-white">Email</label>
              <input
                onChange={(e) => setEmail(e.target.value)}
                type="email"
                placeholder="Enter your email"
                value={email}
                required
                className="w-full mt-1 px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-white">Password</label>
              <input
                onChange={(e) => setPassword(e.target.value)}
                type="password"
                placeholder="Enter your password"
                value={password}
                required
                className="w-full mt-1 px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-400"
              />
            </div>

            {/* ✅ Google button now functional */}
            <button
              type="button"
              onClick={handleGoogleSignIn}
              className="w-full flex items-center justify-center gap-2 bg-white/90 text-gray-800 py-2 rounded-lg hover:bg-white transition font-medium"
            >
              <img
                src="https://i.postimg.cc/Bn8j2pNG/icons8-google-logo-120.png"
                alt="Google"
                className="w-5 h-5"
              />
              Login with Google
            </button>

            {/* Submit button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-pink-500 to-purple-700 text-white px-5 py-2 rounded-lg font-medium shadow hover:scale-105 transition flex justify-center"
            >
              {loading ? "Signing Up..." : "Sign Up"}
            </button>

            {error && <p className="text-red-600 text-center pt-4">{error}</p>}
          </form>

          <p className="text-sm text-white text-center mt-6">
            Already have an account?{" "}
            <Link to="/login" className="text-blue-600 hover:underline">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
    </div>
  );
};

export default SignupPage;
