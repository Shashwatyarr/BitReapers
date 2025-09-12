import React, { useState } from "react";
import { UserAuth } from "./context/AuthContext";
import { useNavigate } from "react-router-dom";

const Signout = () => {
  const { signOut } = UserAuth();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);

  const handleSignOut = async () => {
    try {
      setLoading(true);
      await signOut();
      navigate("/");
    } catch (err) {
      console.error("Error signing out:", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      onClick={handleSignOut}
      disabled={loading}
      className={`bg-gradient-to-r from-pink-500 to-purple-700 text-white px-5 py-2 rounded-lg font-medium shadow hover:scale-105 transition ${
        loading ? "opacity-70 cursor-not-allowed" : ""
      }`}
    >
      {loading ? "Signing out..." : "Sign-Out"}
    </button>
  );
};

export default Signout;
