import React from "react";
import { Link, useNavigate } from "react-router-dom";

const Footer = () => {
  const navigate = useNavigate();

  return (
    <footer className="bg-[#120B0D] text-gray-300 py-10">
      <div className="container mx-auto px-6 md:px-12 grid grid-cols-1 md:grid-cols-3 gap-10">
        {/* Brand / About */}
        <div>
          <h2 className="text-2xl font-bold text-white mb-4">MyWebsite</h2>
          <p className="text-sm leading-6">
            A modern platform built with ❤️ to deliver the best experience for
            our users. Stay connected and explore more with us.
          </p>
        </div>

        {/* Links */}
        <div>
          <h3 className="text-lg font-semibold text-white mb-4">Quick Links</h3>
          <ul className="space-y-3">
            <li>
              <Link to="/" className="hover:text-pink-400 transition">
                Home
              </Link>
            </li>
            <li>
              <Link to="/about" className="hover:text-pink-400 transition">
                About
              </Link>
            </li>
            <li>
              <Link to="/services" className="hover:text-pink-400 transition">
                Services
              </Link>
            </li>
            <li>
              <Link to="/contact" className="hover:text-pink-400 transition">
                Contact
              </Link>
            </li>
          </ul>
        </div>

        {/* Socials */}
        <div>
          <h3 className="text-lg font-semibold text-white mb-4">Follow Us</h3>
          <div className="flex gap-5">
            <button
              onClick={() => navigate("/facebook")}
              className="hover:text-pink-400 transition"
            >
              🌐
            </button>
            <button
              onClick={() => navigate("/twitter")}
              className="hover:text-pink-400 transition"
            >
              🐦
            </button>
            <button
              onClick={() => navigate("/instagram")}
              className="hover:text-pink-400 transition"
            >
              📸
            </button>
            <button
              onClick={() => navigate("/linkedin")}
              className="hover:text-pink-400 transition"
            >
              💼
            </button>
          </div>
        </div>
      </div>

      {/* Bottom line */}
      <div className="mt-10 border-t border-gray-600 pt-6 text-center text-sm text-gray-400">
        © {new Date().getFullYear()} MyWebsite. All rights reserved.
      </div>
    </footer>
  );
};

export default Footer;
