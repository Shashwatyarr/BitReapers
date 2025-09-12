import React from 'react'
import { Link } from 'react-router-dom'
import { UserAuth } from './context/AuthContext'
import Signout from './Signout';
const Navbar = () => {

    const {session}=UserAuth();
  return (
    <nav className="fixed top-0 left-0 w-full flex justify-between items-center pr-2 pl-10 py-4 backdrop-blur-sm z-50">
      
      <span className="flex items-center text-white font-bold text-xl space-x-2">
  <img 
    src="https://i.postimg.cc/59rfdtkm/generated-image-6.png" 
    alt="Side Banner" 
    className="h-[60px] w-[60px] rounded-2xl"
  />
  <span className='text-xl'>BitReaper</span>
</span>

      <ul className="flex gap-6 text-gray-100/80 ml-10">
        <li>
          <Link
            to="/"
            className="px-3 py-1 rounded-2xl border border-transparent hover:border-white hover:bg-white/20 transition-colors"
          >
            Home
          </Link>
        </li>
        <li>
          <Link
            to="/download"
            className="px-3 py-1 rounded-2xl border border-transparent hover:border-white hover:bg-white/20 transition-colors"
          >
            Products
          </Link>
        </li>
        <li>
          <Link
            to="/download"
            className="px-3 py-1 rounded-2xl border border-transparent hover:border-white hover:bg-white/20 transition-colors"
          >
            Resources
          </Link>
        </li>
        <li>
          <Link
            to="/about"
            className="px-3 py-1 rounded-2xl border border-transparent hover:border-white hover:bg-white/20 transition-colors"
          >
            About Us
          </Link>
        </li>
      </ul>
      <div className="flex gap-2">
  {session ? (
    <Signout />
  ) : (
    <Link
      to="/login"
      className="bg-gradient-to-r from-pink-500 to-purple-700 text-white px-5 py-2 rounded-lg font-medium shadow hover:scale-105 transition"
    >
      Register
    </Link>
  )}

  <Link
    to="/download"
    className="bg-white text-black px-5 py-2 rounded-lg font-medium shadow hover:scale-105 transition"
  >
    Download
  </Link>
</div>

    </nav>
  )
}

export default Navbar
