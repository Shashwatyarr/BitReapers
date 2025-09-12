// App.jsx
import React from "react";
import { Route,Router, Routes } from "react-router-dom";
import { Navigate } from "react-router-dom";

import bgImage from "./assets/image (1).png"
import Navbar from "./Navbar";
import Home from "./home";
import LoginPage from "./LoginPage";
import SignupPage from "./SignupPage";
import Signout from "./Signout";
import Footer from "./footer";
import Download from "./Download";
import { UserAuth } from "./context/AuthContext";

export default function App() {
  const session=UserAuth();
  return (
    <>
    <div
  className="relative flex flex-col justify-center items-center overflow-hidden font-sans bg-contain bg-center bg-no-repeat min-h-screen bg-black"
  style={{
    backgroundImage: `url('https://i.postimg.cc/x87FdHQY/generated-image-3.png')`,
  }}
>

    <Navbar/>
      <Routes>
        <Route path="/" element=<Home/>/>
        <Route path="/login" element=<LoginPage/>/>
        <Route path="/signup" element=<SignupPage/>/>
        <Route path="/signout" element=<Signout/>/>
        <Route path="/download" element={session?<Download/>:<LoginPage/>}/>
        <Route path="*" element={<Navigate to="/"/>}/>
      </Routes>
    </div>
      <Footer/>
      </>
  );
}
