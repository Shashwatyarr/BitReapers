import React from "react";
import { motion } from "framer-motion";

const Home = () => {
    const words = [
    "Security", "Reliability", "Trust", "Safety", "Integrity",
    "Resilience", "Stability", "Confidence", "Assurance", "Protection",
    "Transparency", "Dependability", "Support", "Consistency", "Loyalty",
    "Privacy", "Strength", "Accountability", "Clarity", "Authenticity"
  ];
  return (
    <>
      {/* 🔹 First Section (App.jsx background wali image) */}
      <div
        className="relative flex flex-col justify-center items-center overflow-hidden font-sans bg-cover bg-center min-h-screen min-w-full bg-no-repeat"
        style={{
          backgroundImage: `url('https://i.postimg.cc/BvLfHqf5/magical-mystical-landscape-wallpaper-purple-tones-1.jpg')`,
        }}
      >
        <section className="flex flex-col justify-center items-center w-full mb-10">
          {/* Animated Heading */}
          <motion.h1
            className="text-white text-center text-5xl md:text-7xl font-bold tracking-tight drop-shadow-md"
            initial={{ opacity: 0, y: -50 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 1, ease: "easeOut" }}
          >
           Your Data Lives On.... <br /> Until We Wipe It
          </motion.h1>

          {/* Animated Subtext */}
          <motion.p
            className="text-gray-200 mt-4 mb-8 text-xl text-center max-w-xl"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5, duration: 1 }}
          >
           Cross-Platform secure wiping, Cryptographic Proof, and Eco-firendly IT disposal.
          </motion.p>

          {/* Animated Buttons */}
          <motion.div
            className="flex gap-4"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 1, duration: 0.7 }}
          >
            <button className="bg-gradient-to-r from-pink-500 to-purple-700 text-white px-6 py-3 rounded-lg font-semibold shadow hover:scale-105 transition">
              Get Started
            </button>
            <button className="border-2 border-white text-white px-6 py-3 rounded-lg font-semibold shadow hover:bg-white hover:text-black transition">
              Learn More
            </button>
          </motion.div>
        </section>

        {/* Dashboard Widgets Example */}
        <motion.div
          className="absolute right-10 top-1/2 flex flex-col gap-6"
          initial={{ opacity: 0, x: 100 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 1.2, duration: 1 }}
        >
          <div className="bg-white/10 backdrop-blur-sm rounded-2xl p-4 text-white shadow-lg w-48">
            <p className="text-sm opacity-70">Recent project</p>
            <p className="font-bold text-3xl mt-2">47%</p>
            <p className="text-xs mt-1 opacity-60">Success level</p>
          </div>
        </motion.div>
      </div>

      {/* 🔹 Second Section (Black Background) */}
       <div className="w-full overflow-hidden">
      <div className="w-full overflow-hidden">
      <div
        className="relative w-full py-4"
        style={{
          background: "linear-gradient(90deg, #ff0099, #7b2ff7)" // pink → purple
        }}
      >
        {/* Infinite Scrolling Text */}
        <motion.div
          className="flex whitespace-nowrap text-white text-lg font-semibold"
          animate={{ x: ["0%", "-100%"] }}
          transition={{ repeat: Infinity, duration: 20, ease: "linear" }}
        >
          {/* First set of words */}
          {words.map((word, i) => (
            <span key={i} className="flex items-center mr-10">
              <span className="text-xl mr-2">•</span> {word}
            </span>
          ))}

          {/* Duplicate set to remove empty gap */}
          {words.map((word, i) => (
            <span key={`dup-${i}`} className="flex items-center mr-10">
              <span className="text-xl mr-2">•</span> {word}
            </span>
          ))}
        </motion.div>
      </div>
    </div>
    </div>
      <div className="min-h-screen w-full bg-black flex justify-center items-center px-10">
  <div className="flex w-full max-w-7xl">
    {/* ✅ Left Section */}

    <div className="relative flex-1 flex justify-start items-center px-12 py-16">
      {/* Pink Gradient Behind */}
      <div className="absolute inset-0 bg-gradient-to-br from-pink-600/40 to-purple-700/40 rounded-3xl blur-3xl"></div>

      {/* Content */}
      <div className="relative z-10 max-w-xl text-left">
        {/* Main Title */}
        <motion.h2
          className="text-white text-4xl md:text-6xl font-bold leading-tight"
          initial={{ opacity: 0, x: -50 }}
          whileInView={{ opacity: 1, x: 0 }}
          transition={{ duration: 1 }}
        >
          Happily <br /> Serving <br /> Customers
        </motion.h2>

        {/* Subtitle */}
        <motion.h3
          className="mt-4 text-pink-200 text-lg md:text-xl font-medium"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3, duration: 1 }}
        >
          Secure & Complete Data Wiping
        </motion.h3>

        {/* Description */}
        <motion.p
          className="mt-3 text-gray-300 text-sm md:text-base leading-relaxed"
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5, duration: 1 }}
        >
          Our solution ensures every bit of your sensitive information is wiped
          clean beyond recovery. With industry-leading methods, we provide
          security, reliability, and peace of mind — whether you’re an
          individual or a large enterprise.
        </motion.p>

        {/* Gradient Button */}
        <motion.button
          className="mt-6 bg-gradient-to-r from-pink-500 to-purple-700 text-white px-6 py-3 rounded-lg font-semibold shadow hover:scale-105 transition"
          initial={{ opacity: 0, y: 40 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7, duration: 1 }}
        >
          Learn More
        </motion.button>
      </div>
    </div>;


    {/* ✅ Right Section */}
    <div className="relative flex-[1.6] flex justify-center items-center">
      {/* Pink Gradient Behind (200px lower) */}
      <div className="absolute inset-0 translate-y-[200px] bg-gradient-to-tr from-pink-500/40 to-purple-600/40 rounded-3xl blur-3xl"></div>

      {/* Image */}
      <motion.img
        src="https://i.postimg.cc/wT2Q9gNV/Pngtree-pink-twisted-organic-object-abstract-5428837.png"
        alt="Abstract Shape"
        className="relative w-4/5 h-auto z-10"
        initial={{ opacity: 0, x: 50 }}
        whileInView={{ opacity: 1, x: 0 }}
        transition={{ duration: 1 }}
      />
    </div>
  </div>
</div>
{/* {Third Section} */}
{/* 🔹 Mirrored Section (without tape) */}
<div className="min-h-screen w-full bg-black flex justify-center items-center px-10">
  <div className="flex w-full max-w-7xl">
    
    {/* ✅ Left Section (Image Now) */}
    <div className="relative flex-[1.6] flex justify-center items-center">
      {/* Pink Gradient Behind (200px lower) */}
      <div className="absolute inset-0 translate-y-[200px] bg-gradient-to-tr from-pink-500/40 to-purple-600/40 rounded-3xl blur-3xl"></div>

      {/* Image */}
      <motion.img
        src="https://i.postimg.cc/fW2YPBQ2/Pngtree-3d-rotating-abstract-object-stereo-5428828.png"
        alt="Abstract Shape"
        className="relative w-4/5 h-auto z-10"
        initial={{ opacity: 0, x: -50 }}
        whileInView={{ opacity: 1, x: 0 }}
        transition={{ duration: 1 }}
      />
    </div>

    {/* ✅ Right Section (Text Now) */}
    <div className="relative flex-1 flex justify-end items-center px-12 py-16">
      {/* Pink Gradient Behind */}
      <div className="absolute inset-0 bg-gradient-to-bl from-pink-600/40 to-purple-700/40 rounded-3xl blur-3xl"></div>

      {/* Content */}
      <div className="relative z-10 max-w-xl text-right">
        {/* Main Title */}
        <motion.h2
          className="text-white text-4xl md:text-6xl font-bold leading-tight"
          initial={{ opacity: 0, x: 50 }}
          whileInView={{ opacity: 1, x: 0 }}
          transition={{ duration: 1 }}
        >
          Empowering <br /> Digital <br /> Security
        </motion.h2>

        {/* Subtitle */}
        <motion.h3
          className="mt-4 text-pink-200 text-lg md:text-xl font-medium"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3, duration: 1 }}
        >
          Trusted & Reliable Solutions
        </motion.h3>

        {/* Description */}
        <motion.p
          className="mt-3 text-gray-300 text-sm md:text-base leading-relaxed"
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5, duration: 1 }}
        >
          We deliver advanced data protection, privacy, and resilience —
          ensuring your digital assets are safeguarded at every step. Our
          expertise enables you to operate with confidence in an evolving
          digital world.
        </motion.p>

        {/* Gradient Button */}
        <motion.button
          className="mt-6 bg-gradient-to-r from-pink-500 to-purple-700 text-white px-6 py-3 rounded-lg font-semibold shadow hover:scale-105 transition"
          initial={{ opacity: 0, y: 40 }}
          whileInView={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7, duration: 1 }}
        >
          Explore More
        </motion.button>
      </div>
    </div>
  </div>
</div>

    </>
  );
};

export default Home;
