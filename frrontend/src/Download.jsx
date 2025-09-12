import { motion } from "framer-motion";

const BlackSection = () => {
  return (
    <div className="min-h-screen w-full bg-black flex justify-center items-center px-10">
      <div className="flex w-full max-w-7xl">
        {/* ✅ Left Section (Texts) */}
        <div className="relative flex-1 flex justify-start items-center px-12 py-16">
          {/* Gradient Glow Behind */}
          <motion.div
            className="absolute inset-0 bg-gradient-to-br from-pink-600/30 to-purple-700/30 rounded-3xl blur-3xl"
            animate={{ scale: [1, 1.05, 1] }}
            transition={{ repeat: Infinity, duration: 6, ease: "easeInOut" }}
          ></motion.div>

          {/* Content */}
          <div className="relative z-10 max-w-xl text-left">
            {/* Title */}
            <motion.h2
              className="text-white text-4xl md:text-6xl font-bold leading-tight"
              initial={{ opacity: 0, x: -80 }}
              whileInView={{ opacity: 1, x: 0 }}
              transition={{ duration: 1.2, ease: "easeOut" }}
            >
              Protecting <br /> The Digital <br /> Earth
            </motion.h2>

            {/* Subtitle */}
            <motion.h3
              className="mt-4 text-pink-200 text-lg md:text-xl font-medium"
              initial={{ opacity: 0, y: 40 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3, duration: 1 }}
            >
              Secure & Complete Data Wiping
            </motion.h3>

            {/* Description */}
            <motion.p
              className="mt-3 text-gray-300 text-sm md:text-base leading-relaxed"
              initial={{ opacity: 0, y: 40 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5, duration: 1 }}
            >
              Just like the Earth constantly renews itself, our data wiping
              technology ensures every trace of sensitive information is
              securely erased — leaving no digital footprint behind.
            </motion.p>

            {/* Button */}
            <motion.button
              className="mt-6 bg-gradient-to-r from-pink-500 to-purple-700 text-white px-6 py-3 rounded-lg font-semibold shadow hover:scale-110 transition"
              initial={{ opacity: 0, y: 50 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.7, duration: 1 }}
              whileHover={{ scale: 1.15 }}
              whileTap={{ scale: 0.95 }}
            >
              Download BitReaper
            </motion.button>
            <motion.button
              className="mt-6 ml-3 bg-white  text-black px-6 py-3 rounded-lg font-semibold shadow hover:scale-110 transition"
              initial={{ opacity: 0, y: 50 }}
              whileInView={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.7, duration: 1 }}
              whileHover={{ scale: 1.15 }}
              whileTap={{ scale: 0.95 }}
            >
              Download Balena-Etcher
            </motion.button>
          </div>
        </div>

        {/* ✅ Right Section (Earth Image) */}
        <div className="relative flex-[1.6] flex justify-center items-center">
          {/* 🌌 Gradient Aura Behind Earth */}
          <motion.div
            className="absolute w-[500px] h-[500px] rounded-full bg-gradient-to-tr from-pink-500/40 to-purple-600/40 blur-3xl"
            animate={{ scale: [1, 1.1, 1] }}
            transition={{ repeat: Infinity, duration: 6, ease: "easeInOut" }}
          ></motion.div>

          {/* ✨ White Glow on Top */}
          <div className="absolute top-[-50px] w-[250px] h-[250px] rounded-full bg-white/30 blur-2xl"></div>

          {/* 🌍 Rotating Earth */}
          <motion.img
            src="https://i.postimg.cc/xCw7KH3n/Pngtree-colorful-3d-globe-representation-20343863.png"
            alt="Earth"
            className="relative w-4/5 h-auto z-10 rounded-full shadow-lg"
            whileInView={{ opacity: 1, scale: 1 }}
            transition={{ duration: 1.5, ease: "easeOut" ,repeat: Infinity, duration: 60}}
            animate={{ rotate: 360 }}
          />
        </div>
      </div>
    </div>
  );
};

export default BlackSection;
