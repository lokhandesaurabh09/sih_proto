/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      animation: {
        "glow-pulse": "glowPulse 2.2s ease-in-out infinite",
        scan: "scan 5s linear infinite",
      },
      keyframes: {
        glowPulse: {
          "0%, 100%": { boxShadow: "0 0 6px rgba(52,211,153,0.55), 0 0 16px rgba(52,211,153,0.2)" },
          "50%": { boxShadow: "0 0 14px rgba(52,211,153,0.9), 0 0 34px rgba(52,211,153,0.4)" },
        },
        scan: {
          "0%": { transform: "translateX(-120%)" },
          "100%": { transform: "translateX(320%)" },
        },
      },
    },
  },
  plugins: [],
};