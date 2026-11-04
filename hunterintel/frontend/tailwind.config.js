/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        ink: { 950: "#080b10", 900: "#0b0f14", 850: "#0f141b", 800: "#131a23", 700: "#1a232f", 600: "#243140", 500: "#33445a" },
        fg: { DEFAULT: "#d8e0ea", muted: "#8e9bad", dim: "#617086" },
        accent: { DEFAULT: "#38bdf8", soft: "#0c4a6e" },
        verified: "#34d399",
        claim: "#60a5fa",
        inferred: "#fbbf24",
        danger: "#f87171",
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
