/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      fontFamily: {
        display: ["Manrope", "ui-sans-serif", "system-ui"],
        mono: ["IBM Plex Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      colors: {
        slate: {
          50: "#fafafa",
          100: "#f4f4f5",
          200: "#e4e4e7",
          300: "#d4d4d8",
          400: "#a1a1aa",
          500: "#71717a",
          600: "#52525b",
          700: "#3f3f46",
          800: "#27272a",
          900: "#141416",
          950: "#080809",
        },
        mva: {
          cyan: "#22d3ee",
          green: "#10b981",
          lime: "#84cc16",
          amber: "#f59e0b",
          red: "#ef4444",
        },
      },
      boxShadow: {
        cyber: "0 24px 90px rgba(0, 0, 0, 0.62)",
        glow: "0 0 34px rgba(220, 38, 38, 0.25)",
      },
      backgroundImage: {
        "cyber-grid":
          "linear-gradient(rgba(239,68,68,.07) 1px, transparent 1px), linear-gradient(90deg, rgba(239,68,68,.07) 1px, transparent 1px)",
      },
    },
  },
  plugins: [],
};
