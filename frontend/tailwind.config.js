/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "#EEF4FB",
        ink: { DEFAULT: "#14223B", soft: "#3D4963", faint: "#5F6B84" },
        signal: { DEFAULT: "#2F6BFF", soft: "#E3ECFF" },
        sev: { low: "#1F9E8F", medium: "#D99A0B", high: "#E0631A", critical: "#D1366B" },
        phase: { connect: "#5B8DEF", auth: "#9B6BF2", shell: "#E0631A", close: "#8592AA" },
      },
      fontFamily: {
        display: ['"Sora"', "ui-sans-serif", "system-ui", "sans-serif"],
        sans: ['"Plus Jakarta Sans"', "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        glass: "0 1px 0 rgba(255,255,255,.9) inset, 0 12px 32px -12px rgba(40,72,140,.22), 0 2px 6px -2px rgba(40,72,140,.10)",
        lift: "0 1px 0 rgba(255,255,255,.9) inset, 0 22px 44px -14px rgba(40,72,140,.30)",
        soft: "6px 6px 14px rgba(163,181,214,.55), -6px -6px 14px rgba(255,255,255,.95)",
        pressed: "inset 4px 4px 9px rgba(163,181,214,.6), inset -4px -4px 9px rgba(255,255,255,.95)",
      },
    },
  },
  plugins: [],
};
