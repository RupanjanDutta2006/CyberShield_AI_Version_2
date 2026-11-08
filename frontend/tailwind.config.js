/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#0a0d14',
          card: '#111726',
          border: '#1e293b',
          accent: '#06b6d4',
          cyan: '#22d3ee',
          violet: '#8b5cf6',
          danger: '#ef4444',
          warning: '#f59e0b',
          success: '#10b981',
          muted: '#64748b'
        }
      }
    },
  },
  plugins: [],
}
