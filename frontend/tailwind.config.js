/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#05070a',
          surface: '#0b0f17',
          card: '#101726',
          border: '#1b253b',
          muted: '#64748b',
          text: '#e2e8f0',
        },
        risk: {
          low: '#10b981',       // Green 0-25
          medium: '#eab308',    // Yellow 26-50
          high: '#f97316',      // Orange 51-75
          critical: '#ef4444',  // Red 76-100
        },
        cyber: {
          blue: '#00f0ff',
          green: '#00ff66',
          amber: '#ffaa00',
          red: '#ff003c',
          purple: '#a855f7',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-fast': 'pulse 1s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(0, 240, 255, 0.2)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 240, 255, 0.6)' },
        }
      }
    },
  },
  plugins: [],
}

