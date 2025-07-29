/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'dragon-dark': '#0f1419',
        'dragon-card': '#1a1f2e',
        'dragon-border': '#2d3748',
        'dragon-primary': '#667eea',
        'dragon-secondary': '#764ba2',
      }
    },
  },
  plugins: [],
} 