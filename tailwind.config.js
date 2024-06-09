/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{js,jsx,ts,tsx}'],
  darkMode: ['selector', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        background: 'var(--content-background)',
        card: 'var(--ifm-card-background-color)',
        text: 'var(--ifm-text-color)',
        secondary: 'var(--ifm-secondary-text-color)',
        link: 'var(--ifm-link-color)',
        primary: 'var(--ifm-color-primary)',
        primaryLight: 'var(--ifm-color-primary-light)',
        primaryLighter: 'var(--ifm-color-primary-lighter)',
        primaryLightest: 'var(--ifm-color-primary-lightest)',
      },
      fontFamily: {
        misans: ['misans'],
      },
      borderRadius: {
        card: 'var(--ifm-card-border-radius)',
      },
      boxShadow: {
        blog: 'var(--blog-item-shadow)',
      },
      animation: {
        marquee: 'marquee var(--duration) linear infinite',
        'marquee-vertical': 'marquee-vertical var(--duration) linear infinite',
      },
      keyframes: {
        marquee: {
          from: { transform: 'translateX(0)' },
          to: { transform: 'translateX(calc(-100% - var(--gap)))' },
        },
        'marquee-vertical': {
          from: { transform: 'translateY(0)' },
          to: { transform: 'translateY(calc(-100% - var(--gap)))' },
        },
      },
    },
  },
  corePlugins: {
    preflight: false,
  },
  plugins: [],
}
