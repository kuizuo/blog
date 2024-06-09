import svgToDataUri from 'mini-svg-data-uri'
import plugin from 'tailwindcss/plugin'

const {
  default: flattenColorPalette,
} = require('tailwindcss/lib/util/flattenColorPalette')

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
        border: 'var(--ifm-border-color)',
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
  plugins: [
    plugin(({ matchUtilities, theme }) => {
      matchUtilities(
        {
          'bg-grid': (value) => ({
            backgroundImage: `url("${svgToDataUri(
              `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32" fill="none" stroke="${value}"><path d="M0 .5H31.5V32"/></svg>`,
            )}")`,
          }),
        },
        {
          values: flattenColorPalette(theme('backgroundColor')),
          type: 'color',
        },
      )
    }),
  ],
}
