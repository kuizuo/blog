import { inject } from '@vercel/analytics';

export default async function vercelAnalytics(context, options) {
  return {
    name: 'docusaurus-plugin-vercel-analytics',
    injectHtmlTags() {
      if (process.env.NODE_ENV === 'development') {
        return {}
      }

      return {
        headTags: [
          {
            tagName: 'script',
            innerHTML: `
            window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };
           `,
          },
          { tagName: 'script', defer: true, src: '/_vercel/insights/script.js' },
        ],
      }
    },
  };
}
