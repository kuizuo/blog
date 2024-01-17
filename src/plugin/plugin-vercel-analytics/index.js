import { inject } from '@vercel/analytics';

export default async function vercelAnalytics(context, options) {
  return {
    name: 'vercel-analytics',
    async loadContent() {
      inject();
    },
    async contentLoaded({ content, actions }) {
    },
    /* other lifecycle API */
  };
}
