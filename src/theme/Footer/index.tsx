import React from 'react'
import Footer from '@theme-original/Footer'
import { Analytics } from '@vercel/analytics/react'

export default function FooterWrapper(props) {
  return (
    <>
      <Footer {...props} />
      <Analytics />
    </>
  )
}
