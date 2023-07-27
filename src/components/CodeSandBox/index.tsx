import React from 'react'
import { useColorMode } from '@docusaurus/theme-common'

function index({ slug, title, height = '600px' }) {
  const { isDarkTheme } = useColorMode()
  const themedSrc = `https://codesandbox.io/embed/${slug}?fontsize=14&hidenavigation=1&view=preview&theme=${
    isDarkTheme ? 'dark' : 'light'
  }`
  return (
    <div>
      <iframe
        src={themedSrc}
        style={{
          width: '100%',
          height,
          border: 0,
          borderRadius: '4px',
          overflow: 'hidden',
        }}
        title={title}
        allow="accelerometer; ambient-light-sensor; camera; encrypted-media; geolocation; gyroscope; hid; microphone; midi; payment; usb; vr; xr-spatial-tracking"
        sandbox="allow-forms allow-modals allow-popups allow-presentation allow-same-origin allow-scripts"
      ></iframe>
    </div>
  )
}

export default index
