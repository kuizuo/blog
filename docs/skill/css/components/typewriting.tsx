import React, { useState } from 'react'
import { css } from '@emotion/react'

export default function Typewriting() {
  const TypewritingStyle = css`
  .wrapper {
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .typing-demo {
    width: 24ch;
    animation: typing 2s steps(22), blink 0.5s step-end infinite alternate;
    white-space: nowrap;
    overflow: hidden;
    border-right: 3px solid;
    font-family: monospace;
    font-size: 2em;
  }

  @keyframes typing {
    from {
      width: 0;
    }
  }

  @keyframes blink {
    50% {
      border-color: transparent;
    }
  }
`
  return (
    <div css={TypewritingStyle}>
      <div className='wrapper'>
        <div className='typing-demo'>有趣且实用的 CSS 小技巧</div>
      </div>
    </div>
  )
}
