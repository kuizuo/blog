import { css } from '@emotion/react'

export default function Shadow() {
  const ShadowStyle = css`
    .wrapper {
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .mr-2 {
      margin-right: 2em;
    }

    .mb-1 {
      margin-bottom: 1em;
    }

    .text-center {
      text-align: center;
    }

    .box-shadow {
      box-shadow: 2px 4px 8px #585858;
    }

    .drop-shadow {
      filter: drop-shadow(2px 4px 8px #585858);
    }
  `

  return (
    <div css={ShadowStyle}>
      <div className='wrapper'>
        <div className='mr-2'>
          <div className='mb-1 text-center'>box-shadow</div>
          <img className='box-shadow' src='https://markodenic.com/man_working.png' alt='Image with box-shadow' />
        </div>

        <div>
          <div className='mb-1 text-center'>drop-shadow</div>
          <img className='drop-shadow' src='https://markodenic.com/man_working.png' alt='Image with drop-shadow' />
        </div>
      </div>
    </div>
  )
}
