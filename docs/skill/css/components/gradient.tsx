import { css } from '@emotion/react'

export default function Gradient() {
  const GradientStyle = css`
    .gradient-border {
      border: solid 5px transparent;
      border-radius: 10px;
      background-image: linear-gradient(white, white), linear-gradient( 135deg, #81FFEF 10%, #F067B4 100%);;
      background-origin: border-box;
      background-clip: content-box, border-box;
    }

    .box {
      margin: 0 auto;
      width: 150px;
      height: 100px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
  `

  return (
    <div css={GradientStyle}>
      <div className='box gradient-border'>炫酷渐变边框</div>
    </div>
  )
}
