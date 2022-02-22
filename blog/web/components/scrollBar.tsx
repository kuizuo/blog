import { css } from '@emotion/react'

export default function ScrollBar() {
  const ScrollBarStyle = css`
    .wrapper {
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .tile {
      overflow: auto;
      display: inline-block;
      background-color: #ccc;
      height: 200px;
      width: 200px;
    }

    
    .tile-content {
      padding: 20px;
      height: 500px;
    }

    .tile-scrollbar::-webkit-scrollbar {
      width: 12px;
      background-color: #eff1f5;
    }

    .tile-scrollbar::-webkit-scrollbar-track {
      border-radius: 3px;
      background-color: transparent;
    }

    .tile-scrollbar::-webkit-scrollbar-thumb {
      border-radius: 5px;
      background-color: #515769;
      border: 2px solid #eff1f5;
    }
  `

  return (
    <div css={ScrollBarStyle}>
      <div className='wrapper'>
        <div className='tile tile-scrollbar'>
          <div className='tile-content'>自定义滚动条</div>
        </div>
      </div>
    </div>
  )
}
