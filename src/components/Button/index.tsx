import React from 'react'
import styled from '@emotion/styled'

function Button({ isLink = false, children, ...rest }) {
  return (
    <StyledButton as={isLink ? 'a' : 'button'} {...rest}>
      {children}
    </StyledButton>
  )
}

const StyledButton = styled.button`
  display: inline-block;
  color: white;
  padding: 0.75em 20px;
  margin-left: -2px;
  font-weight: 600;
  background: linear-gradient(
    90deg,
    var(--ifm-color-primary) 11.3%,
    var(--ifm-color-primary-light) 161.54%
  );
  box-shadow: 0px 0px 32px rgba(0, 105, 165, 0.35);
  border-radius: 7px;
  font-family: 'Yuanti SC', 'Youyuan', 'You Yuan', '幼圆', 'PingFang SC',
    'Microsoft Yahei', Helvetica, sans-serif;

  :hover {
    color: white;
    text-decoration: none;
  }
`

export default Button
