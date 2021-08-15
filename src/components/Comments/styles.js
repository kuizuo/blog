import styled, { css } from "styled-components";

export const LeaveComment = styled.button``;

export const StyledComments = styled.div`
  display: grid;
  row-gap: 4em;
`;

export const StyledCommentItem = styled.div`
  display: grid;
  grid-template-areas:
    "avatar nickname"
    "avatar time"
    "avatar content";
  grid-template-columns: 64px 1fr;
  column-gap: 1em;

  ${({ isReply }) =>
    isReply &&
    css`
      margin-left: 4em;
    `}
`;

export const Avatar = styled.img`
  grid-area: avatar;
  width: 64px;
  height: 64px;
  border-radius: 50%;
`;

export const NickName = styled.div`
  grid-area: nickname;
  font-size: 1.25rem;
  color: var(--ifm-color-primary);
`;

export const Time = styled.div`
  grid-area: time;
  color: #adb2ba;
`;

export const Content = styled.div`
  grid-area: content;
  margin-top: 1em;
  word-break: break-all;
`;
