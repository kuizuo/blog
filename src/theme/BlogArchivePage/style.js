import styled, { css } from 'styled-components';

export const StyledArchivePage = styled.div`
  .row {
    justify-content: center;
    margin-top: 1rem;
    .col--10 {
      max-width: 860px;
      margin: 0 auto;
      padding: 1rem 2.5rem 1rem;

      box-shadow: 0 1px 2px 0 rgb(0 0 0 / 10%);
      margin-bottom: 1rem;
      border-radius: 2px;
      background: var(--card-background);
    }
  }

  .count {
    text-align: right;
    margin-top: -2.5rem;
    font-size: 0.85rem;
    opacity: 0.8;
  }

  ul {
    margin-top: 1rem;
  }

  li {
    list-style: none;
    > a {
      display: block;
      color: #00323c;
      transition: padding 0.3s;
      padding: 0.5rem 1rem;
      line-height: 1.2rem;
      font-weight: 500;

      text-decoration: none;
      &:hover {
        padding-left: 2.5rem;
        color: var(--ifm-color-primary);
        background: #f9f9f9;
      }
      span {
        opacity: 0.6;
        font-size: 0.85rem;
        font-weight: 400;
        margin-right: 0.3rem;
      }
    }
  }

  h3 {
    border-bottom: 1px solid rgb(0 0 0 / 15%);
    font-weight: 400;
    padding: 0 0 2px 0;
    span {
      font-size: 0.85rem;
      font-weight: 300;
      float: right;
      margin-top: 0.5rem;
    }
  }
`;
