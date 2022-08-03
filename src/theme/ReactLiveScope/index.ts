import React from 'react';
import styled from '@emotion/styled';
import {css} from '@emotion/react';
import * as components from './components';

// Add react-live imports you need here
const ReactLiveScope = {
  React,
  ...React,
  styled,
  css,
  ...components,
};

export default ReactLiveScope;
