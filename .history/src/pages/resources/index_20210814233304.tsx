import React from 'react';

import Layout from '@theme/Layout';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

import styles from './styles.module.css';

import { List, Card } from 'antd';
import 'antd/dist/antd.css'; // or 'antd/dist/antd.less' 

function Resources() {
  const context = useDocusaurusContext();
  const { siteConfig = {} } = context;
  const data = [
    {
      title: 'Title 1',
    },
    {
      title: 'Title 2',
    },
    {
      title: 'Title 3',
    },
    {
      title: 'Title 4',
    },
    {
      title: 'Title 5',
    },
    {
      title: 'Title 6',
    },
  ];

  return (
    <Layout
      title={`Hello from ${siteConfig.title}`}
      description="Description will go into a meta tag in <head />">
      
    </Layout>
  );
}

export default Resources;
