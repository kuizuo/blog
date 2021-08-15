import React from 'react';
import classnames from 'classnames';
import Layout from '@theme/Layout';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import useBaseUrl from '@docusaurus/useBaseUrl';
import styles from './styles.module.css';

import { List, Card } from 'antd';
//import 'antd/dist/antd.css'; // or 'antd/dist/antd.less' 

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
      <div className="container-wrapper">
        <div className="container padding-vert--sm">
          <div className="row">
            <div className="col col--12">
              <List
                grid={{
                  gutter: 16,
                  xs: 1,
                  sm: 2,
                  md: 4,
                  lg: 4,
                  xl: 6,
                  xxl: 3,
                }}
                dataSource={data}
                renderItem={item => (
                  <List.Item>
                    <Card title={item.title}>Card content</Card>
                  </List.Item>
                )}
              />
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}

export default Resources;
