import React from 'react'
import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import Layout from '@theme/Layout'
import Head from '@docusaurus/Head'

import styles from './style.module.css'

export default function Resources() {
  return (
    <Layout title={'资源导航'} wrapperClassName='blog-list__page'>
      <Head>
        <meta name='keywords' content='前端, html, css, js, javascript, react, vue, typescript, es6, 资源' />
        <title>{'资源导航-愧怍的小站'}</title>
      </Head>

      <iframe
        src='https://nav.kuizuo.cn/'
        loading='lazy'
        scrolling='yes'
        border={0}
        frameBorder='no'
        framespacing={0}
        allowFullScreen={true}
        // style={{ width: "100%", height: "500px" }}
        className={styles.Frame}
      ></iframe>
    </Layout>
  )
}
