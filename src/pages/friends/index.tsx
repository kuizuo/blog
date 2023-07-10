import React from 'react'
import Layout from '@theme/Layout'
import CodeBlock from '@theme/CodeBlock'

import FriendCard from './_components/FriendCard'
import { Friends, type Friend } from '@site/data/friend'

import styles from './styles.module.css'

const TITLE = '友链'
const DESCRIPTION = '请点击下方按钮申请友链，熟人可直接找我~'
const ADD_FRIEND_URL = 'https://github.com/kuizuo/blog/edit/main/data/friend.ts'

function FriendHeader() {
  return (
    <section className="margin-top--lg margin-bottom--lg text--center">
      <h1>{TITLE}</h1>
      <p>{DESCRIPTION}</p>
      <div className={styles.siteInfo}>
        <CodeBlock language="jsx">
          {`{
  // 本站信息
  title: '愧怍的小站',
  description: '道阻且长，行则将至',
  avatar: 'https://kuizuo.cn/img/logo.png'
}`}
        </CodeBlock>
      </div>
      <a
        className="button button--primary"
        href={ADD_FRIEND_URL}
        target="_blank"
        rel="noreferrer"
      >
        🔗 申请友链
      </a>
    </section>
  )
}

function FriendCards() {
  const friends = Friends
  return (
    <section className="margin-top--lg margin-bottom--lg">
      <div className="container">
        <ul className={styles.showcaseList}>
          {friends.map(friend => (
            <FriendCard key={friend.avatar} friend={friend} />
          ))}
        </ul>
      </div>
    </section>
  )
}

function FriendLink(): JSX.Element {
  return (
    <Layout title={TITLE} description={DESCRIPTION}>
      <main className="margin-vert--lg">
        <FriendHeader />
        <FriendCards />
      </main>
    </Layout>
  )
}

export default FriendLink
