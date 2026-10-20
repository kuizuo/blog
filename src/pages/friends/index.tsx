import Link from '@docusaurus/Link'
import Translate, { translate } from '@docusaurus/Translate'
import useBrokenLinks from '@docusaurus/useBrokenLinks'
import { type Friend, Friends } from '@site/data/friends'
import collection from '@site/src/css/collection.module.css'
import CodeBlock from '@theme/CodeBlock'
import Layout from '@theme/Layout'
import { memo } from 'react'
import styles from './styles.module.css'

const TITLE = translate({ id: 'friends.title', message: '友链' })
const DESCRIPTION = translate({ id: 'friends.description', message: '有很多良友，胜于有很多财富。' })
const ADD_FRIEND_URL = 'https://github.com/kuizuo/blog/edit/main/data/friends.tsx'
const SITE_INFO = `title: '愧怍'
bio: '道阻且长，行则将至'
website: 'https://kuizuo.me'
avatar: 'https://kuizuo.me/img/logo.png'
`

function stableFriendOrder(friend: Friend): number {
  const text = `${friend.title}${friend.website}`
  let hash = 0
  for (let i = 0; i < text.length; i++) {
    hash = (hash * 31 + text.charCodeAt(i)) % 1000000007
  }
  return hash
}

const friends = [...Friends].sort((left, right) => {
  const order = stableFriendOrder(left) - stableFriendOrder(right)
  return order || left.title.localeCompare(right.title, 'en-US')
})

const FriendCard = memo(({ friend }: { friend: Friend }) => (
  <li>
    <Link to={friend.website} className={styles.friendCard}>
      <span className={styles.avatar} aria-hidden="true">
        <span>{friend.title.slice(0, 1)}</span>
        {friend.avatar && (
          <img
            src={friend.avatar}
            alt=""
            width={56}
            height={56}
            loading="lazy"
            decoding="async"
            onError={(event) => { event.currentTarget.hidden = true }}
          />
        )}
      </span>
      <span className={styles.friendInfo}>
        <span className={styles.friendTitle}>{friend.title}</span>
        <span className={styles.friendDescription}>{friend.description}</span>
      </span>
      <span className={styles.arrow} aria-hidden="true">↗</span>
    </Link>
  </li>
))

export default function FriendLink(): JSX.Element {
  useBrokenLinks().collectAnchor('exchange')

  return (
    <Layout title={TITLE} description={DESCRIPTION}>
      <main className={collection.page}>
        <div className={collection.container}>
          <header className={collection.header}>
            <div>
              <h1 className={collection.title}>{TITLE}</h1>
              <p className={collection.description}>{DESCRIPTION}</p>
            </div>
            <Link href="#exchange" className={collection.textLink}>
              <Translate id="friends.exchange">交换友链</Translate>
              <span aria-hidden="true">↓</span>
            </Link>
          </header>
          <ul className={styles.friendList}>
            {friends.map(friend => <FriendCard key={friend.website} friend={friend} />)}
          </ul>
          <section id="exchange" className={styles.exchange} aria-labelledby="exchange-title">
            <div className={styles.exchangeIntro}>
              <h2 id="exchange-title"><Translate id="friends.exchange">交换友链</Translate></h2>
              <p><Translate id="friends.exchange.description">如果你也在记录生活、分享技术，欢迎交换友链。</Translate></p>
              <Link href={ADD_FRIEND_URL} className={collection.textLink}>
                <Translate id="friends.add">在 GitHub 上添加友链</Translate>
                <span aria-hidden="true">↗</span>
              </Link>
            </div>
            <div className={styles.siteInfo}>
              <CodeBlock language="yaml" title={translate({ id: 'friends.siteInfo', message: '本站信息' })}>
                {SITE_INFO}
              </CodeBlock>
            </div>
          </section>
        </div>
      </main>
    </Layout>
  )
}
