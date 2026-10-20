import Link from '@docusaurus/Link'
import Translate, { translate } from '@docusaurus/Translate'
import useBrokenLinks from '@docusaurus/useBrokenLinks'
import Comment from '@site/src/components/Comment'
import collection from '@site/src/css/collection.module.css'
import BackToTopButton from '@theme/BackToTopButton'
import Layout from '@theme/Layout'
import MDXContent from '@theme/MDXContent'
import AboutContent from './_content.mdx'
import styles from './styles.module.css'

export default function About(): JSX.Element {
  useBrokenLinks().collectAnchor('about-comments')

  return (
    <Layout
      title={translate({ id: 'about.title', message: '自我介绍' })}
      description={translate({ id: 'about.description', message: '愧怍的自我介绍' })}
    >
      <main className={collection.page}>
        <div className={`${collection.container} ${styles.container}`}>
          <header className={`${collection.header} ${styles.header}`}>
            <div>
              <p className={styles.eyebrow}><Translate id="about.label">关于我</Translate></p>
              <h1 className={collection.title}><Translate id="about.greeting">你好👋，我是愧怍。</Translate></h1>
              <p className={collection.description}>
                <Translate id="about.identity">全网同名愧怍（Kuizuo）</Translate>
                <span className={styles.identitySeparator} aria-hidden="true"> · </span>
                <Translate id="about.avatar.intro">头像是</Translate>
                {' '}
                <Link href="https://baike.baidu.com/item/%E9%85%B7%E4%B9%90/18058703" className={styles.inlineLink}>
                  <Translate id="about.avatar.name">酷乐</Translate>
                </Link>
              </p>
            </div>
            <img className={styles.avatar} src="/img/logo.png" alt="" width="96" height="96" />
          </header>
          <div className={styles.layout}>
            <article className={styles.content}>
              <MDXContent><AboutContent /></MDXContent>
            </article>
            <section id="about-comments" className={styles.comments} aria-labelledby="about-comments-title">
              <h2 id="about-comments-title"><Translate id="about.comments">聊两句</Translate></h2>
              <p>感谢你能看到这里，希望我的分享对你有帮助。如果你有什么困扰，也可咨询我，在我时间有限的情况下，我会竭力回复。</p>
              <p className={styles.commentInvitation}>既然都看到这了，不妨留下你的评论。</p>
              <Comment />
            </section>
          </div>
        </div>
      </main>
      <BackToTopButton />
    </Layout>
  )
}
