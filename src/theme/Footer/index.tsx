import Link from '@docusaurus/Link'
import IconExternalLink from '@theme/Icon/ExternalLink'
import social from '@site/data/social'
import { getPoliceRecordCode, siteInfo } from '@site/data/site'
import styles from './styles.module.css'

type FooterLink = {
  label: string
  href?: string
  showExternalIcon?: boolean
  to?: string
}

const currentYear = new Date().getFullYear()

const linkGroups: Array<{ title: string, links: FooterLink[] }> = [
  {
    title: '关于',
    links: [
      { label: '首页', to: '/' },
      { label: '关于我', to: '/about' },
      { label: '关于本站项目', href: siteInfo.repository },
    ],
  },
  {
    title: '更多',
    links: [
      { label: '项目', to: '/project' },
      { label: '归档', to: '/blog/archive' },
      { label: '友链', to: '/friends' },
    ],
  },
  {
    title: '联系',
    links: [
      { label: 'GitHub', href: social.github.href },
      { label: 'X', href: social.x.href },
      { label: '发邮件', href: social.email.href },
    ],
  },
]

const utilityLinks: FooterLink[] = [
  { label: 'RSS 订阅', href: `${siteInfo.url}${social.rss.href}`, showExternalIcon: false },
  { label: '站点地图', href: `${siteInfo.url}/sitemap.xml`, showExternalIcon: false },
]

function FooterAnchor({ link }: { link: FooterLink }): JSX.Element {
  const showExternalIcon = link.showExternalIcon ?? Boolean(link.href?.startsWith('http'))
  const linkProps = link.href ? { href: link.href } : { to: link.to }

  return (
    <Link {...linkProps} className={styles.link}>
      {link.label}
      {showExternalIcon && <IconExternalLink className={styles.externalIcon} />}
    </Link>
  )
}

export default function Footer(): JSX.Element {
  return (
    <footer className={styles.footer}>
      <div className={styles.inner}>
        <div className={styles.top}>
          <section className={styles.brand} aria-label="站点信息">
            <h2 className={styles.title}>{siteInfo.name}</h2>
            <p className={styles.description}>{siteInfo.description}</p>
            <p className={styles.copyright}>
              <span>
                {`© ${siteInfo.copyrightStartYear}-${currentYear} ${siteInfo.name}`}
              </span>
              <br />
              <span>
                Powered by
                {' '}
                <Link href="https://docusaurus.io">Docusaurus</Link>
              </span>
            </p>
          </section>

          <nav className={styles.groups} aria-label="页脚导航">
            {linkGroups.map(group => (
              <section key={group.title} className={styles.group}>
                <h3 className={styles.groupTitle}>{group.title}</h3>
                <ul className={styles.groupList}>
                  {group.links.map(link => (
                    <li key={link.label}>
                      <FooterAnchor link={link} />
                    </li>
                  ))}
                </ul>
              </section>
            ))}
          </nav>
        </div>

        <div className={styles.bottom}>
          <nav className={styles.utility} aria-label="订阅和站点地图">
            {utilityLinks.map(link => (
              <FooterAnchor key={link.label} link={link} />
            ))}
          </nav>

          <div className={styles.records}>
            <Link href="http://beian.miit.gov.cn/">{siteInfo.beian.icp}</Link>
            <span className={styles.recordDivider} aria-hidden="true">·</span>
            <Link href={`http://www.beian.gov.cn/portal/registerSystemInfo?recordcode=${getPoliceRecordCode()}`}>
              {siteInfo.beian.police}
            </Link>
          </div>
        </div>
      </div>
    </footer>
  )
}
