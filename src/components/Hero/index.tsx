import React from 'react'
import { motion } from 'framer-motion' // Import motion from framer-motion

import Link from '@docusaurus/Link'
import Translate from '@docusaurus/Translate'
import { useThemeConfig } from '@docusaurus/theme-common'
import { ThemeConfig } from '@docusaurus/preset-classic'

import HeroMain from './img/hero_main.svg'
import JuejinIcon from '@site/static/svg/juejin.svg'
import { Icon } from '@iconify/react'

import styles from './styles.module.scss'

const variants = {
  visible: i => ({
    opacity: 1,
    y: 0,
    transition: {
      type: 'spring',
      damping: 25,
      stiffness: 100,
      duration: 0.3,
      delay: i * 0.3,
    },
  }),
  hidden: { opacity: 0, y: 30 },
}

function Hero() {
  return (
    <motion.div className={styles.hero}>
      <div className={styles.bloghome__intro}>
        <motion.div
          className={styles.hero_text}
          custom={1}
          initial="hidden"
          animate="visible"
          variants={variants}
        >
          <Translate id="homepage.hero.greet">你好! 我是</Translate>
          <span className={styles.intro__name}>
            <Translate id="homepage.hero.name">愧怍</Translate>
          </span>
        </motion.div>
        <motion.p
          custom={2}
          initial="hidden"
          animate="visible"
          variants={variants}
        >
          <Translate id="homepage.hero.text">
            {`在这里我会分享各类技术栈所遇到问题与解决方案，带你了解最新的技术栈以及实际开发中如何应用，并希望我的开发经历对你有所启发。`}
          </Translate>
          <br />
          <br />
          <Translate
            id="homepage.hero.look"
            values={{
              note: (
                <Link to="/docs/skill">
                  <Translate id="hompage.hero.note">技术笔记</Translate>
                </Link>
              ),
              project: (
                <Link to="/project">
                  <Translate id="hompage.hero.project">实战项目</Translate>
                </Link>
              ),
              link: (
                <Link to="/resource">
                  <Translate id="hompage.hero.link">资源导航</Translate>
                </Link>
              ),
              idea: (
                <Link to="/blog/tags/随笔">
                  <Translate id="hompage.hero.idea">想法感悟</Translate>
                </Link>
              ),
            }}
          >
            {`你可以随处逛逛，查看{note}、{project}、{link}、以及我的{idea}。`}
          </Translate>
        </motion.p>
        <SocialLinks
          custom={2}
          initial="hidden"
          animate="visible"
          variants={variants}
        />
        <motion.div
          className={styles.introOuter}
          custom={3}
          initial="hidden"
          animate="visible"
          variants={variants}
        >
          <div className={styles.introGradient}></div>
          <a className={styles.introButton} href={'./about'}>
            <Translate id="hompage.hero.introduce">自我介绍</Translate>
          </a>
        </motion.div>
      </div>
      <div className={styles.bloghome__image}>
        <HeroMain />
      </div>
    </motion.div>
  )
}

export function SocialLinks({ ...prop }) {
  const themeConfig = useThemeConfig() as ThemeConfig

  const socials = themeConfig.socials as {
    github: string
    twitter: string
    juejin: string
    csdn: string
    qq: string
    wx: string
    cloudmusic: string
    zhihu: string
  }

  return (
    <motion.div className={styles.social__links} {...prop}>
      <a href="/rss.xml" target="_blank">
        <Icon icon="ri:rss-line" />
      </a>
      <a href={socials.github} target="_blank">
        <Icon icon="ri:github-line" />
      </a>
      <a href={socials.juejin} target="_blank">
        <JuejinIcon />
      </a>
      <a href={socials.qq} target="_blank">
        <Icon icon="ri:qq-line" />
      </a>
      <a href={socials.twitter} target="_blank">
        <Icon icon="ri:twitter-line" />
      </a>
      <a href={socials.zhihu} target="_blank">
        <Icon icon="ri:zhihu-line" />
      </a>
    </motion.div>
  )
}

export default Hero
