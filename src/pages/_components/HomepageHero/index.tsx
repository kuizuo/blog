import React from 'react'
import { motion } from 'framer-motion' // Import motion from framer-motion

import Translate from '@docusaurus/Translate'

import HeroMain from './img/hero_main.svg'

import styles from './styles.module.scss'
import SocialLinks from '@site/src/components/SocialLinks'

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
        </motion.p>
        <motion.div
          custom={2}
          initial="hidden"
          animate="visible"
          variants={variants}
        >
          <SocialLinks />
        </motion.div>

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

export default Hero
