import { type Variants, motion, useReducedMotion } from 'framer-motion'

import Translate from '@docusaurus/Translate'

import HeroSvg from './img/hero.svg'

import SocialLinks from '@site/src/components/SocialLinks'
import styles from './styles.module.css'

const variants: Variants = {
  visible: i => ({
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.3,
      ease: [0.16, 1, 0.3, 1],
      delay: i * 0.1,
    },
  }),
  hidden: { opacity: 0, y: 30 },
}

function Circle() {
  return <div className={styles.circle} />
}

function Name() {
  const reduceMotion = useReducedMotion()

  return (
    <motion.h1
      className={styles.hero_text}
      custom={1}
      initial={reduceMotion ? false : 'hidden'}
      animate="visible"
      variants={variants}
      onMouseMove={(e) => {
        e.currentTarget.style.setProperty('--x', `${e.clientX}px`)
        e.currentTarget.style.setProperty('--y', `${e.clientY}px`)
      }}
    >
      <Translate id="homepage.hero.greet">你好! 我是</Translate>
      <span className={styles.name}>
        <Translate id="homepage.hero.name">愧怍</Translate>
      </span>
      <span className="ml-1">👋</span>
    </motion.h1>
  )
}

export default function Hero() {
  const reduceMotion = useReducedMotion()

  return (
    <motion.div className={styles.hero}>
      <div className={styles.intro}>
        <Name />
        <motion.p custom={2} initial={reduceMotion ? false : 'hidden'} animate="visible" variants={variants}>
          <Translate id="homepage.hero.text">
            在这里我会分享各类技术栈所遇到问题与解决方案，带你了解最新的技术栈以及实际开发中如何应用，并希望我的开发经历对你有所启发。
          </Translate>
        </motion.p>
        <motion.div className={styles.socials} custom={3} initial={reduceMotion ? false : 'hidden'} animate="visible" variants={variants}>
          <SocialLinks />
        </motion.div>
      </div>
      <motion.div className={styles.background} aria-hidden="true">
        <HeroSvg />
        <Circle />
      </motion.div>
    </motion.div>
  )
}
