import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import Layout from '@theme/Layout'
import { useReducedMotion } from 'framer-motion'
import BlogSection from '../components/landing/BlogSection'
import FeaturesSection from '../components/landing/FeaturesSection'
import Hero from '../components/landing/Hero'
import Particles from '../components/magicui/particles'
import styles from './index.module.css'

export default function Home() {
  const reduceMotion = useReducedMotion()
  const {
    siteConfig: { customFields, tagline },
  } = useDocusaurusContext()
  const { description } = customFields as { description: string }

  return (
    <Layout title={tagline} description={description}>
      <main className={styles.home}>
        <Hero />
        {!reduceMotion && <Particles className="pointer-events-none absolute inset-0" quantity={100} ease={80} color="#ffffff" refresh />}

        <div className="relative">
          <div className="mx-auto max-w-7xl pb-12 lg:px-8">
            <BlogSection />
            <FeaturesSection />
          </div>
        </div>
      </main>
    </Layout>
  )
}
