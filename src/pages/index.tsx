import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import Layout from '@theme/Layout'
import BlogSection from '../components/landing/BlogSection'
import FeaturesSection from '../components/landing/FeaturesSection'
import Hero from '../components/landing/Hero'
import ProjectSection from '../components/landing/ProjectSection'
import Particles from '../components/magicui/particles'

export default function Home() {
  const {
    siteConfig: { customFields, tagline },
  } = useDocusaurusContext()
  const { description } = customFields as { description: string }

  return (
    <Layout title={tagline} description={description}>
      <main>
        <Hero />
        <Particles className="absolute inset-0" quantity={100} ease={80} color="#ffffff" refresh />

        <div className="relative">
          <div className="mx-auto max-w-7xl bg-background lg:px-8">
            <BlogSection />
            <ProjectSection />
            <FeaturesSection />
          </div>
          <div
            className="absolute inset-0 -z-50 bg-grid-slate-50 [mask-image:linear-gradient(0deg,#fff,rgba(255,255,255,0.3))] dark:bg-grid-slate-700/25 dark:[mask-image:linear-gradient(0deg,rgba(255,255,255,0.1),rgba(255,255,255,0.5))]"
            style={{ backgroundPosition: '10px 10px;' }}
          />
        </div>
      </main>
    </Layout>
  )
}
