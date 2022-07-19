import useDocusaurusContext from '@docusaurus/useDocusaurusContext'
import { useColorMode } from '@docusaurus/theme-common'
import BrowserOnly from '@docusaurus/BrowserOnly'
import Giscus, { GiscusProps } from '@giscus/react'

export default function BlogComment(): JSX.Element {
  const { siteConfig } = useDocusaurusContext()
  const { themeConfig } = siteConfig

  const theme = useColorMode().colorMode === 'dark' ? 'dark' : 'light'

  const options: GiscusProps = {
    ...(themeConfig.giscus as GiscusProps),
    id: 'comments',
    reactionsEnabled: '1',
    emitMetadata: '0',
    inputPosition: 'top',
    theme,
  }
  return <BrowserOnly fallback={<div></div>}>{() => <Giscus {...options} />}</BrowserOnly>
}
