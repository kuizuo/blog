import Translate from '@docusaurus/Translate'
import GitHubCalendar from 'react-github-calendar'

import { useColorMode } from '@docusaurus/theme-common'
import { Icon } from '@iconify/react'
import ThemedImage from '@theme/ThemedImage'

interface GithubProps {
  className?: string
}

export default function Github({ className }: GithubProps) {
  const { isDarkTheme } = useColorMode()

  const githubStatsUrl = (type: 'overview' | 'languages', isDark: boolean) =>
    `https://raw.githubusercontent.com/kuizuo/github-stats/master/generated/${type}.svg#gh-${
      isDark ? 'dark' : 'light'
    }-mode-only`

  return (
    <div className={className}>
      <h2 className="mb-2 flex items-center justify-center gap-1 text-base md:justify-start md:px-4">
        <Icon icon="ri:github-line" />
        <Translate id="homepage.feature.github.title">Github</Translate>
      </h2>
      <div className="relative flex w-full flex-col items-center justify-center overflow-hidden bg-background">
        <div className="github-stats mb-4 flex w-full flex-col justify-between gap-4 overflow-x-auto px-0 sm:flex-row">
          <ThemedImage
            alt="GitHub Overview Stats"
            sources={{
              light: githubStatsUrl('overview', false),
              dark: githubStatsUrl('overview', true),
            }}
          />
          <ThemedImage
            alt="GitHub Languages Stats"
            sources={{
              light: githubStatsUrl('languages', false),
              dark: githubStatsUrl('languages', true),
            }}
          />
        </div>
        <GitHubCalendar username="kuizuo" blockSize={11} colorScheme={isDarkTheme ? 'dark' : 'light'} />
      </div>
    </div>
  )
}
