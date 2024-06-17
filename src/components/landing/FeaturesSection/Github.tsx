import Translate from '@docusaurus/Translate'
import GitHubCalendar from 'react-github-calendar'

import { useColorMode } from '@docusaurus/theme-common'
import { Icon } from '@iconify/react'

interface GithubProps {
  className?: string
}

export default function Github({ className }: GithubProps) {
  const { isDarkTheme } = useColorMode()

  const githubStatsUrl = (type: 'overview' | 'languages') =>
    `https://raw.githubusercontent.com/kuizuo/github-stats/master/generated/${type}.svg#gh-${
      isDarkTheme ? 'dark' : 'light'
    }-mode-only`

  return (
    <div className={className}>
      <h2 className="mb-2 flex items-center gap-1 justify-center md:justify-start md:px-4 text-base">
        <Icon icon="ri:github-line" />
        <Translate id="homepage.feature.github.title">Github</Translate>
      </h2>
      <div className="relative flex w-full flex-col items-center justify-center overflow-hidden bg-background">
        <div className="mb-4 flex w-full justify-between gap-4 px-4">
          <img src={githubStatsUrl('overview')} alt="GitHub Overview Stats" />
          <img src={githubStatsUrl('languages')} alt="GitHub Languages Stats" />
        </div>
        <GitHubCalendar username="kuizuo" blockSize={11} colorScheme={isDarkTheme ? 'dark' : 'light'} />
      </div>
    </div>
  )
}
