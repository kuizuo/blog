import Translate from '@docusaurus/Translate'

import { Icon } from '@iconify/react'

export default function Skill({ className }: { className?: string }) {
  return (
    <div className={className}>
      <h2 className="mb-2 flex items-center gap-1 text-base">
        <Icon icon="ri:github-line" />
        <Translate id="homepage.feature.github.title">Github</Translate>
      </h2>
      <div className="relative flex w-full items-center justify-center overflow-hidden bg-background p-4">
        <img
          src="https://metrics.lecoq.io/kuizuo?template=classic&base=header%2C%20activity%2C%20community%2C%20repositories%2C%20metadata&base.indepth=false&base.hireable=false&base.skip=false&config.timezone=Asia%2FShanghai"
          alt="kuizuo's Github chart"
        />
      </div>
    </div>
  )
}
