import Translate from '@docusaurus/Translate'

import { Icon } from '@iconify/react'
import SKILLS from '@site/data/skills'
import IconCloud from '../../magicui/icon-cloud'

export default function Skill({ className }: { className?: string }) {
  return (
    <div className={className}>
      <h2 className="mb-2 flex items-center gap-1 text-base justify-center md:justify-start" >
        <Icon icon="carbon:tool-kit" />
        <Translate id="homepage.feature.skill.title">技术栈</Translate>
      </h2>
      <div className="relative flex aspect-square w-full items-center justify-center overflow-hidden bg-background p-4">
        <IconCloud iconSlugs={SKILLS} />
      </div>
    </div>
  )
}
