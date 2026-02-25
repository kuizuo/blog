import Translate from '@docusaurus/Translate'
import features from '@site/data/features'
import { cn } from '@site/src/lib/utils'
import { BentoGrid, BentoGridItem } from '../../magicui/bento-grid'
import { Section } from '../Section'

export default function FeaturesSection() {
  return (
    <Section title={<Translate id="homepage.feature.title">个人特点</Translate>} icon="ri:map-pin-user-line">
      <BentoGrid className="mx-auto w-full">
        {features.map((item, i) => (
          <BentoGridItem
            key={i}
            title={item.title}
            description={item.description}
            header={item.header}
            icon={item.icon}
            className={cn('p-2 md:p-4', i === 3 || i === 6 ? 'md:col-span-2' : '')}
          />
        ))}
      </BentoGrid>

      {/* <div className="mt-4 grid grid-cols-1 justify-center gap-4 px-0 md:grid-cols-6 md:grid-rows-2 md:px-4">
        <Skill className="md:col-span-2 md:row-span-2" />
        <Github className="h-full md:col-span-4 md:row-span-2" />
      </div> */}
    </Section>
  )
}
