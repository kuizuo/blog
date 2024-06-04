import Translate from '@docusaurus/Translate'
import clsx from 'clsx'
import React from 'react'

import features, { type FeatureItem } from '@site/data/features'
import SectionTitle from '../SectionTitle'

function Feature({ title, Svg, text }: FeatureItem) {
  return (
    <div
      className={clsx(
        'relative flex w-full flex-col gap-2 rounded-md bg-transparent p-0 transition-all duration-300 ease-linear',
      )}
    >
      <div className="text-center">
        <Svg className={'h-[150px] w-full'} role="img" />
      </div>
      <div className="py-4 text-left">
        <h3>{title}</h3>
        <p>{text}</p>
      </div>
    </div>
  )
}

export default function FeaturesSection() {
  return (
    <section className={clsx('padding-vert--sm container max-w-7xl')}>
      <SectionTitle icon={'ri:map-pin-user-line'}>
        <Translate id="homepage.feature.title">个人特点</Translate>
      </SectionTitle>
      <div className="flex w-full flex-col justify-center gap-4 md:flex-row">
        {features.map((props, idx) => (
          <Feature key={idx} {...props} />
        ))}
      </div>
    </section>
  )
}
