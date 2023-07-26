import React from 'react'
import clsx from 'clsx'
import styles from './styles.module.css'

import juejinSvg from '@site/static/svg/juejin.svg'

type FeatureItem = {
  title: string
  Svg: React.ComponentType<React.ComponentProps<'svg'>>
  description: JSX.Element
}

const FeatureList: FeatureItem[] = [
  {
    title: 'TS 全栈工程师',
    Svg: juejinSvg,
    description: (
      <>
        作为一名
        TypeScript（TS）全栈工程师，在前端和后端开发中都拥有丰富经验，并且熟练运用
        TypeScript。善于构建稳健、可扩展的应用程序，充分利用强类型和现代
        JavaScript 特性。
      </>
    ),
  },
  {
    title: '会点逆向、爬虫',
    Svg: juejinSvg,
    description: (
      <>
        在逆向工程和网络爬虫领域有一些经验和知识。熟悉逆向工程，可以分析和理解软件或系统的内部工作原理。此外，你在网络爬虫方面的技能使你能够高效地从各种在线资源中提取有价值的数据。这种组合技能使你能够解决各种独特的挑战，并为广泛的技术项目做出贡献。
      </>
    ),
  },
  {
    title: '开源爱好者',
    Svg: juejinSvg,
    description: (
      <>
        作为一名开源爱好者，热衷于为全球开发者社区贡献力量。积极参与开源项目，可以通过提交代码、修复问题或协助撰写文档等方式进行贡献。对开源软件的热爱促进了协作、知识分享，并推动技术的进步，造福所有人。
      </>
    ),
  },
]

function Feature({ title, Svg, description }: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  )
}

export default function HomepageFeatures(): JSX.Element {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  )
}
