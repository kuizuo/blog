import Link from '@docusaurus/Link'
import Translate from '@docusaurus/Translate'
import { Icon } from '@iconify/react'
import type React from 'react'

interface SectionProps {
  title: string | JSX.Element
  icon?: string
  href?: string
  children: React.ReactNode
}

export function Section({ title, icon, href, children }: SectionProps) {
  return (
    <section className="group/section py-2 max-lg:mx-4">
      <div className="mt-8 mb-4 inline-flex w-full items-center justify-between md:mt-6">
        <h2 className="m-0 inline-flex items-center justify-center gap-1 text-base">
          {icon && <Icon icon={icon} />}
          {title}
        </h2>
        {href && (
          <Link
            href={href}
            className="group/link inline-flex items-center justify-center text-base opacity-0 transition duration-500 group-hover/section:opacity-100"
          >
            <Translate id="homepage.lookMore">查看更多</Translate>
            <Icon icon="ri:arrow-right-s-line" className="transition group-hover/link:translate-x-1" />
          </Link>
        )}
      </div>
      {children}
    </section>
  )
}
