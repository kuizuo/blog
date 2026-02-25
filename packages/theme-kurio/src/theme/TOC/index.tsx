import type { Props } from '@theme/TOC'
import TOCItems from '@theme/TOCItems'

const LINK_CLASS_NAME = 'table-of-contents__link toc-highlight'
const LINK_ACTIVE_CLASS_NAME = 'table-of-contents__link--active'

export default function TOC({ className, ...props }: Props): JSX.Element {
  return (
    <div
      className={['thin-scrollbar', className].join(' ')}
    >
      <TOCItems
        {...props}
        className="table-of-contents pl-0"
        linkClassName={LINK_CLASS_NAME}
        linkActiveClassName={LINK_ACTIVE_CLASS_NAME}
      />
      123
    </div>
  )
}
