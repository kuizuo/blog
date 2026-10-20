import Translate, { translate } from '@docusaurus/Translate'
import SegmentedControl from '@site/src/components/SegmentedControl'
import type { ViewType } from '@site/src/hooks/useViewType'

export default function ViewTypeSwitch({ viewType, toggleViewType }: {
  viewType: ViewType
  toggleViewType: (viewType: ViewType) => void
}) {
  return (
    <SegmentedControl
      label={translate({ id: 'blog.view.label', message: '文章显示方式' })}
      value={viewType}
      onChange={toggleViewType}
      controls="blog-posts"
      options={[
        {
          value: 'list',
          label: <Translate id="blog.view.list">列表</Translate>,
          icon: (
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
              <path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01" />
            </svg>
          ),
        },
        {
          value: 'grid',
          label: <Translate id="blog.view.grid">网格</Translate>,
          icon: (
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true">
              <rect x="3" y="3" width="7" height="7" rx="1.5" />
              <rect x="14" y="3" width="7" height="7" rx="1.5" />
              <rect x="3" y="14" width="7" height="7" rx="1.5" />
              <rect x="14" y="14" width="7" height="7" rx="1.5" />
            </svg>
          ),
        },
      ]}
    />
  )
}
