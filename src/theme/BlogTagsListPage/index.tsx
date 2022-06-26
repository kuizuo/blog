import BlogLayout from '@theme/BlogLayout'
import type { Props } from '@theme/BlogTagsListPage'
import Link from '@docusaurus/Link'
import { PageMetadata, HtmlClassNameProvider, ThemeClassNames, translateTagsPageTitle } from '@docusaurus/theme-common'
import SearchMetadata from '@theme/SearchMetadata'
import clsx from 'clsx'

function BlogTagsListPage(props: Props) {
  const { tags, sidebar } = props
  const title = translateTagsPageTitle()

  const TagsList = () => (
    <div className='row'>
      {tags.map((tag) => (
        <Link className={`post__tags tags__item margin-horiz--sm margin-bottom--sm`} href={tag.permalink} key={tag.label}>
          {tag.label} ({tag.count})
        </Link>
      ))}
    </div>
  )

  return (
    <HtmlClassNameProvider className={clsx(ThemeClassNames.wrapper.blogPages, ThemeClassNames.page.blogTagsListPage)}>
      <PageMetadata title={title} />
      <SearchMetadata tag='blog_tags_list' />
      <BlogLayout sidebar={sidebar}>
        <h1>{title}</h1>
        <TagsList></TagsList>
      </BlogLayout>
    </HtmlClassNameProvider>
  )
}

export default BlogTagsListPage
