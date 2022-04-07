import BlogLayout from '@theme/BlogLayout'
import Link from '@docusaurus/Link'
import { PageMetadata, HtmlClassNameProvider, ThemeClassNames, translateTagsPageTitle } from '@docusaurus/theme-common'
import SearchMetadata from '@theme/SearchMetadata'
import clsx from 'clsx'

function getCategoryOfTag(tag: string) {
  return tag[0].toUpperCase()
}

function BlogTagsListPage(props) {
  const { tags, sidebar, items } = props
  const title = translateTagsPageTitle()

  const tagCategories: { [category: string]: string[] } = {}
  Object.keys(tags).forEach((tag) => {
    const category = getCategoryOfTag(tag)
    tagCategories[category] = tagCategories[category] || []
    tagCategories[category].push(tag)
  })
  const tagsList = Object.entries(tagCategories).sort(([a], [b]) => a.localeCompare(b))

  const TagsList = () => (
    <div className='row'>
      {tagsList
        .map(([category, tagsForCategory]) => (
          <div key={category} style={{ display: 'flex', flexWrap: 'wrap' }}>
            {tagsForCategory.map((tag, index) => (
              <Link className={`post__tags margin-horiz--sm margin-bottom--sm`} href={tags[tag].permalink} key={tag}>
                {tags[tag].name} ({tags[tag].count})
              </Link>
            ))}
          </div>
        ))
        .filter((item) => item != null)}
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
