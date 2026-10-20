import Link from '@docusaurus/Link'
import Translate from '@docusaurus/Translate'
import type { BlogPost } from '@docusaurus/plugin-content-blog'
import { usePluginData } from '@docusaurus/useGlobalData'
import Image from '@theme/IdealImage'
import { Section } from '../Section'

const chunk = <T,>(arr: T[], size: number): T[][] =>
  Array.from({ length: Math.ceil(arr.length / size) }, (_, i) => arr.slice(i * size, i * size + size))

const BLOG_POSTS_COUNT = 6
const BLOG_POSTS_PER_ROW = 2

export function BlogItem({ post }: { post: BlogPost }) {
  const {
    metadata: { permalink, frontMatter, title, description },
  } = post

  return (
    <li
      className="card bg-blog flex w-full shadow-blog"
      key={permalink}
    >
      {frontMatter.image && (
        <Link href={permalink} className="block max-h-[240px] w-full overflow-hidden" tabIndex={-1} aria-hidden="true">
          <Image src={frontMatter?.image} alt={title} img="" />
        </Link>
      )}
      <div className="card__body">
        <h3 className="text-base leading-relaxed">
          <Link href={permalink} className="text-text underline-offset-4 hover:underline">
            {title}
          </Link>
        </h3>
        <p className="mb-0 text-sm leading-relaxed text-secondary">{description}</p>
      </div>
    </li>
  )
}

export default function BlogSection(): JSX.Element {
  const blogData = usePluginData('docusaurus-plugin-content-blog') as {
    posts: BlogPost[]
    postNum: number
    tagNum: number
  }

  const posts = chunk(blogData.posts.slice(0, BLOG_POSTS_COUNT), BLOG_POSTS_PER_ROW)

  if (blogData.postNum === 0) {
    return <>作者还没开始写博文哦...</>
  }

  return (
    <Section title={<Translate id="homepage.blog.title">近期博客</Translate>} icon="ri:quill-pen-line" href="/blog">
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        {posts.map((postGroup, index) => (
          <ul className="m-0 flex min-w-0 list-none flex-col gap-6 p-0" key={index}>
            {postGroup.map(post => (
              <BlogItem key={post.id} post={post} />
            ))}
          </ul>
        ))}
      </div>
    </Section>
  )
}
