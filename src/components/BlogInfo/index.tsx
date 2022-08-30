import useGlobalData from '@docusaurus/useGlobalData';
import type {
  BlogTag,
  BlogTags,
  BlogPost,
} from '@docusaurus/plugin-content-blog';
import {FontAwesomeIcon} from '@fortawesome/react-fontawesome';
import {
  faTag,
  faArchive,
  faBook,
  faThLarge,
} from '@fortawesome/free-solid-svg-icons';
import {IconProp} from '@fortawesome/fontawesome-svg-core';
import Link from '@docusaurus/Link';
import {SocialLinks} from '@site/src/components/Hero';
import {useThemeConfig} from '@docusaurus/theme-common';
import useBaseUrl from '@docusaurus/useBaseUrl';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

type Count = {
  blog: number;
  tag: number;
  doc: number;
  project: number;
};

export function BlogUser({
  count,
  isNavbar = false,
}: {
  count?: Count;
  isNavbar?: boolean;
}) {
  const {
    siteConfig: {tagline},
  } = useDocusaurusContext();
  const {
    navbar: {title, logo = {src: ''}},
  } = useThemeConfig();

  const logoLink = useBaseUrl(logo.src || '/');

  if (!count) {
    const globalData = useGlobalData();
    const blogPluginData = globalData?.['docusaurus-plugin-content-blog']?.[
      'default'
    ] as any;
    const blogData = blogPluginData?.blogs as BlogPost[];
    const tagData = blogPluginData?.tags as BlogTags;
    const projectData = blogPluginData?.projects;
    const docData = (
      globalData?.['docusaurus-plugin-content-docs']?.['default'] as any
    )?.versions[0].docs;

    count = {
      blog: blogData.length,
      tag: Object.keys(tagData).length ?? 0,
      doc: docData?.length ?? 0,
      project: projectData?.length ?? 0,
    };
  }

  return (
    <div
      className={`row ${
        isNavbar ? 'bloginfo__card-navbar' : 'bloginfo__card'
      }`}>
      <Link href="/about">
        <img className="bloginfo__img" src={logoLink} alt="logo"></img>
      </Link>
      <div>
        <Link className="bloginfo__name" href="about">
          {title}
        </Link>
      </div>
      <div className="bloginfo__description">{tagline}</div>
      <div className="bloginfo__num">
        <Link className="bloginfo__num-item" href="/archive" data-tips="博客数">
          <FontAwesomeIcon
            icon={faArchive as IconProp}
            width="16"
            height="16"
          />{' '}
          {count.blog}
        </Link>
        <Link className="bloginfo__num-item" href="/tags" data-tips="标签数">
          <FontAwesomeIcon
            icon={faTag as IconProp}
            width="16"
            height="16"
            style={{transform: 'rotate(90deg)'}}
          />{' '}
          {count.tag}
        </Link>
        <Link
          className="bloginfo__num-item"
          href="/docs/skill"
          data-tips="笔记数">
          <FontAwesomeIcon icon={faBook as IconProp} width="16" height="16" />{' '}
          {count.doc}
        </Link>
        <Link className="bloginfo__num-item" href="/project" data-tips="项目数">
          <FontAwesomeIcon
            icon={faThLarge as IconProp}
            width="16"
            height="16"
          />{' '}
          {count.project}
        </Link>
      </div>
      <SocialLinks
        animatedProps={{
          maxWidth: '100%',
          padding: '0.5em 0',
          justifyContent: 'space-evenly',
          ...(isNavbar ? {borderBottom: '1px solid #eee'} : null),
        }}
      />
    </div>
  );
}

const TagsSection = ({data}: {data: BlogTag[]}) => {
  return (
    <div className="bloginfo__tags">
      {data
        .filter((tag) => tag != null)
        .sort((a, b) => b.items.length - a.items.length)
        .slice(0, 25)
        .map((tag) => (
          <Link
            className={`post__tags note__item margin-right--sm margin-bottom--sm`}
            href={tag.permalink}
            key={tag.permalink}>
            {tag.label}
          </Link>
        ))}
    </div>
  );
};

export default function BlogInfo() {
  const globalData = useGlobalData();
  const blogPluginData = globalData?.['docusaurus-plugin-content-blog']?.[
    'default'
  ] as any;
  const blogData = blogPluginData?.blogs as BlogPost[];
  const tagData = blogPluginData?.tags as BlogTags;
  const docData = (
    globalData?.['docusaurus-plugin-content-docs']?.['default'] as any
  )?.versions[0].docs;
  const projectData = blogPluginData?.projects;

  const count: Count = {
    blog: blogData.length,
    tag: Object.keys(tagData).length ?? 0,
    doc: docData?.length ?? 0,
    project: projectData?.length ?? 0,
  };

  return (
    <div className="bloginfo col col--3 margin-bottom--md">
      <section className="bloginfo__content">
        <div className="bloghome__posts-card bloginfo__user margin-bottom--md">
          <BlogUser count={count} />
        </div>
        <div className="bloghome__posts-card margin-bottom--md">
          <div className="row bloginfo__card">
            <div>
              <FontAwesomeIcon
                icon={faTag as IconProp}
                style={{transform: 'rotate(90deg)'}}
              />
              <Link className="margin-horiz--sm" href="/tags">
                标签
              </Link>
            </div>
            <TagsSection data={Object.values(tagData)} />
          </div>
        </div>
      </section>
    </div>
  );
}
