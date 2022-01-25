import React from 'react';
import clsx from 'clsx';
import Layout from '@theme/Layout';
import { MDXProvider } from '@mdx-js/react';
import MDXComponents from '@theme/MDXComponents';
import type { Props } from '@theme/MDXPage';
import TOC from '@theme/TOC';
import { ThemeClassNames } from '@docusaurus/theme-common';

import styles from './styles.module.css';

function MDXPage(props: Props) {
  const { content: MDXPageContent } = props;
  const { frontMatter, metadata } = MDXPageContent;

  const { title, description, wrapperClassName, hide_table_of_contents: hideTableOfContents } = frontMatter;
  const { permalink } = metadata;

  return (
    <Layout title={title} description={description} permalink={permalink} wrapperClassName={wrapperClassName ?? ThemeClassNames.wrapper.mdxPages} pageClassName={ThemeClassNames.page.mdxPage}>
      <main className='container container--fluid margin-vert--lg'>
        <div className={clsx('row', styles.mdxPageWrapper)}>
          <div className={clsx('col', 'col--8', styles.content)}>
            <MDXProvider components={MDXComponents}>
              <MDXPageContent />
            </MDXProvider>
          </div>
          {!hideTableOfContents && MDXPageContent.toc && (
            <div className='col col--2'>
              <TOC toc={MDXPageContent.toc} />
            </div>
          )}
        </div>
      </main>
    </Layout>
  );
}

export default MDXPage;
