/**
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
import type { BrokenMarkdownLink, ContentPaths } from '@docusaurus/utils';
import type { Tag } from '@docusaurus/types';
import type { BlogPostMetadata } from '@docusaurus/plugin-content-blog';
import type { Metadata as BlogPaginatedMetadata } from '@theme/BlogListPage';
export declare type BlogContentPaths = ContentPaths;
export declare type BlogContent = {
    blogSidebarTitle: string;
    blogPosts: BlogPost[];
    blogListPaginated: BlogPaginated[];
    blogTags: BlogTags;
    blogTagsListPath: string;
};
export declare type BlogTags = {
    [permalink: string]: BlogTag;
};
export declare type BlogTag = Tag & {
    /** Blog post permalinks. */
    items: string[];
    pages: BlogPaginated[];
};
export declare type BlogPost = {
    id: string;
    metadata: BlogPostMetadata;
    content: string;
};
export declare type BlogPaginated = {
    metadata: BlogPaginatedMetadata;
    /** Blog post permalinks. */
    items: string[];
};
export declare type BlogBrokenMarkdownLink = BrokenMarkdownLink<BlogContentPaths>;
export declare type BlogMarkdownLoaderOptions = {
    siteDir: string;
    contentPaths: BlogContentPaths;
    truncateMarker: RegExp;
    sourceToPermalink: {
        [aliasedPath: string]: string;
    };
    onBrokenMarkdownLink: (brokenMarkdownLink: BlogBrokenMarkdownLink) => void;
};
