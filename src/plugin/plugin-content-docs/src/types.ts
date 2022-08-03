/// <reference types="@docusaurus/module-type-aliases" />

// @ts-ignore
import type {Sidebars} from './sidebars/types';
import type {BrokenMarkdownLink} from '@docusaurus/utils';
import type {
  VersionMetadata,
  LastUpdateData,
  DocMetadata,
  CategoryGeneratedIndexMetadata,
} from '@docusaurus/plugin-content-docs';
// @ts-ignore
import type {Tag} from '@docusaurus/types';

export type DocFile = {
  contentPath: string; // /!\ may be localized
  filePath: string; // /!\ may be localized
  source: string;
  content: string;
  lastUpdate: LastUpdateData;
};

export type SourceToPermalink = {
  [source: string]: string;
};

export type VersionTag = Tag & {
  /** all doc ids having this tag. */
  docIds: string[];
};
export type VersionTags = {
  [permalink: string]: VersionTag;
};

export type LoadedVersion = VersionMetadata & {
  mainDocId: string;
  docs: DocMetadata[];
  sidebars: Sidebars;
  categoryGeneratedIndices: CategoryGeneratedIndexMetadata[];
};

export type LoadedContent = {
  loadedVersions: LoadedVersion[];
};

export type DocBrokenMarkdownLink = BrokenMarkdownLink<VersionMetadata>;

export type DocsMarkdownOption = {
  versionsMetadata: VersionMetadata[];
  siteDir: string;
  sourceToPermalink: SourceToPermalink;
  onBrokenMarkdownLink: (brokenMarkdownLink: DocBrokenMarkdownLink) => void;
};
