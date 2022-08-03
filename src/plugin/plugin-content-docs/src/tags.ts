import {groupTaggedItems} from '@docusaurus/utils';
import type {VersionTags} from './types';
import type {DocMetadata} from '@docusaurus/plugin-content-docs';
import _ from 'lodash';

export function getVersionTags(docs: DocMetadata[]): VersionTags {
  const groups = groupTaggedItems(docs, (doc) => doc.tags);
  return _.mapValues(groups, (group) => ({
    label: group.tag.label,
    docIds: group.items.map((item) => item.id),
    permalink: group.tag.permalink,
  }));
}
