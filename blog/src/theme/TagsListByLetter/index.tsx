import React from 'react'
import {
  listTagsByLetters,
  type TagLetterEntry,
} from '@docusaurus/theme-common'
import Tag from '@theme/Tag'
import type { Props } from '@theme/TagsListByLetter'

import styles from './styles.module.css'

function TagLetterEntryItem({ letterEntry }: { letterEntry: TagLetterEntry }) {
  return (
    <article>
      <h2>{letterEntry.letter}</h2>
      <ul className="padding--none">
        {letterEntry.tags.map(tag => (
          <li key={tag.permalink} className={styles.tag}>
            <Tag {...tag} />
          </li>
        ))}
      </ul>
      <hr />
    </article>
  )
}

export default function TagsListByLetter({ tags }: Props): JSX.Element {
  const letterList = listTagsByLetters(tags)
  return (
    <section className="margin-vert--lg">
      {letterList.map(letterEntry => (
        <TagLetterEntryItem
          key={letterEntry.letter}
          letterEntry={letterEntry}
        />
      ))}
    </section>
  )
}

export function TagsListByFlat({ tags }: Props): JSX.Element {
  return (
    <section className="margin-vert--lg">
      <ul className="padding--none">
        {tags.map(tag => (
          <li key={tag.permalink} className={styles.tag}>
            <Tag {...tag} />
          </li>
        ))}
      </ul>
    </section>
  )
}
