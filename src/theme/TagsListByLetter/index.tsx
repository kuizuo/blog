import type { TagLetterEntry } from '@docusaurus/theme-common'
import Tag from '@theme/Tag'
import type { Props } from '@theme/TagsListByLetter'

import styles from './styles.module.css'

type TagListItem = Props['tags'][number]

function compareText(left: string, right: string): number {
  const normalizedLeft = left.toLocaleLowerCase('en-US')
  const normalizedRight = right.toLocaleLowerCase('en-US')

  if (normalizedLeft < normalizedRight) return -1
  if (normalizedLeft > normalizedRight) return 1
  if (left < right) return -1
  if (left > right) return 1
  return 0
}

function listTagsByLetters(tags: readonly TagListItem[]): TagLetterEntry[] {
  const groups: Record<string, TagListItem[]> = {}

  tags.forEach((tag) => {
    const letter = tag.label[0]!.toUpperCase()
    groups[letter] ??= []
    groups[letter].push(tag)
  })

  return Object.entries(groups)
    .sort(([left], [right]) => compareText(left, right))
    .map(([letter, letterTags]) => ({
      letter,
      tags: [...letterTags].sort((left, right) => compareText(left.label, right.label)),
    }))
}

function TagLetterEntryItem({ letterEntry }: { letterEntry: TagLetterEntry }) {
  return (
    <article>
      <h2>{letterEntry.letter}</h2>
      <ul className="padding--none mb-4">
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
        <TagLetterEntryItem key={letterEntry.letter} letterEntry={letterEntry} />
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
