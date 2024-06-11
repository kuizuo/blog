import { useHistory, useLocation } from '@docusaurus/router'
import type { TagType } from '@site/data/projects'
import { toggleListItem } from '@site/src/utils/jsUtils'
import React, { type ComponentProps, type ReactElement, type ReactNode, useCallback, useEffect, useState } from 'react'
import { prepareUserState } from '../../index'

import styles from './styles.module.css'

interface Props extends ComponentProps<'input'> {
  icon: ReactElement<ComponentProps<'svg'>>
  label: ReactNode
  tag: TagType
}

const TagQueryStringKey = 'tags'

export function readSearchTags(search: string): TagType[] {
  return new URLSearchParams(search).getAll(TagQueryStringKey) as TagType[]
}

function replaceSearchTags(search: string, newTags: TagType[]) {
  const searchParams = new URLSearchParams(search)
  searchParams.delete(TagQueryStringKey)
  for (const tag of newTags) {
    searchParams.append(TagQueryStringKey, tag)
  }
  return searchParams.toString()
}

const ShowcaseTagSelect = React.forwardRef<HTMLLabelElement, Props>(({ id, icon, label, tag, ...rest }, ref) => {
  const location = useLocation()
  const history = useHistory()
  const [selected, setSelected] = useState(false)
  useEffect(() => {
    const tags = readSearchTags(location.search)
    setSelected(tags.includes(tag))
  }, [tag, location])
  const toggleTag = useCallback(() => {
    const tags = readSearchTags(location.search)
    const newTags = toggleListItem(tags, tag)
    const newSearch = replaceSearchTags(location.search, newTags)
    history.push({
      ...location,
      search: newSearch,
      state: prepareUserState(),
    })
  }, [tag, location, history])
  return (
    <>
      <input
        type="checkbox"
        id={id}
        className="sr-only"
        onKeyDown={e => {
          if (e.key === 'Enter') {
            toggleTag()
          }
        }}
        onFocus={e => {
          if (e.relatedTarget) {
            e.target.nextElementSibling?.dispatchEvent(new KeyboardEvent('focus'))
          }
        }}
        onBlur={e => {
          e.target.nextElementSibling?.dispatchEvent(new KeyboardEvent('blur'))
        }}
        onChange={toggleTag}
        checked={selected}
        {...rest}
      />
      <label ref={ref} htmlFor={id} className={styles.checkboxLabel}>
        {label}
        {icon}
      </label>
    </>
  )
})

export default ShowcaseTagSelect
