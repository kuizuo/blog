import { useLocation } from '@docusaurus/router'
import NavbarItem from '@theme/NavbarItem'
import type { Props } from '@theme/NavbarItem/DropdownNavbarItem/Desktop'
import NavbarNavLink from '@theme/NavbarItem/NavbarNavLink'
import clsx from 'clsx'
import React, { useEffect, useRef, useState } from 'react'
import styles from './styles.module.css'

export default function DropdownNavbarItemDesktop({ items, position, className, onClick, ...props }: Props) {
  const root = useRef<HTMLDivElement>(null)
  const focusFirst = useRef(false)
  const [open, setOpen] = useState(false)
  const { pathname } = useLocation()

  useEffect(() => setOpen(false), [pathname])

  useEffect(() => {
    if (!open) return

    if (focusFirst.current) {
      focusFirst.current = false
      root.current?.querySelector<HTMLAnchorElement>('ul a')?.focus()
    }

    const closeOutside = (event: MouseEvent | TouchEvent | FocusEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      setOpen(false)
      root.current?.querySelector<HTMLAnchorElement>(':scope > a')?.focus()
    }
    document.addEventListener('mousedown', closeOutside)
    document.addEventListener('touchstart', closeOutside)
    document.addEventListener('focusin', closeOutside)
    document.addEventListener('keydown', closeOnEscape)
    return () => {
      document.removeEventListener('mousedown', closeOutside)
      document.removeEventListener('touchstart', closeOutside)
      document.removeEventListener('focusin', closeOutside)
      document.removeEventListener('keydown', closeOnEscape)
    }
  }, [open])

  return (
    <div
      ref={root}
      className={clsx('navbar__item', 'dropdown', styles.dropdown, {
        'dropdown--right': position === 'right',
        'dropdown--show': open,
      })}
      onPointerEnter={(event) => {
        if (event.pointerType === 'mouse') setOpen(true)
      }}
      onPointerLeave={() => {
        if (!root.current?.contains(document.activeElement)) setOpen(false)
      }}
    >
      <NavbarNavLink
        {...props}
        href={props.to ? undefined : '#'}
        className={clsx('navbar__link', className)}
        aria-haspopup="true"
        aria-expanded={open}
        role="button"
        onClick={props.to
          ? onClick
          : (event) => {
              event.preventDefault()
              setOpen(true)
            }}
        onKeyDown={(event) => {
          if (!['ArrowDown', 'Enter', ' '].includes(event.key)) return
          event.preventDefault()
          if (open) {
            root.current?.querySelector<HTMLAnchorElement>('ul a')?.focus()
          }
          else {
            focusFirst.current = true
            setOpen(true)
          }
        }}
      >
        {props.children ?? props.label}
      </NavbarNavLink>
      <ul
        className={clsx('dropdown__menu', styles.menu)}
        onKeyDown={(event) => {
          if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return
          const links = Array.from(event.currentTarget.querySelectorAll<HTMLAnchorElement>('a[href]'))
          if (!links.length) return
          event.preventDefault()
          const current = links.indexOf(document.activeElement as HTMLAnchorElement)
          const next = event.key === 'Home' ? 0 : event.key === 'End' ? links.length - 1 : (current + (event.key === 'ArrowDown' ? 1 : -1) + links.length) % links.length
          links[next]?.focus()
        }}
      >
        {items.map((item, index) => (
          <NavbarItem key={index} isDropdownItem activeClassName="dropdown__link--active" {...item} />
        ))}
      </ul>
    </div>
  )
}
