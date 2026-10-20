import type { CSSProperties, ReactNode } from 'react'
import styles from './styles.module.css'

type Props<T extends string> = {
  label: string
  value: T
  options: readonly { value: T, label: ReactNode, icon?: ReactNode }[]
  onChange: (value: T) => void
  controls?: string
}

export default function SegmentedControl<T extends string>({ label, value, options, onChange, controls }: Props<T>) {
  const selected = options.findIndex(option => option.value === value)
  return (
    <div className={styles.control} role="group" aria-label={label} style={{ '--segments': options.length } as CSSProperties}>
      <span className={styles.selection} aria-hidden="true" style={{ transform: `translateX(${selected * 100}%)` }} />
      {options.map(option => (
        <button key={option.value} type="button" onClick={() => onChange(option.value)} aria-pressed={value === option.value} aria-controls={controls}>
          {option.icon}
          {option.label}
        </button>
      ))}
    </div>
  )
}
