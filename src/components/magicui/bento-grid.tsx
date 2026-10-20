import { cn } from '@site/src/lib/utils'

export const BentoGrid = ({
  className,
  children,
}: {
  className?: string
  children?: React.ReactNode
}) => {
  return (
    <div className={cn('mx-auto grid max-w-7xl grid-cols-1 gap-6 md:grid-cols-3', className)}>
      {children}
    </div>
  )
}

export const BentoGridItem = ({
  className,
  title,
  description,
  header,
  icon,
}: {
  className?: string
  title?: string | React.ReactNode
  description?: string | React.ReactNode
  header?: React.ReactNode
  icon?: React.ReactNode
}) => {
  return (
    <div
      className={cn(
        'flex min-w-0 flex-col gap-6 rounded-xl border border-border bg-background p-4',
        className,
      )}
    >
      <div className="flex h-40 items-center justify-center [&>svg]:max-h-full [&>svg]:w-full" aria-hidden="true">{header}</div>
      <div>
        <h3 className="mb-3 flex items-center gap-2 text-lg leading-relaxed font-semibold">
          {icon}
          {title}
        </h3>
        <div className="text-sm leading-relaxed text-secondary">{description}</div>
      </div>
    </div>
  )
}
