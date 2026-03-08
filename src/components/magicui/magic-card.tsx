import { cn } from '@site/src/lib/utils'
import { type CSSProperties, type ReactNode, useCallback, useEffect, useRef } from 'react'

interface MagicContainerProps {
  children?: ReactNode
  className?: string
}

const MagicContainer = ({ children, className }: MagicContainerProps) => {
  const containerRef = useRef<HTMLDivElement>(null)
  const boxesRef = useRef<HTMLElement[]>([])
  const rafIdRef = useRef<number | null>(null)
  const pendingEventRef = useRef<MouseEvent | null>(null)
  const containerSizeRef = useRef<{ w: number; h: number }>({ w: 0, h: 0 })

  const syncSize = useCallback(() => {
    if (containerRef.current) {
      containerSizeRef.current.w = containerRef.current.offsetWidth
      containerSizeRef.current.h = containerRef.current.offsetHeight
      boxesRef.current = Array.from(containerRef.current.children) as HTMLElement[]
    }
  }, [])

  useEffect(() => {
    syncSize()
    window.addEventListener('resize', syncSize)
    return () => window.removeEventListener('resize', syncSize)
  }, [syncSize])

  useEffect(() => {
    const container = containerRef.current
    if (!container) return

    const handleMouseMove = (e: MouseEvent) => {
      pendingEventRef.current = e
      if (rafIdRef.current !== null) return

      rafIdRef.current = requestAnimationFrame(() => {
        rafIdRef.current = null
        const evt = pendingEventRef.current
        pendingEventRef.current = null
        if (!evt || !containerRef.current) return

        // Single container read — no forced reflow per box
        const containerRect = containerRef.current.getBoundingClientRect()
        const mouseX = evt.clientX - containerRect.left
        const mouseY = evt.clientY - containerRect.top
        const { w, h } = containerSizeRef.current
        const inside = mouseX >= 0 && mouseX <= w && mouseY >= 0 && mouseY <= h

        const boxes = boxesRef.current
        // Batch all reads first, then batch all writes — eliminates layout thrashing
        const boxRects = boxes.map(box => box.getBoundingClientRect())
        boxes.forEach((box, i) => {
          const br = boxRects[i]
          box.style.setProperty('--mouse-x', `${mouseX - (br.left - containerRect.left)}px`)
          box.style.setProperty('--mouse-y', `${mouseY - (br.top - containerRect.top)}px`)
          box.style.setProperty('--opacity', inside ? '1' : '0')
        })
      })
    }

    const handleMouseLeave = () => {
      if (rafIdRef.current !== null) {
        cancelAnimationFrame(rafIdRef.current)
        rafIdRef.current = null
      }
      boxesRef.current.forEach(box => box.style.setProperty('--opacity', '0'))
    }

    container.addEventListener('mousemove', handleMouseMove)
    container.addEventListener('mouseleave', handleMouseLeave)
    return () => {
      container.removeEventListener('mousemove', handleMouseMove)
      container.removeEventListener('mouseleave', handleMouseLeave)
      if (rafIdRef.current !== null) cancelAnimationFrame(rafIdRef.current)
    }
  }, [])

  return (
    <div className={cn('h-full w-full', className)} ref={containerRef}>
      {children}
    </div>
  )
}

interface MagicCardProps {
  /**
   * @default <div />
   * @type ReactElement
   * @description
   * The component to be rendered as the card
   * */
  as?: React.ReactElement
  /**
   * @default ""
   * @type string
   * @description
   * The className of the card
   */
  className?: string

  /**
   * @default ""
   * @type ReactNode
   * @description
   * The children of the card
   * */
  children?: ReactNode

  /**
   * @default 600
   * @type number
   * @description
   * The size of the spotlight effect in pixels
   * */
  size?: number

  /**
   * @default true
   * @type boolean
   * @description
   * Whether to show the spotlight
   * */
  spotlight?: boolean

  /**
   * @default "rgba(255,255,255,0.03)"
   * @type string
   * @description
   * The color of the spotlight
   * */
  spotlightColor?: string

  /**
   * @default true
   * @type boolean
   * @description
   * Whether to isolate the card which is being hovered
   * */
  isolated?: boolean

  /**
   * @default "rgba(255,255,255,0.03)"
   * @type string
   * @description
   * The background of the card
   * */
  background?: string

  [key: string]: any
}

const MagicCard: React.FC<MagicCardProps> = ({
  className,
  children,
  size = 600,
  spotlight = true,
  borderColor = 'var(--content-background)',
  isolated = true,
  ...props
}) => {
  return (
    <div
      style={
        {
          '--mask-size': `${size}px`,
          '--border-color': `${borderColor}`,
        } as CSSProperties
      }
      className={cn(
        'relative z-0 h-full w-full rounded-2xl',
        'bg-[radial-gradient(var(--mask-size)_circle_at_var(--mouse-x)_var(--mouse-y),var(--border-color),transparent_100%)]',
        className,
      )}
      {...props}
    >
      {children}
    </div>
  )
}

export { MagicCard, MagicContainer }
