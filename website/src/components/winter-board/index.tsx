import {
  type CSSProperties,
  useLayoutEffect,
  useEffect,
  useState,
  useRef,
} from 'react'
import type { WorkerRemoteMessage, WorkerMessage } from './worker/messages'

// create worker at runtime (webpack 5 / Docusaurus supports new URL(..., import.meta.url))

interface WinterBoardProps {
  className?: string
  style?: CSSProperties
}

export function WinterBoard(props: WinterBoardProps) {
  const { className, style } = props
  const [readyWorker, setReadyWorker] = useState<Worker | undefined>()

  useEffect(() => {
    // create worker dynamically so bundlers can handle it
    const worker = new Worker(new URL('./worker', import.meta.url), { type: 'module' })
    worker.addEventListener('message', (event) => {
      const msg = event.data as WorkerRemoteMessage
      if (msg.type === 'ready') {
        setReadyWorker(worker)
      }
    })

    return () => {
      worker.terminate()
    }
  }, [setReadyWorker])

  if (readyWorker) {
    return (
      <WinterBoardCanvas
        className={className}
        style={style}
        worker={readyWorker}
      />
    )
  }

  return null
}

function WinterBoardCanvas(props: WinterBoardProps & { worker: Worker }) {
  const { className, style, worker } = props
  const ref = useRef<HTMLDivElement>(null)

  useLayoutEffect(() => {
    if (!ref.current) return () => {}

    const canvas = document.createElement('canvas')
    canvas.style.width = '100%'
    canvas.style.height = '100%'

    const offscreenCanvas = canvas.transferControlToOffscreen()
    worker.postMessage(
      { type: 'attach', canvas: offscreenCanvas } satisfies WorkerMessage,
      [offscreenCanvas],
    )

    ref.current.appendChild(canvas)

    const resizeObserver = new ResizeObserver(() => {
      // FIXME: our renderer is DPI-dependent currently.
      const scaleFactor = 2 /* window.devicePixelRatio */
      const width = canvas.clientWidth * scaleFactor
      const height = canvas.clientHeight * scaleFactor
      worker.postMessage({
        type: 'resize',
        width,
        height,
      } satisfies WorkerMessage)
    })
    resizeObserver.observe(canvas)

    return () => {
      resizeObserver.disconnect()
      canvas.remove()
      worker.postMessage({ type: 'detach' } satisfies WorkerMessage)
    }
  }, [ref, worker])

  return <div ref={ref} className={className} style={style} />
}
