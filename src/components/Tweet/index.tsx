import BrowserOnly from '@docusaurus/BrowserOnly'
import { Tweet as ReactTweet } from 'react-tweet'

export default function Tweet({ id }: { id: string }) {
  return (
    <BrowserOnly fallback={<div>Loading...</div>}>
      {() => (
        <span className="flex justify-center">
          <ReactTweet id={id} />
        </span>
      )}
    </BrowserOnly>
  )
}
