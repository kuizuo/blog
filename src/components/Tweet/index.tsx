import BrowserOnly from '@docusaurus/BrowserOnly'
import { Component, type ReactNode } from 'react'
import { EmbeddedTweet, TweetNotFound, TweetSkeleton, useTweet } from 'react-tweet'
import type { Tweet as TweetData } from 'react-tweet/api'

function normalizeEntityList(value: unknown) {
  return Array.isArray(value) ? value : []
}

function normalizeDisplayRange(value: unknown, text: string): [number, number] {
  if (
    Array.isArray(value)
    && typeof value[0] === 'number'
    && typeof value[1] === 'number'
  ) {
    return [value[0], value[1]]
  }

  return [0, Array.from(text).length]
}

function normalizeTweet(tweet: any): any {
  const text = typeof tweet.text === 'string' ? tweet.text : ''
  const entities = tweet.entities ?? {}

  return {
    ...tweet,
    text,
    display_text_range: normalizeDisplayRange(tweet.display_text_range, text),
    entities: {
      ...entities,
      hashtags: normalizeEntityList(entities.hashtags),
      urls: normalizeEntityList(entities.urls),
      user_mentions: normalizeEntityList(entities.user_mentions),
      symbols: normalizeEntityList(entities.symbols),
      ...(entities.media ? { media: normalizeEntityList(entities.media) } : {}),
    },
    parent: tweet.parent ? normalizeTweet(tweet.parent) : tweet.parent,
    quoted_tweet: tweet.quoted_tweet ? normalizeTweet(tweet.quoted_tweet) : tweet.quoted_tweet,
  }
}

function TweetFallback({ id }: { id: string }) {
  return (
    <span className="flex justify-center">
      <a href={`https://x.com/i/web/status/${id}`} target="_blank" rel="noopener noreferrer">
        查看这条推文
      </a>
    </span>
  )
}

class TweetErrorBoundary extends Component<
  { id: string, children: ReactNode },
  { hasError: boolean }
> {
  override state = { hasError: false }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  override componentDidCatch(error: unknown) {
    console.error(`Failed to render tweet ${this.props.id}`, error)
  }

  override render() {
    if (this.state.hasError) {
      return <TweetFallback id={this.props.id} />
    }

    return this.props.children
  }
}

function TweetEmbed({ id }: { id: string }) {
  const { data, error, isLoading } = useTweet(id)

  if (isLoading) {
    return <TweetSkeleton />
  }

  if (error || !data) {
    return <TweetNotFound error={error} />
  }

  return <EmbeddedTweet tweet={normalizeTweet(data) as TweetData} />
}

export default function Tweet({ id }: { id: string }) {
  return (
    <BrowserOnly fallback={<div>Loading...</div>}>
      {() => (
        <span className="flex justify-center">
          <TweetErrorBoundary id={id}>
            <TweetEmbed id={id} />
          </TweetErrorBoundary>
        </span>
      )}
    </BrowserOnly>
  )
}
