import Layout from '@theme/Layout'
import Link from '@docusaurus/Link'
import Translate, { translate } from '@docusaurus/Translate'
import { Icon } from '@iconify/react'
import type Plyr from 'plyr'
import 'plyr/dist/plyr.css'
import { type RefObject, useEffect, useMemo, useRef, useState } from 'react'
import { useReducedMotion } from 'motion/react'

import Comment from '@site/src/components/Comment'
import { type VideoCategory, type VideoItem, videoCategoryLabels, videos } from '@site/data/videos'
import collection from '@site/src/css/collection.module.css'
import styles from './styles.module.css'

const TITLE = translate({ id: 'videos.title', message: '手指极限' })
const DESCRIPTION = translate({ id: 'videos.description', message: '献丑罢了' })
const ALL_CATEGORY = 'all'

type CategoryFilter = typeof ALL_CATEGORY | VideoCategory

function formatDate(date?: string): string {
  if (!date) return translate({ id: 'videos.date.unknown', message: '未标注日期' })

  return date
}

function getCategoryLabel(category: CategoryFilter): string {
  if (category === ALL_CATEGORY) return translate({ id: 'videos.category.all', message: '全部' })

  return translate({ id: `videos.category.${category}`, message: videoCategoryLabels[category] })
}

function getVideoTags(video: VideoItem, limit: number): string[] {
  const categoryLabel = getCategoryLabel(video.category)

  return [categoryLabel, ...(video.tags ?? [])]
    .filter((tag, index, tags) => tags.indexOf(tag) === index)
    .slice(0, limit)
}

function VideoThumbnail({ video, className }: { video: VideoItem, className?: string }) {
  if (video.poster) {
    return (
      <>
        <Icon icon="ri:play-line" className={styles.thumbnailFallback} aria-hidden="true" />
        <img src={video.poster} alt="" className={className} loading="lazy" decoding="async" onError={(event) => { event.currentTarget.hidden = true }} />
      </>
    )
  }

  return (
    <video
      className={className}
      src={`${video.src}#t=0.1`}
      preload="metadata"
      muted
      playsInline
      aria-label={video.title}
    />
  )
}

function EmptyState() {
  return (
    <section className={styles.emptyState}>
      <div className={styles.emptyIcon} aria-hidden="true">
        <Icon icon="ri:movie-2-line" />
      </div>
      <h2><Translate id="videos.empty.title">影像正在整理中</Translate></h2>
      <p><Translate id="videos.empty.description">整理好新的片段后，会放在这里。</Translate></p>
    </section>
  )
}

function VideoPlayer({ video }: { video: VideoItem }) {
  const videoRef = useRef<HTMLVideoElement>(null)
  const playerRef = useRef<Plyr | null>(null)
  const latestVideoRef = useRef(video)

  function updatePlayerSource(player: Plyr, nextVideo: VideoItem) {
    player.source = {
      type: 'video',
      title: nextVideo.title,
      sources: [
        {
          src: nextVideo.src,
          type: nextVideo.type,
        },
      ],
      ...(nextVideo.poster ? { poster: nextVideo.poster } : {}),
    }
  }

  useEffect(() => {
    let destroyed = false
    let player: Plyr | null = null

    async function initPlayer() {
      const { default: PlyrConstructor } = await import('plyr')

      if (destroyed || !videoRef.current) return

      player = new PlyrConstructor(videoRef.current, {
        controls: ['play-large', 'play', 'progress', 'current-time', 'duration', 'mute', 'volume', 'settings', 'fullscreen'],
        ratio: '16:9',
      })
      playerRef.current = player
      updatePlayerSource(player, latestVideoRef.current)
    }

    initPlayer()

    return () => {
      destroyed = true
      player?.destroy()
      if (playerRef.current === player) {
        playerRef.current = null
      }
    }
  }, [])

  useEffect(() => {
    latestVideoRef.current = video
    if (playerRef.current) {
      updatePlayerSource(playerRef.current, video)
    }
  }, [video])

  return (
    <video
      ref={videoRef}
      className={styles.videoElement}
      playsInline
      controls
      aria-label={video.title}
    />
  )
}

function VideoStage({
  activeVideo,
  filteredVideos,
  activeVideoId,
  onSelectVideo,
  stageRef,
}: {
  activeVideo: VideoItem
  filteredVideos: VideoItem[]
  activeVideoId: string
  onSelectVideo: (videoId: string) => void
  stageRef: RefObject<HTMLElement>
}) {
  const activeTags = getVideoTags(activeVideo, 3)
  const playlistRef = useRef<HTMLDivElement>(null)
  const reduceMotion = useReducedMotion()

  useEffect(() => {
    const container = playlistRef.current
    const selected = container?.querySelector<HTMLButtonElement>('[aria-current="true"]')
    if (!container || !selected) return

    const bounds = container.getBoundingClientRect()
    const item = selected.getBoundingClientRect()
    const left = Math.min(0, item.left - bounds.left) + Math.max(0, item.right - bounds.right)
    const top = Math.min(0, item.top - bounds.top) + Math.max(0, item.bottom - bounds.bottom)
    container.scrollBy({ left, top, behavior: reduceMotion ? 'auto' : 'smooth' })
  }, [activeVideoId, reduceMotion])

  return (
    <section className={styles.stage} ref={stageRef} tabIndex={-1} aria-labelledby="active-video-title">
      <div className={styles.playerColumn}>
        <div className={styles.playerShell}>
          <VideoPlayer video={activeVideo} />
        </div>
        <div className={styles.activeMeta}>
          <div>
            <h2 id="active-video-title">{activeVideo.title}</h2>
            {activeVideo.description && <p>{activeVideo.description}</p>}
            <p className={styles.activeDetails}>
              {activeVideo.date && <time dateTime={activeVideo.date}>{activeVideo.date}</time>}
              {activeVideo.duration && <span>{activeVideo.duration}</span>}
            </p>
          </div>
          <div className={styles.activeTags}>
            {activeTags.map(tag => <span key={tag}>{tag}</span>)}
          </div>
        </div>
      </div>

      <aside className={styles.playlist} aria-label={translate({ id: 'videos.playlist', message: '播放列表' })}>
        <div className={styles.playlistHeader}>
          <h2><Translate id="videos.playlist">播放列表</Translate></h2>
          <span><Translate id="videos.count" values={{ count: filteredVideos.length }}>{'{count} 个视频'}</Translate></span>
        </div>
        <div className={styles.playlistItems} ref={playlistRef}>
          {filteredVideos.map((video) => {
            const isActive = video.id === activeVideoId

            return (
              <button
                key={video.id}
                type="button"
                className={isActive ? `${styles.playlistItem} ${styles.playlistItemActive}` : styles.playlistItem}
                onClick={() => onSelectVideo(video.id)}
                aria-current={isActive ? 'true' : undefined}
              >
                <span className={styles.playlistThumbWrap}>
                  {isActive && <Icon icon="ri:play-fill" className={styles.playingIcon} />}
                  <VideoThumbnail video={video} className={styles.playlistThumb} />
                </span>
                <span className={styles.playlistText}>
                  <span>{video.title}</span>
                  <span>{video.duration ?? '--:--'}</span>
                </span>
              </button>
            )
          })}
        </div>
      </aside>
    </section>
  )
}

function FilterBar({
  categories,
  selectedCategory,
  onSelectCategory,
}: {
  categories: CategoryFilter[]
  selectedCategory: CategoryFilter
  onSelectCategory: (category: CategoryFilter) => void
}) {
  return (
    <div className={styles.filterBar} role="group" aria-label={translate({ id: 'videos.categories', message: '视频分类' })}>
      <div className={styles.filterButtons}>
        {categories.map((category) => {
          const isSelected = category === selectedCategory

          return (
            <button
              key={category}
              type="button"
              className={isSelected ? `${styles.filterButton} ${styles.filterButtonActive}` : styles.filterButton}
              onClick={() => onSelectCategory(category)}
              aria-pressed={isSelected}
            >
              {getCategoryLabel(category)}
            </button>
          )
        })}
      </div>
    </div>
  )
}

function VideoGrid({
  videos: gridVideos,
  activeVideoId,
  onSelectVideo,
}: {
  videos: VideoItem[]
  activeVideoId: string
  onSelectVideo: (videoId: string) => void
}) {
  return (
    <div className={styles.grid}>
      {gridVideos.map((video) => {
        const isActive = video.id === activeVideoId
        const cardTags = getVideoTags(video, 2)

        return (
          <button
            key={video.id}
            type="button"
            className={isActive ? `${styles.card} ${styles.cardActive}` : styles.card}
            onClick={() => onSelectVideo(video.id)}
            aria-pressed={isActive}
          >
            <span className={styles.cardMedia}>
              <VideoThumbnail video={video} className={styles.cardThumb} />
              {isActive && <span className={styles.currentLabel}><Translate id="videos.current">当前视频</Translate></span>}
              <span className={styles.duration}>{video.duration ?? '--:--'}</span>
            </span>
            <span className={styles.cardBody}>
              <span className={styles.cardTitle}>{video.title}</span>
              <span className={styles.cardInfo}>
                <span className={styles.cardTags}>
                  {cardTags.map(tag => <span key={tag}>{tag}</span>)}
                </span>
                <span>{formatDate(video.date)}</span>
              </span>
            </span>
          </button>
        )
      })}
    </div>
  )
}

function VideosContent() {
  const stageRef = useRef<HTMLElement>(null)
  const pendingPlayerFocus = useRef(false)
  const reduceMotion = useReducedMotion()
  const availableCategories = useMemo<CategoryFilter[]>(() => {
    const categorySet = new Set<VideoCategory>()
    videos.forEach(video => categorySet.add(video.category))

    return [ALL_CATEGORY, ...Object.keys(videoCategoryLabels).filter((category): category is VideoCategory =>
      categorySet.has(category as VideoCategory),
    )]
  }, [])

  const [selectedCategory, setSelectedCategory] = useState<CategoryFilter>(ALL_CATEGORY)
  const [activeVideoId, setActiveVideoId] = useState(videos[0]?.id ?? '')

  const filteredVideos = useMemo(() => {
    if (selectedCategory === ALL_CATEGORY) return videos

    return videos.filter(video => video.category === selectedCategory)
  }, [selectedCategory])

  const activeVideo = filteredVideos.find(video => video.id === activeVideoId) ?? filteredVideos[0]

  function focusPlayer() {
    stageRef.current?.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' })
    stageRef.current?.focus({ preventScroll: true })
  }

  useEffect(() => {
    if (!pendingPlayerFocus.current) return
    pendingPlayerFocus.current = false
    focusPlayer()
  }, [activeVideo?.id, reduceMotion])

  function handleSelectCategory(category: CategoryFilter) {
    if (category === selectedCategory) return
    setSelectedCategory(category)
    const nextVideos = category === ALL_CATEGORY ? videos : videos.filter(video => video.category === category)
    setActiveVideoId(nextVideos[0]?.id ?? '')
  }

  function handleGridSelect(videoId: string) {
    if (videoId === activeVideo?.id) {
      focusPlayer()
      return
    }
    pendingPlayerFocus.current = true
    setActiveVideoId(videoId)
  }

  if (videos.length === 0 || !activeVideo) {
    return <EmptyState />
  }

  return (
    <>
      <VideoStage
        activeVideo={activeVideo}
        filteredVideos={filteredVideos}
        activeVideoId={activeVideo.id}
        onSelectVideo={setActiveVideoId}
        stageRef={stageRef}
      />
      <section className={styles.library} aria-labelledby="video-library-title">
        <div className={styles.libraryHeader}>
          <h2 id="video-library-title">
            <Translate id="videos.library">视频片段</Translate>
            <span>{filteredVideos.length}</span>
          </h2>
          <FilterBar
            categories={availableCategories}
            selectedCategory={selectedCategory}
            onSelectCategory={handleSelectCategory}
          />
        </div>
        <VideoGrid
          videos={filteredVideos}
          activeVideoId={activeVideo.id}
          onSelectVideo={handleGridSelect}
        />
      </section>
    </>
  )
}

export default function VideosPage(): JSX.Element {
  return (
    <Layout title={TITLE} description={DESCRIPTION}>
      <main className={`${collection.page} ${styles.page}`}>
        <div className={collection.container}>
          <header className={collection.header}>
            <div>
              <h1 className={collection.title}>{TITLE}</h1>
              <p className={collection.description}>{DESCRIPTION}</p>
            </div>
            <Link href="https://www.instagram.com/kuizuo12/" className={collection.textLink} target="_blank" rel="noopener noreferrer">
              <Icon icon="ri:instagram-line" width={20} height={20} aria-hidden="true" />
              Instagram · @kuizuo12
              <span aria-hidden="true">↗</span>
            </Link>
          </header>
          <VideosContent />
          <section className={styles.comments} aria-labelledby="video-comments-title">
            <h2 id="video-comments-title"><Translate id="videos.comments">聊两句</Translate></h2>
            <Comment />
          </section>
        </div>
      </main>
    </Layout>
  )
}
