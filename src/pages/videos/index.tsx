import Layout from '@theme/Layout'
import { Icon } from '@iconify/react'
import type Plyr from 'plyr'
import 'plyr/dist/plyr.css'
import { useEffect, useMemo, useRef, useState } from 'react'

import { type VideoCategory, type VideoItem, videoCategoryLabels, videos } from '@site/data/videos'
import styles from './styles.module.css'

const TITLE = '手指极限'
const DESCRIPTION = '献丑罢了'
const ALL_CATEGORY = 'all'

type CategoryFilter = typeof ALL_CATEGORY | VideoCategory

function formatDate(date?: string): string {
  if (!date) return '未标注'

  return date
}

function getCategoryLabel(category: CategoryFilter): string {
  if (category === ALL_CATEGORY) return '全部'

  return videoCategoryLabels[category]
}

function getVideoTags(video: VideoItem, limit: number): string[] {
  const categoryLabel = videoCategoryLabels[video.category]

  return [categoryLabel, ...(video.tags ?? [])]
    .filter((tag, index, tags) => tags.indexOf(tag) === index)
    .slice(0, limit)
}

function VideoThumbnail({ video, className }: { video: VideoItem, className?: string }) {
  if (video.poster) {
    return <img src={video.poster} alt={video.title} className={className} loading="lazy" />
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
      <h2>影像正在整理中</h2>
      <p>等真实视频放上来后，这里会成为一面关于练习、手感和瞬间的影像墙。</p>
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
}: {
  activeVideo: VideoItem
  filteredVideos: VideoItem[]
  activeVideoId: string
  onSelectVideo: (videoId: string) => void
}) {
  const activeTags = getVideoTags(activeVideo, 3)

  return (
    <section className={styles.stage}>
      <div className={styles.playerColumn}>
        <div className={styles.playerShell}>
          <VideoPlayer video={activeVideo} />
        </div>
        <div className={styles.activeMeta}>
          <div>
            <h2>{activeVideo.title}</h2>
            {activeVideo.description && <p>{activeVideo.description}</p>}
          </div>
          <div className={styles.activeTags}>
            {activeTags.map(tag => <span key={tag}>{tag}</span>)}
          </div>
        </div>
      </div>

      <aside className={styles.playlist} aria-label="播放列表">
        <div className={styles.playlistHeader}>
          <h2>播放列表</h2>
          <span>
            {filteredVideos.length}
            {' '}
            个视频
          </span>
        </div>
        <div className={styles.playlistItems}>
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
                <Icon icon="ri:more-2-fill" className={styles.moreIcon} aria-hidden="true" />
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
    <div className={styles.filterBar} aria-label="视频分类">
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
    <section className={styles.grid} aria-label="视频墙">
      {gridVideos.map((video) => {
        const isActive = video.id === activeVideoId
        const cardTags = getVideoTags(video, 2)

        return (
          <button
            key={video.id}
            type="button"
            className={isActive ? `${styles.card} ${styles.cardActive}` : styles.card}
            onClick={() => onSelectVideo(video.id)}
          >
            <span className={styles.cardMedia}>
              <VideoThumbnail video={video} className={styles.cardThumb} />
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
    </section>
  )
}

function VideosContent() {
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

  function handleSelectCategory(category: CategoryFilter) {
    setSelectedCategory(category)
    const nextVideos = category === ALL_CATEGORY ? videos : videos.filter(video => video.category === category)
    setActiveVideoId(nextVideos[0]?.id ?? '')
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
      />
      <FilterBar
        categories={availableCategories}
        selectedCategory={selectedCategory}
        onSelectCategory={handleSelectCategory}
      />
      <VideoGrid
        videos={filteredVideos}
        activeVideoId={activeVideo.id}
        onSelectVideo={setActiveVideoId}
      />
    </>
  )
}

export default function VideosPage(): JSX.Element {
  return (
    <Layout title={TITLE} description={DESCRIPTION}>
      <main className={styles.page}>
        <div className={styles.container}>
          <header className={styles.header}>
            <h1>{TITLE}</h1>
            <p>{DESCRIPTION}</p>
          </header>
          <VideosContent />
        </div>
      </main>
    </Layout>
  )
}
