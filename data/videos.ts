export type VideoCategory =
  | 'pen'
  | 'cube'
  | 'cardistry'
  | 'zippo'
  | 'other'

export interface VideoItem {
  id: string
  title: string
  src: string
  type: 'video/mp4' | 'video/webm'
  category: VideoCategory
  tags?: string[]
  date?: string
  duration?: string
  poster?: string
  description?: string
}

export const videoCategoryLabels: Record<VideoCategory, string> = {
  pen: '转笔',
  cube: '魔方',
  cardistry: '花切',
  zippo: 'Zippo',
  other: '其他',
}

export const videos: VideoItem[] = [
  {
    id: 'pen-spin',
    title: '转笔',
    src: 'https://img.kuizuo.me/videos/pen-spin.mp4',
    type: 'video/mp4',
    category: 'pen',
    tags: ['转笔'],
    date: '2018-04-05',
    duration: '0:14',
    poster: 'https://img.kuizuo.me/videos/posters/pen-spin.jpg',
  },
  {
    id: 'zippo',
    title: 'Zippo',
    src: 'https://img.kuizuo.me/videos/zippo.mp4',
    type: 'video/mp4',
    category: 'zippo',
    tags: ['Zippo'],
    date: '2018-04-05',
    duration: '0:17',
    poster: 'https://img.kuizuo.me/videos/posters/zippo.jpg',
  },
  {
    id: 'Knucklebone',
    title: 'Knucklebone',
    src: 'https://img.kuizuo.me/videos/bone.mp4',
    type: 'video/mp4',
    category: 'other',
    tags: ['Knucklebone'],
    date: '2018-12-12',
    duration: '0:13',
    poster: 'https://img.kuizuo.me/videos/posters/bone.jpg',
  },
  {
    id: 'begleri',
    title: 'Begleri',
    src: 'https://img.kuizuo.me/videos/begleri.mp4',
    type: 'video/mp4',
    category: 'other',
    tags: ['Begleri'],
    date: '2022-08-22',
    duration: '0:20',
    poster: 'https://img.kuizuo.me/videos/posters/begleri.jpg',
  },
  {
    id: 'phone-rotate',
    title: '手机旋转',
    src: 'https://img.kuizuo.me/videos/phone-rotate.mp4',
    type: 'video/mp4',
    category: 'other',
    tags: ['手机', '旋转'],
    date: '2024-11-07',
    duration: '0:41',
    poster: 'https://img.kuizuo.me/videos/posters/phone-rotate.jpg',
  },
  {
    id: 'card-spin',
    title: '单卡旋转',
    src: 'https://img.kuizuo.me/videos/card-spin.mp4',
    type: 'video/mp4',
    category: 'cardistry',
    tags: ['单卡', '旋转'],
    date: '2024-11-16',
    duration: '0:07',
    poster: 'https://img.kuizuo.me/videos/posters/card-spin.jpg',
  },
  {
    id: 'card-rotate',
    title: '纸牌旋转',
    src: 'https://img.kuizuo.me/videos/card-rotate.mp4',
    type: 'video/mp4',
    category: 'cardistry',
    tags: ['纸牌', '旋转'],
    date: '2025-04-03',
    duration: '0:09',
    poster: 'https://img.kuizuo.me/videos/posters/card-rotate.jpg',
  },
  {
    id: 'riffle-fan',
    title: 'Riffle Fan 开扇',
    src: 'https://img.kuizuo.me/videos/riffle-fan.mp4',
    type: 'video/mp4',
    category: 'cardistry',
    tags: ['纸牌', '开扇'],
    date: '2025-04-05',
    duration: '0:11',
    poster: 'https://img.kuizuo.me/videos/posters/riffle-fan.jpg',
  },
  {
    id: 'phone-spin',
    title: '转手机',
    src: 'https://img.kuizuo.me/videos/phone-spin.mp4',
    type: 'video/mp4',
    category: 'other',
    tags: ['手机', '控制'],
    date: '2025-04-25',
    duration: '0:10',
    poster: 'https://img.kuizuo.me/videos/posters/phone-spin.jpg',
  },
]
