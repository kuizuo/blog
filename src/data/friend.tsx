export type Friend = {
  title: string
  description?: string
  website: string
  avatar?: any
}

export const Friends: Friend[] = [
  {
    title: '峰华前端工程师',
    description: '致力于帮助你以最直观、最快速的方式学会前端开发',
    website: 'https://zxuqian.cn',
    avatar: require('./avatar/zxuqian.png'),
  },
  {
    title: 'Mas0n',
    description: '梦想是咸鱼',
    website: 'https://blog.shi1011.cn/',
    avatar: require('./avatar/mas0n.png'),
  },
]

function sortFriend() {
  let result = Friends

  result.sort(() => 0.5 - Math.random())
  result = result.map((friend) => {
    const avatar = typeof friend.avatar === 'string' ? friend.avatar : friend.avatar.src.src
    return { ...friend, avatar }
  })
  return result
}

export const sortedFriends = sortFriend()
