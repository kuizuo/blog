export type Friend = {
  title: string;
  description: string;
  website: string;
  avatar?: any;
};

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
  {
    title: 'Jetzihan',
    description: '有黑羽快斗必有我',
    website: 'https://jetzihan.netlify.app/',
    avatar: require('./avatar/jetzihan.png'),
  },
  {
    title: 'KnIFeR',
    description: 'Web开发学习者，分享编程相关的技术和见闻',
    website: 'http://knifer.fun/',
    avatar: require('./avatar/knifer.png'),
  },
  {
    title: 'Pincman',
    description: '中年老码农,专注于全栈开发与教学',
    website: 'https://pincman.com/',
    avatar: require('./avatar/pincman.png'),
  },
  {
    title: '前端老怪兽',
    description: '一只会敲代码的怪兽',
    website: 'https://zswei.xyz/',
    avatar: require('./avatar/old_monster.png'),
  },
  {
    title: 'Meoo',
    description: '一杯茶，一根网线，一台电脑',
    website: 'https://meoo.space/',
    avatar: require('./avatar/meoo.png'),
  },
  {
    title: '尚宇',
    description: '心怀理想，仰望星空，埋头苦干',
    website: 'https://www.disnox.top/',
    avatar: require('./avatar/disnox.png'),
  },
];

export function sortFriend() {
  const result = Friends;

  return result;
}
