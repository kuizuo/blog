export const mac_tools: Friend[] = [
    {
        title: 'AltTab',
        description: 'AltTab brings the power of Windows’s “alt-tab” window switcher to macOS.',
        website: 'https://alt-tab-macos.netlify.app/',
        // avatar: '/img/friend/zxuqian.png',
        avatar: '',
    },
    {
        title: 'pap.er',
        description: '专为 Mac 设计的壁纸应用',
        website: 'https://paper.meiyuan.in/',
        // avatar: '/img/friend/zxuqian.png',
        avatar: '',
    },
]

export type Friend = {
    title: string
    description: string
    website: string
    avatar?: any
}
