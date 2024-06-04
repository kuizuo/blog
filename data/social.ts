export type Social = {
  github?: string
  linkedin?:string
  twitter?: string
  spotify?: string
  email?: string
  discord?: string
}

type SocialValue = {
  href?: string
  title: string
  icon: string
  color: string
}

const social: Social = {
  github: 'https://github.com/fernandogprieto',
  linkedin: 'https://linkedin.com/in/fernandogprieto/',
  twitter: 'https://twitter.com/fernandogprieto',
  email: 'mailto:prieto.fernandog@gmail.com',
  discord: 'https://discord.gg/NhtJVXkD4p',
}

const socialSet: Record<keyof Social | 'rss', SocialValue> = {
  github: {
    href: social.github,
    title: 'GitHub',
    icon: 'ri:github-line',
    color: '#010409',
  },
  linkedin:{
    href: social.linkedin,
    title: 'LinkedIn',
    icon: 'ri:linkedin-line',
    color: '#010409',
  },
  twitter: {
    href: social.twitter,
    title: 'Twitter',
    icon: 'ri:twitter-line',
    color: '#1da1f2',
  },
  discord: {
    href: social.discord,
    title: 'Discord',
    icon: 'ri:discord-line',
    color: '#5A65F6',
  },
  email: {
    href: social.email,
    title: '邮箱',
    icon: 'ri:mail-line',
    color: '#D44638',
  },
  spotify: {
    href: social.spotify,
    title: '网易云',
    icon: 'ri:spotify-line',
    color: '#C20C0C',
  },
  rss: {
    href: '/blog/rss.xml',
    title: 'RSS',
    icon: 'ri:rss-line',
    color: '#FFA501',
  },
}

export default socialSet
