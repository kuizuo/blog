export type Social = {
  github?: string
  LinkedIn?: string
  email?: string
}

type SocialValue = {
  href?: string
  title: string
  icon: string
  color: string
}

const social: Social = {
  github: 'https://github.com/el1ziane',
  LinkedIn: 'https://www.linkedin.com/in/eliziane-rb/',
  email: 'mailto:eliziane.com.br@gmail.com',
}

const socialSet: Record<keyof Social, SocialValue> = {
  github: {
    href: social.github,
    title: 'GitHub',
    icon: 'ri:github-line',
    color: '#010409',
  },
  LinkedIn: {
    href: social.LinkedIn,
    title: 'LinkedIn',
    icon: 'ri:linkedin-line',
    color: '#000',
  },
  email: {
    href: social.email,
    title: 'Email',
    icon: 'ri:mail-line',
    color: '#D44638',
  },

}

export default socialSet
