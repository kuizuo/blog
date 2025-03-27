export const projects: Project[] = [
  {
    title: 'HortiControle',
    description: 'Sistema desenvolvido para o estágio obrigatório da facultade de Engenharia de Software',
    preview: '/img/project/dashboard.png',
    website: 'https://el1ziane.vercel.app/blog/hortiControle',
    source: 'https://github.com/kuizuo/blog',
    tags: ['programação', 'design', 'produto'],
    type: 'web',
  },
  {
    title: 'Desofuscador de Código JS',
    description: 'Ferramenta baseada no Babel para restaurar código JavaScript ofuscado',
    preview: '/img/project/js-deobfuscator.png',
    website: 'https://js-deobfuscator.vercel.app',
    source: 'https://github.com/kuizuo/js-deobfuscator',
    tags: ['opensource', 'favorito'],
    type: 'web',
  },

  {
    title: 'Servidor de API',
    description: '🔗 Site de serviço de API baseado em Nuxt',
    preview: '/img/project/kz-api.png',
    website: 'https://api.kuizuo.cn',
    source: 'https://github.com/kuizuo/api-service',
    tags: ['opensource', 'favorito', 'produto'],
    type: 'web',
  },
]

export type Tag = {
  label: string
  description: string
  color: string
}

export type TagType = 'favorito' | 'opensource' | 'produto' | 'design' | 'programação' | 'pessoal'

export type ProjectType = 'web' | 'app' | 'comercial' | 'pessoal' | 'brinquedo' | 'outro'

export const projectTypeMap = {
  web: '🖥️ Site',
  app: '💫 Aplicativo',
  comercial: 'Projeto Comercial',
  pessoal: '👨‍💻 Pessoal',
  brinquedo: '🔫 Experimento',
  outro: '🗃️ Outros',
}

export type Project = {
  title: string
  description: string
  preview?: string
  website: string
  source?: string | null
  tags: TagType[]
  type: ProjectType
}

export const Tags: Record<TagType, Tag> = {
  favorito: {
    label: 'Favorito',
    description: 'Meus sites favoritos, você precisa conferir!',
    color: '#e9669e',
  },
  opensource: {
    label: 'Código Aberto',
    description: 'Projetos open source que podem inspirar!',
    color: '#39ca30',
  },
  produto: {
    label: 'Produto',
    description: 'Projetos relacionados a produtos!',
    color: '#dfd545',
  },
  design: {
    label: 'Design',
    description: 'Sites bem projetados!',
    color: '#a44fb7',
  },
  programação: {
    label: 'Programação',
    description: 'Projetos de programação',
    color: '#8c2f00',
  },
  pessoal: {
    label: 'Pessoal',
    description: 'Projetos pessoais',
    color: '#12affa',
  },
}

export const TagList = Object.keys(Tags) as TagType[]

export const groupByProjects = projects.reduce(
  (group, project) => {
    const { type } = project
    group[type] = group[type] ?? []
    group[type].push(project)
    return group
  },
  {} as Record<ProjectType, Project[]>,
)
