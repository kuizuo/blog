import { existsSync } from 'node:fs'
import { readdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { input, select } from '@inquirer/prompts'

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const blogDir = path.join(rootDir, 'blog')
const invalidFileNameChars = /[/:*?"<>|\\]/

function formatDate(date) {
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')

  return `${year}-${month}-${day}`
}

function validateNonEmpty(value, fieldName) {
  if (!value.trim()) {
    return `请输入${fieldName}`
  }

  return true
}

function parseTags(value) {
  return value
    .split(/[,，]/)
    .map(tag => tag.trim())
    .filter(Boolean)
}

function buildContent({ slug, title, date, tags }) {
  const tagText = tags.join(', ')

  return `---
slug: ${slug}
title: ${title}
date: ${date}
authors: kuizuo
tags: [${tagText}]
keywords: [${tagText}]
---

xxx

{/* truncate */}
`
}

async function getBlogDirectoryChoices() {
  const entries = await readdir(blogDir, { withFileTypes: true })

  return entries
    .filter(entry => entry.isDirectory())
    .map(entry => ({
      name: path.join('blog', entry.name),
      value: entry.name,
    }))
    .sort((current, next) => current.name.localeCompare(next.name))
}

async function main() {
  const directoryChoices = await getBlogDirectoryChoices()

  if (directoryChoices.length === 0) {
    throw new Error('blog 目录下没有可选择的分类目录')
  }

  const directory = await select({
    message: '选择文章目录',
    choices: directoryChoices,
  })

  const title = await input({
    message: '输入文章标题',
    validate: (value) => {
      const result = validateNonEmpty(value, '文章标题')

      if (result !== true) {
        return result
      }

      if (invalidFileNameChars.test(value)) {
        return '标题不能包含 / : * ? " < > | 或反斜杠'
      }

      return true
    },
  })

  const slug = await input({
    message: '输入 slug',
    validate: value => validateNonEmpty(value, 'slug'),
  })

  const tags = await input({
    message: '输入标签，多个标签用逗号分隔',
    validate: (value) => {
      if (parseTags(value).length === 0) {
        return '请至少输入一个标签'
      }

      return true
    },
  })

  const filePath = path.join(blogDir, directory, `${title.trim()}.md`)

  if (existsSync(filePath)) {
    throw new Error(`文件已存在：${path.relative(rootDir, filePath)}`)
  }

  const content = buildContent({
    slug: slug.trim(),
    title: title.trim(),
    date: formatDate(new Date()),
    tags: parseTags(tags),
  })

  await writeFile(filePath, content, { flag: 'wx' })

  console.log(`已生成：${path.relative(rootDir, filePath)}`)
}

main().catch((error) => {
  if (error instanceof Error && error.name === 'ExitPromptError') {
    process.exit(1)
  }

  console.error(error instanceof Error ? error.message : error)
  process.exit(1)
})
