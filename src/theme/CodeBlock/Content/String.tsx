import { usePrismTheme, useThemeConfig } from '@docusaurus/theme-common'
import {
  containsLineNumbers,
  parseCodeBlockTitle,
  parseLanguage,
  parseLines,
  useCodeWordWrap,
} from '@docusaurus/theme-common/internal'
import { Icon } from '@iconify/react'
import { cn } from '@site/src/lib/utils'
import Container from '@theme/CodeBlock/Container'
import type { Props } from '@theme/CodeBlock/Content/String'
import CopyButton from '@theme/CodeBlock/CopyButton'
import Line from '@theme/CodeBlock/Line'
import WordWrapButton from '@theme/CodeBlock/WordWrapButton'
import { Highlight, type Language } from 'prism-react-renderer'
import React from 'react'

import styles from './styles.module.css'

// Prism languages are always lowercase
// We want to fail-safe and allow both "php" and "PHP"
// See https://github.com/facebook/docusaurus/issues/9012
function normalizeLanguage(language: string | undefined): string | undefined {
  return language?.toLowerCase()
}

function parseIcon(metastring?: string): JSX.Element | null {
  const iconRegex = /icon=(?<quote>["'])(?<icon>.*?)\1/

  const icon = metastring?.match(iconRegex)?.groups?.icon ?? ''

  if (!icon) return null

  return <Icon icon={icon} width="16" />
}

export default function CodeBlockString({
  children,
  className: blockClassName = '',
  metastring,
  title: titleProp,
  showLineNumbers: showLineNumbersProp,
  language: languageProp,
}: Props): JSX.Element {
  const {
    prism: { defaultLanguage, magicComments },
  } = useThemeConfig()
  const language = normalizeLanguage(languageProp ?? parseLanguage(blockClassName) ?? defaultLanguage)

  const prismTheme = usePrismTheme()
  const wordWrap = useCodeWordWrap()

  // We still parse the metastring in case we want to support more syntax in the
  // future. Note that MDX doesn't strip quotes when parsing metastring:
  // "title=\"xyz\"" => title: "\"xyz\""
  const title = parseCodeBlockTitle(metastring) || titleProp

  const icon = parseIcon(metastring)

  const { lineClassNames, code } = parseLines(children, {
    metastring,
    language,
    magicComments,
  })
  const showLineNumbers = showLineNumbersProp ?? containsLineNumbers(metastring)

  return (
    <Container
      as="div"
      className={cn(
        blockClassName,
        language && !blockClassName.includes(`language-${language}`) && `language-${language}`,
      )}
    >
      {title && (
        <div className={styles.codeBlockTitle}>
          {icon}
          {title}
          <span style={{ flex: 1, textAlign: 'right' }}>{language}</span>
        </div>
      )}
      <div className={styles.codeBlockContent}>
        <Highlight theme={prismTheme} code={code} language={(language ?? 'text') as Language}>
          {({ className, style, tokens, getLineProps, getTokenProps }) => (
            <pre
              ref={wordWrap.codeBlockRef}
              className={cn(className, styles.codeBlock, 'thin-scrollbar')}
              style={style}
            >
              <code className={cn(styles.codeBlockLines, showLineNumbers && styles.codeBlockLinesWithNumbering)}>
                {tokens.map((line, i) => (
                  <Line
                    key={i}
                    line={line}
                    getLineProps={getLineProps}
                    getTokenProps={getTokenProps}
                    classNames={lineClassNames[i]}
                    showLineNumbers={showLineNumbers}
                  />
                ))}
              </code>
            </pre>
          )}
        </Highlight>
        <div className={styles.buttonGroup}>
          {(wordWrap.isEnabled || wordWrap.isCodeScrollable) && (
            <WordWrapButton
              className={styles.codeButton}
              onClick={() => wordWrap.toggle()}
              isEnabled={wordWrap.isEnabled}
            />
          )}
          <CopyButton className={styles.codeButton} code={code} />
        </div>
      </div>
    </Container>
  )
}
