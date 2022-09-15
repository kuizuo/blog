import React, {
  useState,
  CSSProperties,
  useLayoutEffect,
  useRef,
  useEffect,
} from 'react';
import clsx from 'clsx';
import {
  PageMetadata,
  useColorMode,
  createStorageSlot,
} from '@docusaurus/theme-common';
import Layout from '@theme/Layout';
import * as sandpackThemes from '@codesandbox/sandpack-themes';
import {
  SandpackCodeEditor,
  SandpackConsole,
  SandpackFileExplorer,
  SandpackLayout,
  SandpackPreview,
  SandpackProvider,
  SandpackTests,
  SandpackPredefinedTemplate,
  SANDBOX_TEMPLATES,
  SANDPACK_THEMES,
  SandpackStack,
} from '@codesandbox/sandpack-react';
import styles from './styles.module.css';

const ConsoleIcon = (): React.ReactElement => (
  <svg
    fill="currentColor"
    height="16"
    viewBox="0 0 16 16"
    width="16"
    xmlns="http://www.w3.org/2000/svg">
    <title>Open browser console</title>
    <path d="M5.65871 3.62037C5.44905 3.44066 5.1334 3.46494 4.95368 3.6746C4.77397 3.88427 4.79825 4.19992 5.00792 4.37963L5.65871 3.62037ZM5.00792 11.6204C4.79825 11.8001 4.77397 12.1157 4.95368 12.3254C5.1334 12.5351 5.44905 12.5593 5.65871 12.3796L5.00792 11.6204ZM9.9114 7.92407L10.2368 7.54445L9.9114 7.92407ZM5.00792 4.37963L9.586 8.3037L10.2368 7.54445L5.65871 3.62037L5.00792 4.37963ZM9.586 7.6963L5.00792 11.6204L5.65871 12.3796L10.2368 8.45555L9.586 7.6963ZM9.586 8.3037C9.39976 8.14407 9.39976 7.85594 9.586 7.6963L10.2368 8.45555C10.5162 8.2161 10.5162 7.7839 10.2368 7.54445L9.586 8.3037Z" />
    <path d="M10 11.5C9.72386 11.5 9.5 11.7239 9.5 12C9.5 12.2761 9.72386 12.5 10 12.5V11.5ZM14.6667 12.5C14.9428 12.5 15.1667 12.2761 15.1667 12C15.1667 11.7239 14.9428 11.5 14.6667 11.5V12.5ZM10 12.5H14.6667V11.5H10V12.5Z" />
  </svg>
);

const ConsoleCounterButton: React.FC<{
  onClick: () => void;
  counter: number;
}> = ({onClick, counter}) => {
  return (
    <button
      className={clsx('sp-button', styles.consoleButton)}
      onClick={onClick}>
      <ConsoleIcon />
      {counter > 0 && <span>{counter}</span>}
    </button>
  );
};

const getPreviewHeight =
  (
    showConsoleButton?: boolean,
    editorHeight: CSSProperties['height'] = `var(--sp-layout-height)`,
  ) =>
  (ratio = 2): string | number | undefined => {
    if (showConsoleButton) {
      const height =
        typeof editorHeight === 'number' ? `${editorHeight}px` : editorHeight;

      return `calc(${height} / ${ratio})`;
    }

    return editorHeight;
  };

const themes = sandpackThemes as unknown as typeof SANDPACK_THEMES;

function MySandPack() {
  const [theme, setTheme] = useState<string>('aquaBlue');
  const [template, setTemplate] = useState<SandpackPredefinedTemplate>('react');
  const [counter, setCounter] = useState(0);
  const [consoleVisibility, setConsoleVisibility] = useState(false);
  const [editorHeight, setEditorHeight] = useState(1000);
  const {colorMode} = useColorMode();

  const actionsChildren = (
    <ConsoleCounterButton
      counter={counter}
      onClick={(): void => setConsoleVisibility((prev) => !prev)}
    />
  );

  const rightColumnItemHeight = getPreviewHeight(
    consoleVisibility,
    editorHeight,
  );

  const templateFiles =
    SANDBOX_TEMPLATES[template as SandpackPredefinedTemplate] ?? {};
  const mode = 'mode' in templateFiles ? templateFiles.mode : 'preview';

  const editorPart = 50;
  const previewPart = 100 - editorPart;

  const rightColumnStyle = {
    flexGrow: previewPart,
    flexShrink: previewPart,
    minWidth: 700 * (previewPart / (previewPart + editorPart)),
    gap: consoleVisibility ? 1 : 0,
  };

  const SandpackStorage = createStorageSlot('sandpack');

  const firstUpdate = useRef(true);

  useLayoutEffect(() => {
    if (firstUpdate.current) {
      firstUpdate.current = false;
      return;
    } else {
      colorMode === 'dark' ? setTheme('nightOwl') : setTheme('aquaBlue');
    }
  }, [colorMode]);

  useEffect(() => {
    const config = JSON.parse(
      SandpackStorage.get()! ?? '{"theme":"aquaBlue","template":"react"}',
    );
    const {theme, template} = config;
    setTheme(theme);
    setTemplate(template);

    setEditorHeight(window.innerHeight - 101);
  }, []);

  useEffect(() => {
    SandpackStorage.set(
      JSON.stringify({
        theme,
        template,
      }),
    );
  }, [theme, template]);

  return (
    <>
      <nav className={styles.liveCodeNav}>
        <a
          className={styles.navbarBrand}
          href="https://sandpack.codesandbox.io">
          <div className={styles.navbarLogo}>
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 100 100"
              fill={colorMode === 'dark' ? '#000' : '#fff'}
              style={{height: '100%'}}>
              <rect
                x="49.9973"
                y="24.489"
                width="32.2814"
                height="65.0273"
                stroke={colorMode === 'dark' ? '#fff' : '#000'}
                strokeWidth="6.96721"
              />
              <rect
                x="17.4836"
                y="11.4836"
                width="32.2814"
                height="65.0273"
                stroke={colorMode === 'dark' ? '#fff' : '#000'}
                strokeWidth="6.96721"
              />
            </svg>
          </div>
          <b className={styles.navbarTitle}>Sandpack</b>
        </a>
        <div className={styles.control}>
          <div className={styles.select}>
            Template
            <select
              name="Template"
              value={template}
              style={{marginLeft: '.5rem'}}
              onChange={({target}) =>
                setTemplate(target.value as SandpackPredefinedTemplate)
              }>
              {Object.keys(SANDBOX_TEMPLATES).map((item) => (
                <option value={item} key={item}>
                  {item}
                </option>
              ))}
            </select>
          </div>
          <div className={styles.select}>
            Theme
            <select
              value={theme}
              style={{marginLeft: '.5rem'}}
              onChange={({target}) => setTheme(target.value)}>
              {Object.keys(themes).map((item) => (
                <option value={item} key={item}>
                  {item}
                </option>
              ))}
            </select>
          </div>
        </div>
      </nav>
      <div className={styles.sandpackBox}>
        {/* <SandPackBox></SandPackBox> */}
        <SandpackProvider template={template} theme={themes[theme]}>
          <SandpackLayout style={{'--sp-layout-height': editorHeight + 'px'}}>
            <SandpackFileExplorer />
            <SandpackCodeEditor
              {...{
                showTabs: true,
                showLineNumbers: true,
                showInlineErrors: true,
                showNavigator: true,
                closableTabs: true,
                wrapContent: true,
              }}
            />
            <SandpackStack>
              {mode === 'preview' && (
                <SandpackPreview
                  actionsChildren={actionsChildren}
                  showNavigator={true}
                  showRefreshButton={true}
                  style={{
                    ...rightColumnStyle,
                    height: rightColumnItemHeight(consoleVisibility ? 1.5 : 1),
                  }}
                />
              )}
              {mode === 'tests' && (
                <SandpackTests
                  actionsChildren={actionsChildren}
                  style={{
                    ...rightColumnStyle,
                    height: rightColumnItemHeight(consoleVisibility ? 1.5 : 1),
                  }}
                />
              )}

              <div
                className={styles.consoleWrapper}
                style={{
                  height: consoleVisibility ? rightColumnItemHeight(3) : 0,
                }}>
                <SandpackConsole
                  onLogsChange={(logs): void => setCounter(logs.length)}
                  showHeader={true}
                />
              </div>
            </SandpackStack>
          </SandpackLayout>
        </SandpackProvider>
      </div>
    </>
  );
}

export default function LiveCode() {
  const title = '在线代码';
  const description = '基于 Sandpack 的在线代码编辑器';

  return (
    <>
      <PageMetadata title={title} description={description} />
      <Layout noFooter>
        <MySandPack></MySandPack>
      </Layout>
    </>
  );
}
