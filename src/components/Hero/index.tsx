import React from 'react';

import {useTrail, animated} from 'react-spring';
import Translate, {translate} from '@docusaurus/Translate';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Link from '@docusaurus/Link';

import HeroMain from './img/hero_main.svg';

import GithubIcon from '@site/static/icons/github.svg';
import JuejinIcon from '@site/static/icons/juejin.svg';
import RssIcon from '@site/static/icons/rss.svg';
import QqIcon from '@site/static/icons/qq.svg';
import WxIcon from '@site/static/icons/wx.svg';
import CsdnIcon from '@site/static/icons/csdn.svg';
import CloudMusicIcon from '@site/static/icons/cloud-music.svg';
import TwitterIcon from '@site/static/icons/twitter.svg';
import Button from '../Button';

import styles from './styles.module.css';

function Hero() {
  const {
    // 当前语言
    i18n: {currentLocale},
  } = useDocusaurusContext();

  // animation
  const animatedTexts = useTrail(5, {
    from: {opacity: 0, transform: 'translateY(3em)'},
    to: {opacity: 1, transform: 'translateY(0)'},
    config: {
      mass: 3,
      friction: 45,
      tension: 460,
    },
  });

  return (
    <animated.div className={styles.hero}>
      <div className={styles.bloghome__intro}>
        <animated.div style={animatedTexts[0]} className={styles.hero_text}>
          你好! 我是
          <span className={styles.intro__name}>愧怍</span>
        </animated.div>
        <animated.p style={animatedTexts[1]}>
          <Translate
            id="homepage.hero.text"
            description="hero text"
            values={{
              blogs: (
                <Link to="#homepage_blogs">
                  <Translate
                    id="hompage.hero.text.blog"
                    description="Blog link label">
                    技术博客
                  </Translate>
                </Link>
              ),
              project: (
                <Link to="/project">
                  <Translate
                    id="hompage.hero.text.project"
                    description="Project link label">
                    实战项目
                  </Translate>
                </Link>
              ),
              links: (
                <Link to="/resources">
                  <Translate
                    id="hompage.hero.text.link"
                    description="Link link label">
                    资源导航
                  </Translate>
                </Link>
              ),
            }}>
            {`在这里你能了解到各类实战开发的所遇到的问题，帮助你在学习的过程了解最新的技术栈，并希望我的个人经历对你有所启发。`}
          </Translate>
        </animated.p>
        {/* {currentLocale === 'zh-CN' && (
          <animated.p style={animatedTexts[3]}>
            <Translate id='homepage.qqgroup1' description='qq group1'>
              QQ 群：5478458
            </Translate>
          </animated.p>
        )} */}
        <SocialLinks animatedProps={animatedTexts[4]} />
        {
          <animated.div style={animatedTexts[2]}>
            <Button isLink href={'./about'}>
              <Translate
                id="homepage.visitMyBlog.linkLabel"
                description="The label for the link to my blog">
                blog
              </Translate>
              <Translate>自我介绍</Translate>
            </Button>
          </animated.div>
        }
      </div>
      <HeroMainImage />
    </animated.div>
  );
}

export function SocialLinks({animatedProps, ...props}) {
  const {siteConfig} = useDocusaurusContext();
  const {themeConfig} = siteConfig;
  const socials = themeConfig.socials as {
    github: string;
    twitter: string;
    juejin: string;
    csdn: string;
    qq: string;
    wx: string;
    cloudmusic: string;
  };

  return (
    <animated.div className={styles.social__links} style={animatedProps}>
      <a href="./rss.xml" target="_blank">
        <RssIcon />
      </a>
      <a href={socials.github} target="_blank">
        <GithubIcon />
      </a>
      <a href={socials.juejin} target="_blank">
        <JuejinIcon />
      </a>
      {/* <a href='https://blog.csdn.net/kuizuo12' target='_blank'>
        <CsdnIcon />
      </a> */}
      <a href={socials.qq} target="_blank">
        <QqIcon />
      </a>
      {/* <a href='' target='_blank'>
        <WxIcon />
      </a> */}
      <a href={socials.twitter} target="_blank">
        <TwitterIcon />
      </a>
      <a href={socials.cloudmusic} target="_blank">
        <CloudMusicIcon />
      </a>
    </animated.div>
  );
}

function HeroMainImage() {
  return (
    <div className={styles.bloghome__image}>
      <HeroMain />
    </div>
  );
}

export default Hero;
