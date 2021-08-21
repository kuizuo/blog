import React from "react";

import { useTrail, animated } from "react-spring";
import Translate, { translate } from "@docusaurus/Translate";
import useDocusaurusContext from "@docusaurus/useDocusaurusContext";
import Link from "@docusaurus/Link";


import HeroMain from "./img/hero_main.svg";
import CSDNIcon from "@site/static/icons/csdn.svg";
import Juejincon from "@site/static/icons/juejin.svg";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faGithub,
  faQq
} from "@fortawesome/free-brands-svg-icons";
// import useBaseUrl from "@docusaurus/useBaseUrl";

// import useFollowers from "./useFollowers";

import styles from "./styles.module.css";

function Hero() {
  const {
    // 当前语言
    i18n: { currentLocale },
  } = useDocusaurusContext();



  // animation
  const animatedTexts = useTrail(5, {
    from: { opacity: 0, transform: "translateY(3em)" },
    to: { opacity: 1, transform: "translateY(0)" },
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
          <Translate description="hero greet">Hello! 我是</Translate>
          <span className={styles.intro__name}>
            <Translate description="my name">愧怍</Translate>
          </span>
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
                    description="Blog link label"
                  >
                    技术博客
                  </Translate>
                </Link>
              ),
              project: (
                <Link to="/project">
                  <Translate
                    id="hompage.hero.text.project"
                    description="Project link label"
                  >
                    实战项目
                  </Translate>
                </Link>
              ),
              links: (
                <Link to="/docs/resources">
                  <Translate
                    id="hompage.hero.text.link"
                    description="Link link label"
                  >
                    资源导航
                  </Translate>
                </Link>
              ),
            }}
          >
            {`点击查看最新{blogs}、{project}、{links}，在这里你能了解到各类实战开发的所遇到的问题，帮助你在学习的过程了解最新的技术栈，并希望我的个人经历对你有所启发。`}
          </Translate>
        </animated.p>
        {currentLocale === "zh-CN" && (
          <animated.p style={animatedTexts[3]}>
            <Translate id="homepage.qqgroup1" description="qq group1">
              QQ 群：980879514
            </Translate>
          </animated.p>
        )}
        <SocialLinks animatedProps={animatedTexts[4]} />
        {/* <animated.div style={animatedTexts[2]}>
          <Button
            isLink
            href={translate({
              id: "homepage.follow.link.href",
              message:
                "https://space.bilibili.com/302954484?from=search&seid=1788147379248960737",
              description: "social link bilibili or twitter",
            })}
          >
            <Translate description="follow me btn text">去B站关注</Translate>
            <Translate
              id="homepage.followers"
              description="followers"
              values={{ count: (Math.round(followers) / 10000).toFixed(1) }}
            >
              {" {count} 万"}
            </Translate>
          </Button>
        </animated.div> */}
      </div>

      <HeroMainImage />
      {/* <animated.div
      className="bloghome__scroll-down"
      style={animatedBackground}
    >
      <button>
        <ArrowDown />
      </button>
    </animated.div> */}
    </animated.div>
  );
}

function SocialLinks({ animatedProps, ...props }) {
  // const { isDarkTheme } = useThemeContext();
  return (
    <animated.div className={styles.social__links} style={animatedProps}>
      <a href="https://github.com/kuizuo">
        <FontAwesomeIcon icon={faGithub} size="lg" />
      </a>
      <a href="https://blog.csdn.net/kuizuo12">
        <CSDNIcon />
      </a>
      <a href="https://juejin.cn/user/1565318510545901">
        <Juejincon />
      </a>
      <a href="https://wpa.qq.com/msgrd?v=3&amp;uin=911993023&amp;site=qq">
        <FontAwesomeIcon icon={faQq} size="lg" />
      </a>
      {/*       <div className={`dropdown ${styles.dropdown} dropdown--hoverable`}>
        <FontAwesomeIcon icon={faQq} size="lg" />
        <img
          width="50%"
          className={`dropdown__menu ${styles.dropdown__menu}`}
          src={useBaseUrl("/img/publicQR.webp")}
        />
      </div> */}
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
