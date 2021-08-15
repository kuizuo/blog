import React, { useEffect, useState } from "react";
import PropTypes from "prop-types";
import styles from "./style.module.css";

function BVideo({ src, bsrc }) {
  // get aid
  // const params = new URLSearchParams(src.split("?")[1]);
  // const aid = params.get("aid");

  // const [view, setView] = useState("");

  // const getView = async () => {
  //   const resp = await fetch(
  //     `https://api.bilibili.com/archive_stat/stat?aid=${aid}`
  //   );
  //   const data = await resp.json();
  //   const { view } = data?.data;
  //   setView(view);
  // };

  // useEffect(() => {
  //   getView();
  // }, []);

  return (
    <>
      <iframe
        src={src}
        loading="lazy"
        scrolling="no"
        border={0}
        frameBorder="no"
        framespacing={0}
        allowFullScreen={true}
        // style={{ width: "100%", height: "500px" }}
        className={styles.videoFrame}
      ></iframe>
      {/* <div>
        <p>播放量：{view}</p>
      </div> */}
      {/* <div style={{ fontWeight: 800, padding: "2em 0" }}> */}
      {/* <a href={bsrc}>点击跳转到B站进行观看~记得给个三连哦！</a> */}
      {/* </div> */}
    </>
  );
}

BVideo.propTypes = {
  src: PropTypes.string.isRequired,
  bsrc: PropTypes.string,
};

export default BVideo;
