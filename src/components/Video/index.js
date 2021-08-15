import React from "react";

function Video({ src, webmSrc, ...rest }) {
  return (
    <video autoPlay loop muted playsInline {...rest}>
      {webmSrc && <source src={webmSrc} type="video/webm" />}
      <source src={src} type="video/mp4" />
    </video>
  );
}

export default Video;
