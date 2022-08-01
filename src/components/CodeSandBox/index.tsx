import React from "react";
import PropTypes from "prop-types";
import useThemeContext from "@theme/hooks/useThemeContext";

function index({ slug, title, height = "600px" }) {
  const { isDarkTheme } = useThemeContext();
  let themedSrc = `https://codesandbox.io/embed/${slug}?fontsize=14&hidenavigation=1&view=preview&theme=${
    isDarkTheme ? "dark" : "light"
  }`;
  return (
    <div>
      <iframe
        src={themedSrc}
        style={{
          width: "100%",
          height,
          border: 0,
          "border-radius": "4px",
          overflow: "hidden",
        }}
        title={title}
        allow="accelerometer; ambient-light-sensor; camera; encrypted-media; geolocation; gyroscope; hid; microphone; midi; payment; usb; vr; xr-spatial-tracking"
        sandbox="allow-forms allow-modals allow-popups allow-presentation allow-same-origin allow-scripts"
      ></iframe>
    </div>
  );
}

index.propTypes = {};

export default index;
