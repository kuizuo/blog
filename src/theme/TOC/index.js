import React, { useEffect } from "react";
import OriginalTOC from "@theme-original/TOC";
// import Ad from "../../components/Ad";
// import Adsense from "@site/src/components/Adsense";
// import adConfig from "../../components/Ad/config";

import styles from "./styles.module.css";

// import clsx from "clsx";

function TOC({ ...rest }) {
  // const { sidebar } = adConfig;

  return (
    <div className={styles.sidebarContainer}>
      <OriginalTOC {...rest} />
      {/* <div className={styles.ads}>
        {sidebar.map(({ id, alt, imageSrc, link }) => (
          <Ad key={id} link={link} src={imageSrc} alt={alt} />
        ))}
      </div> */}
      <section>
        {/* <Adsense format="auto" responsive="true" slot="2034513429" /> */}
      </section>
    </div>
  );
}

export default TOC;
