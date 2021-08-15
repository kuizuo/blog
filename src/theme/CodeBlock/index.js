import React from "react";
import InitialCodeBlock from "@theme-original/CodeBlock";

function CodeBlock(props) {
  return props.preview ? (
    <>
      <InitialCodeBlock {...props} />
      <p>预览：</p>
      <iframe
        sandbox
        srcdoc={props.children}
        style={{
          width: "100%",
          height: "100%",
          border: "2px dashed hsl(0deg 0% 90%)",
        }}
      ></iframe>
    </>
  ) : (
    <InitialCodeBlock {...props} />
  );
}

export default CodeBlock;
