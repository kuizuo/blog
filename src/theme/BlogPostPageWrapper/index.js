import React from "react";
import BlogPostPage from "@theme/BlogPostPage";

function BlogPostPageWrapper(props) {
  return (
    <div>
      <BlogPostPage {...props} />
    </div>
  );
}

export default BlogPostPageWrapper;
