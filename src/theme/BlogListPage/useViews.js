import { useEffect, useState } from "react";

export default function useViews(items) {
  // Get all post views
  const postIds = items.map(({ content }) => {
    return content?.frontMatter?.slug;
  });
  const [views, setViews] = useState([]);
  const getViews = async () => {
    try {
      const res = await fetch("https://api.zxuqian.cn/post/views", {
        method: "POST",
        body: JSON.stringify(postIds),
        headers: {
          "Content-Type": "application/json",
        },
      });
      const views = await res.json();
      setViews(views);
    } catch (error) {}
  };

  useEffect(() => {
    getViews();
  }, []);

  return views;
}
