import { useEffect, useState } from 'react';

export default function useViews(items) {
  // Get all post views
  const titles = items.map(({ content }) => {
    return content?.frontMatter?.title;
  });
  const [views, setViews] = useState([]);
  const getViews = async () => {
    try {
      const res = await fetch('https://blog.kuizuo.cn/posts/views', {
        method: 'POST',
        body: JSON.stringify(titles),
        headers: {
          'Content-Type': 'application/json',
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
