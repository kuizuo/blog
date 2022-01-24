import { useEffect, useState } from 'react';

export default function useViews(item) {
  // Get all post views
  const title = item?.frontMatter?.title;

  const [views, setViews] = useState(0);
  const getViews = async () => {
    try {
      const res = await fetch('https://blog.kuizuo.cn/posts/views', {
        method: 'POST',
        body: JSON.stringify([title]),
        // mode: 'no-cors',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
      });
      const views = await res.json();
      setViews(views?.[0].views ?? Math.floor(Math.random() * (10 - 1)) + 1);
    } catch (error) {}
  };

  useEffect(() => {
    getViews();
  }, []);

  return views;
}
