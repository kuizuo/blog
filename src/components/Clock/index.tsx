import React, {useEffect, useState} from 'react';

// import useFollowers from "./useFollowers";
import styles from './styles.module.css';

function Clock(props) {
  const [date, setDate, getDate] = useState(new Date());
  const [time] = useState({
    day: 0,
    hour: 0,
    minute: 0,
    second: 0,
  });

  useEffect(() => {
    const timerID = setInterval(() => tick(), 1000);

    const difftime = date.getTime() - 1560009600000;
    const diffDate = new Date(difftime);
    const day = parseInt(difftime / 24 / 60 / 60 / 1000);
    time.day = day;
    time.hour = diffDate.getHours().toString().padStart(2, '0');
    time.minute = diffDate.getMinutes().toString().padStart(2, '0');
    time.second = diffDate.getSeconds().toString().padStart(2, '0');
    return function cleanup() {
      clearInterval(timerID);
    };
  });

  function tick() {
    setDate(new Date());
  }

  return (
    <div className={styles.clock}>
      <p className={styles.date}>成功入坑时间</p>
      <p className={styles.time}>
        {time.day + '天' + time.hour + '时' + time.minute + '分'}
      </p>
    </div>
  );
}

export default Clock;
