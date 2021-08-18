import React, { useEffect, useState } from "react";

// import useFollowers from "./useFollowers";
import styles from "./styles.module.css";

function Clock(props) {
  const [date, setDate, getDate] = useState(new Date());
  const [time] = useState({});
  useEffect(() => {
    var timerID = setInterval(() => tick(), 1000);

    let difftime = date.getTime() - 1560009600000
    let diffDate = new Date(difftime)
    var day = parseInt(difftime / 60 / 60 / 60 / 1000);
    time.day = day
    time.hour = diffDate.getHours().toString().padStart(2, '0')
    time.minute = diffDate.getMinutes().toString().padStart(2, '0')
    time.second = diffDate.getSeconds().toString().padStart(2, '0')
    return function cleanup() {
      clearInterval(timerID);
    };
  });

  function tick() {
    setDate(new Date());
  }

  return (
    <div>
      <div style={{ "text-align": "center" }}>入坑时间</div>
      <div className={styles.clock}>
        <div className={`clock-item day`}>
          <div>天</div>
          <span>{time.day}</span>
        </div>
        <div className={`clock-item`}>
          <div>时</div>
          <span>{time.hour}</span>
        </div>
        <div className={`clock-item`}>
          <div>分</div>
          <span>{time.minute}</span>
        </div>
        <div className={`clock-item`}>
          <div>秒</div>
          <span>{time.second}</span>
        </div>
      </div>
    </div>
  );
}

export default Clock;
