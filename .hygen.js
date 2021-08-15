// hygen 生成器辅助函数库
module.exports = {
  helpers: {
    // 用于生成 yyyy-MM-dd 文章标题的日期部分
    date: () => new Date().toISOString().slice(0, 10)
  }
};
