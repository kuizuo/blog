import ora from "ora";
import chalk from "chalk";
import fs from "fs";

/**
 * 获取语雀文档列表
 * @param repo
 * @returns
 */
export async function getYuqueDocs(repo) {
  const spinner = ora(chalk.blue("加载文档列表...")).start();

  const token = process.env.YUQUE_TOKEN;
  // 获取语雀文档列表
  // `https://www.yuque.com/api/v2/repos/fenghua-uy38l/gbo7r6/docs`,
  const res = await fetch(`https://www.yuque.com/api/v2/repos/${repo}/docs`, {
    headers: {
      "X-Auth-Token": token,
    },
  });

  const { data = {} } = await res.json();
  spinner.succeed(chalk.green("加载文档列表成功"));
  return []
  return data.map((doc, index) => ({
    name: `${index + 1}. ${doc.title}`,
    value: { slug: doc.slug, title: doc.title },
    short: doc.title.slice(0, 18) + "...",
  }));
}

/**
 * 获取语雀文档详情
 * @param slug
 * @param repo
 * @returns
 */
export async function getYuqueDoc(slug, repo) {
  const token = process.env.YUQUE_TOKEN;

  const spinner = ora(chalk.blue("获取文档 markdown...")).start();

  // 获取视频详情 API
  const res = await fetch(
    `https://www.yuque.com/api/v2/repos/${repo}/docs/${slug}?raw=1`,
    {
      headers: {
        "X-Auth-Token": token,
      },
    }
  );
  const resData = await res.json();
  // console.log(resData.data.body_draft);
  spinner.succeed(chalk.green("获取文档 markdown成功!"));
  return resData.data.body_draft;
}

export async function createDoc(slug, repo, callback) {
  // get yuque doc body
  const lakeBody = await getYuqueDoc(slug, repo);
  const cleanBody = lakeBody.replace(/<a name="[\w]{5}"><\/a>|<br \/>/g, "\n");

  if (!fs.existsSync("tmp")) {
    fs.mkdirSync("tmp");
  }
  const fileName = new Date().getTime();
  fs.writeFileSync(`tmp/${fileName}`, cleanBody);

  callback(fileName);

  // remove tmp
  fs.rmSync(`tmp/${fileName}`);
}
