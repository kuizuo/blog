/**
 * 自动生成博客、文档或视频教程文本工具
 */

import figlet from "figlet";
import chalk from "chalk";
import inquirer from "inquirer";
import fs from "fs";
import path from "path";
import shell from "shelljs";
import fetch from "isomorphic-fetch";
import dotEnv from "dotenv";
import { getYuqueDocs, getYuqueDoc } from "./common.mjs";
import { createDoc } from "./common.mjs";

dotEnv.config();

export async function askBlogInfo() {
  const repo = process.env.BLOG_REPO;
  const yuqueDocs = await getYuqueDocs(repo);

  const questions = [
    {
      type: "list",
      name: "yuqueDocInfo",
      message: "请选择关联文档",
      choices: yuqueDocs,
    },
    {
      type: "input",
      name: "blogName",
      message: "请输入文件名：",
    },
  ];

  const { blogName, yuqueDocInfo } = await inquirer.prompt(questions);

  // get date
  const now = new Date();
  const finalBlogName = `${now.getFullYear()}-${(
    "0" +
    (now.getMonth() + 1)
  ).slice(-2)}-${("0" + now.getDate()).slice(-2)}-${blogName}`;

  // create img directory
  if (!fs.existsSync(`blog/img/${finalBlogName}`)) {
    fs.mkdirSync(`blog/img/${finalBlogName}`);
  }

  createDoc(yuqueDocInfo.slug, repo, (tmpFileName) => {
    shell.exec(
      `hygen blog new ${finalBlogName} --title "${yuqueDocInfo.title}" --tmp ${tmpFileName} --slug ${blogName}`
    );
  });
}
