
## 下载项目
方式一:
```bash
git clone git@github.com:ydaydayup/vue-vben-admin.git

git submodule init

git submodule update
```

方式二:
```bash
git clone --recurse-submodules  git@github.com:ydaydayup/vue-vben-admin.git
```
其中有 `DbConnector` 目录，不过是空的。 你必须运行两个命令：`git submodule init` 用来初始化本地配置文件，而 `git submodule update` 则从该项目中抓取所有数据并检出父项目中列出的合适的提交。

python manage.py runserver 0.0.0.0:8000 



---

# 环境搭建

## [#](http://124.222.210.96/document/hjbs.html#%E5%87%86%E5%A4%87%E5%B7%A5%E4%BD%9C)准备工作

```
Python >= 3.8.0 (推荐3.8+版本)
nodejs >= 16.0 (推荐最新)
Mysql >= 5.7.0 (可选，默认数据库sqlite3，推荐8.0版本)
Redis(可选，最新版)
```



## [#](http://124.222.210.96/document/hjbs.html#%E4%B8%8B%E8%BD%BD%E4%BB%A3%E7%A0%81)下载代码

- 通过 Gitee 下载页面([https://gitee.com/fuadmin/fu-admin.git (opens new window)](https://gitee.com/fuadmin/fu-admin.git))，下载解压到工作目录
- 通过 `git clone https://gitee.com/fuadmin/fu-admin.git` 下载到工作目录

## [#](http://124.222.210.96/document/hjbs.html#%E5%89%8D%E7%AB%AF-%E2%99%9D)前端 ♝

```
# 克隆项目
git https://gitee.com/fuadmin/fu-admin.git

# 进入项目目录
cd web

# 安装依赖
yarn install --registry=https://registry.npm.taobao.org

# 启动服务
yarn run dev
# 浏览器访问 http://localhost:8080
# .env 文件中可配置启动端口等参数
# 构建生产环境
# yarn run build
```



## [#](http://124.222.210.96/document/hjbs.html#%E5%90%8E%E7%AB%AF-%F0%9F%92%88)后端 💈

```
# 克隆项目
git https://gitee.com/fuadmin/fu-admin.git
# 进入项目目录
cd backend
# 在 `env.py` 中配置数据库信息
# 默认是Mysql，如果使用SqlServer，qing在requirements.txt中打开 
   mssql-django==1.1.2 
   pyodbc==4.0.32
# 安装依赖环境
	pip3 install -r requirements.txt
# 执行迁移命令：
	python3 manage.py makemigrations system
	python3 manage.py migrate
# 初始化数据
	pdm run python  manage.py init
# 初始化省市县数据:
   pdm run python  manage.py init_area

# 启动项目
	pdm run python manage.py runserver 0.0.0.0:8000
	
#  任何情况不要使用 daphne :
```



## [#](http://124.222.210.96/document/hjbs.html#%E8%AE%BF%E9%97%AE%E9%A1%B9%E7%9B%AE)访问项目

- 文档访问地址：[http://localhost:8080/api/docs (opens new window)](http://localhost:8080/api/docs)(默认为此地址，如有修改请按照配置文件)
- 账号：`superadmin` 密码：`123456`