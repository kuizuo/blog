subtree 和 submodule 的目的都是用于 git 子仓库管理，二者的主要区别在于，subtree 属于拷贝子仓库，而 submodule 属于引用子仓库。


| 维度 | subtree | submodule | 优劣对比 |
| ---- | ---- | ---- | ---- |
| 空间占用 | subtree 在初始化 add 时，会将子仓库 copy 到父仓库中，并产生至少一次 merge 记录。所以会占用大量父仓库空间 | submodule 在初始化 add 时，会在父仓库新建一个 .gitmodules 文件，用于保存子仓库的 commit hash 引用。所以不会占用父仓库空间 | submodule 更优 |
| clone | subtree add 至父仓库之后，后续的 clone 操作与单一仓库操作相同 | 后续 clone 时 submodule 还需要 init/update 操作，且 submodule 子仓库有自己的分支 | subtree 更优 |
| update | 子仓库更新后，父仓库需要 subtree pull 操作，且命令行略长，需要指定 --prefix 参数。由于无法感知子仓库的存在，可能会产生 merge 冲突需要处理 | 子仓库更新后，父仓库需要 submodule update 操作。父仓库只需变动子仓库 hash 引用，不会出现冲突 | submodule 更优 |
| commit | 父仓库直接提交父子仓库目录里的变动。若修改了子仓库的文件，则需要执行 subtree push | 父子仓库的变动需要单独分别提交。且注意先提交子仓库再提交父仓库 | subtree 更优 |
## 2、Subtree 命令行简化[](#id-2subtree-ming-ling-hang-jian-hua)

subtree 在操作时，命令行较长，可以使用 remote 配置简化，例如
```bash
# 以下为标准 subtree add 命令行示例
git subtree add --prefix=centos-config --squash git@github.com:kaiye/centos-config.git master
​
# 可以简化为
# 1. 先为远程子仓库配置一个别名，便于后续的 pull 与 push 操作，这里例子以 centos 为别名
git remote add centos git@github.com:kaiye/centos-config.git # gra centos ...
​
# 2. 其中 --prefix= 简写为 -P，配置 --squash 表示不拉取子仓库的历史提交记录
git subtree add -P centos-config --squash centos master
​
# 后续更新子仓库可以使用
git subtree pull -P centos-config centos master
​
# 若发生 fatal: refusing to merge unrelated histories 报错，加上 --squash 参数即可

```

## 3、git submodule update 出错解决方案[](#id-3git-submodule-update-chu-cuo-jie-jue-fang-an)

假如在执行 git submodule update 时出现以下类似错误信息：

```bash
fatal: reference is not a tree: f869da471c5d8a185cd110bbe4842d6757b002f5
Unable to checkout 'f869da471c5d8a185cd110bbe4842d6757b002f5' in submodule path 'centos-config'
```

发生错误的原因是，centos-config 子仓库在某电脑 A 的「本地」commit 了新的版本 「f869da471c5d8a185cd110bbe4842d6757b002f5」，且该次 commit 未 push origin。但其父级仓库中引用了该子仓库的版本号，且将引用记录 push origin，导致其他用户无法 update 。

解决方案是，在电脑 A 上将子仓库 push origin 后，在其他客户机上执行 git submodule update 。或者使用 git reset，将子仓库的引用版本号还原成 origin 上存在的最新版本号。