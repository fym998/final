# 大作业

## 协作：通过 pull request

1. 先 fork 本仓库，克隆产生的仓库，
2. 创建新分支: `git switch -c 分支名`，
3. 进行修改，创建提交
4. 将新的分支 push 到 GitHub: `git push`，
5. 在 GitHub 网页端创建 pull request，再合并入原仓库

## 环境：uv

### 安装uv

参考 [Installation | uv](https://docs.astral.sh/uv/getting-started/installation/)

Windows:
```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### 运行 python 文件

```shell
uv run 文件.py
```

### 安装 pip 包

uv 配置文件已经换源，无需再换

```shell
uv add 包名
```
