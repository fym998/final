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

## 任务1：
1. 输入：压缩包(tar，tar.gz，7z，zip等等自行补充)
2. 第一步处理（固件中提取出所有的，可读文件类（类似vscode直接全局搜索字符串的），apk类，二进制文件类bin、sbin）
3. 第二步处理（针对上面的文件进行正则匹配分析，参考已有的python文件），输出域名、ip、存储桶信息、证书密钥(敏感信息，.key .pem等等)
4. 第三步处理（对进行上述内容，利用AI接口进行清洗，只要外网的部分，输出车企相关的域名、ip、存储桶等信息）
5. 输出，4个csv表格，表头定义
    - （序号、ip、国家、城市、数据的文件来源）
    - （序号、域名、国家、城市、归属企业、数据的文件来源）
    - （序号、存储桶密钥、文件来源）
    - （序号、证书内容、文件来源）


## 任务2：
1. 输入：一个压缩包，内包含多个pcap格式流量包
2. AI清洗
3. 输出，两个csv表格
    - （序号、ip、国家、城市、数据的文件来源）
    - （序号、域名、国家、城市、归属企业、数据的文件来源）
