# WorkBuddy 每日签到（GitHub Actions）

用 Python 脚本调用 WorkBuddy 签到接口，配合 GitHub Actions 每天自动签到。

## 背景：为什么原来好使、现在不好使了

WorkBuddy 桌面端 **5.6.2+** 默认开启了 `AtRestEncryption`。认证文件

```
C:\Users\admin\AppData\Local\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info
```

里的 `auth.accessToken` 从原来的明文 JWT（`eyJ...` 开头的字符串）变成了 **AES-256-GCM 加密信封**：

```json
"accessToken": { "$wbEncrypted": 1, "envelope": "...base64..." }
```

解密密钥**不落盘**，只驻留在 WorkBuddy 客户端进程内存中。因此：

- **本地运行**：本脚本会调用本机 WorkBuddy 自带的 Electron 运行时，在隐藏子进程里解密（`ELECTRON_RUN_AS_NODE=1` + 客户端原生绑定取密钥），明文令牌只在内存里使用，不写文件。
- **GitHub Actions**：云端 runner 上没有 WorkBuddy 客户端，无法解密。所以要把**本机解密后的明文 token**填进 GitHub Secrets，脚本在 CI 里直接读环境变量。token 会过期（约 28 天），到期后在本机重新跑一次 `--export-token` 更新 Secret 即可。

## 使用方法

### 1. 本机导出明文 token（仅 Windows/macOS 本机运行）

```bash
python checkin.py --export-token
```

脚本会调用本机 WorkBuddy 运行时解密，输出如下内容（**不要提交、不要公开**）：

```
WORKBUDDY_ACCESS_TOKEN=eyJhbGciOi...（很长）
WORKBUDDY_ACCOUNT_NAME=你的昵称
WORKBUDDY_UID=a1d1ba46-...
WORKBUDDY_DOMAIN=www.codebuddy.cn
WORKBUDDY_ENTERPRISE_ID=
```

> 如果提示找不到 WorkBuddy 客户端，用环境变量指定路径后重试：
> `set WORKBUDDY_EXE=D:\Program Files\WorkBuddy\WorkBuddy.exe`（Windows）

### 2. 配置 GitHub Secrets

进入仓库 **Settings → Secrets and variables → Actions → New repository secret**，把上面每一项的值分别建成 Secret：

| Secret 名称 | 是否必填 | 说明 |
| --- | --- | --- |
| `WORKBUDDY_ACCESS_TOKEN` | ✅ | 明文 JWT，完整复制，不带引号/空格 |
| `WORKBUDDY_ACCOUNT_NAME` | 否 | 仅用于日志显示 |
| `WORKBUDDY_UID` | 否 | 本地 auth 里的 `account.uid` |
| `WORKBUDDY_DOMAIN` | 否 | 默认 `www.codebuddy.cn` |
| `WORKBUDDY_ENTERPRISE_ID` | 否 | 企业版账号才需要 |

### 3. 启用 GitHub Actions

`.github/workflows/checkin.yml` 已配置：

- 每天北京时间 09:05（UTC 01:05）自动运行；
- 支持在 Actions 页面手动 **Run workflow** 触发测试。

推送代码后，到 Actions 页面手动触发一次确认能正常签到。

## 本地直接运行

```bash
python checkin.py
```

优先级：`config.json` → 环境变量 → 本地客户端（加密令牌会自动解密）。
CI 环境（`GITHUB_ACTIONS` / `CI`）只从环境变量读取 Secrets。

## Token 过期

导出的 token 有效期约 28 天（见 JWT 的 `exp` 字段）。过期后签到会失败（HTTP 401），
重新登录一次 WorkBuddy 桌面端，再执行 `python checkin.py --export-token` 并把新的
`WORKBUDDY_ACCESS_TOKEN` 更新到 GitHub Secrets 即可。

## 免责声明

仅供个人学习与自动化签到使用，请遵守 WorkBuddy 服务条款。令牌属于敏感凭据，请勿泄露。
参考教程：<https://blog.csdn.net/m0_65382359/article/details/163495784>
