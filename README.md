# dsh-config-sync

把本机 DSH（DeepSeek Harness）的**全部插件与设置**备份成一个可移植的 `.zip`，再批量同步到下一台电脑。

> 📖 **日常操作请看 [使用说明.md](使用说明.md)**——按"照着做"的口径编写，含换电脑完整流程、回退步骤和常见问题。本文档偏设计与实现。

## 它解决什么问题

换电脑时，DSH 的环境散落在很多地方：profile 里装了哪些插件、每个插件的版本、`cordis.patch.yml` 里的配置覆盖、插件自己写的数据、全局工作区设置……手工搬极易漏项，而**漏掉一处就可能让新电脑上的 DSH 起不来**。

这个插件把这些收拢成一个文件，并保证还原过程可预览、可回退。

## 核心设计取舍

| 决策 | 原因 |
|---|---|
| **不备份 `node_modules`** | 插件本体有几百 MB，且完全可由 `package.json` + `pnpm-lock.yaml` 复现。归档只记录版本，还原时重装，新电脑得到的是干净正确的依赖树。 |
| **不备份运行时/Electron/日志/缓存** | 这些属于机器而非用户，是可重建的。把 Windows 运行时拷到新装环境正是"还原把好环境弄坏"的典型原因。 |
| **凭据默认不含，且永不明文** | `.credentials.yaml` 和 `workbuddy-vault/` 里是 API key 和登录 token。归档是会被拷到 U 盘和网盘的文件，**默认排除**；显式要求时用 AES-256-GCM 加密成独立成员。 |
| **还原默认只预览** | 写入前必须先看到"会改哪些文件、会增删哪些插件"。加 `apply: true` 才真正执行。 |
| **应用前自动做还原点** | 每次写入前把当前 profile 配置快照到带时间戳的目录，误操作可退回。 |
| **目标有额外插件时拒绝执行** | 避免"同步一次，把本机独有的插件配置弄丢"。需显式 `overwritePlugins: true`。 |

## 安装

插件目录：`D:\Dsh\Sync\dsh-config-sync`

```powershell
D:\Dsh\resources\runtime\cli\bin\dsh.cmd plugin --profile desktop add D:\Dsh\Sync\dsh-config-sync
```

装完需要**重启 DSH** 才会注册工具。

> 该命令要写 `C:\Users\ThinkPad\.dsh\profiles\desktop`（在工作区之外），在受限沙箱下会报 EPERM，需要一次完全权限。

## 用法

### 在 DSH 会话里（推荐）

装好后直接对 agent 说，例如：

- 「看看我这台电脑现在有哪些插件和设置」→ `dsh_config_status`
- 「把插件和设置备份出来」→ `backup_dsh_config`
- 「把这个备份还原到新电脑」→ `restore_dsh_config`

五个工具：

| 工具 | 作用 |
|---|---|
| `dsh_config_status` | 看现状：装了哪些插件、各类设置文件数量、备份会包含什么 |
| `backup_dsh_config` | 生成备份归档（支持 `dryRun` 预览） |
| `restore_dsh_config` | 预览/应用还原 |
| `verify_dsh_config` | 校验归档完整性（逐个成员核对 sha256） |
| `list_dsh_backups` | 列出已有归档 |

### 命令行（DSH 起不来时用这个）

```powershell
$cli = "D:\Dsh\resources\runtime\cli\bin\dsh.cmd"   # 仅用于装插件
node D:\Dsh\Sync\dsh-config-sync\bin\dsh-config-sync.mjs <命令>
```

```powershell
# 看现状
node bin\dsh-config-sync.mjs status

# 备份（默认不含凭据和会话）
node bin\dsh-config-sync.mjs backup --output D:\backup\dsh.zip

# 备份并加密包含登录凭据
node bin\dsh-config-sync.mjs backup --output D:\backup\dsh.zip `
     --categories profile-config,home-config,plugin-state,credentials --password 你的口令

# 校验
node bin\dsh-config-sync.mjs verify --input D:\backup\dsh.zip

# 还原：默认只预览
node bin\dsh-config-sync.mjs restore --input D:\backup\dsh.zip --profile desktop

# 确认后真正写入
node bin\dsh-config-sync.mjs restore --input D:\backup\dsh.zip --profile desktop --apply
```

## 换电脑的完整流程

**旧电脑**

```powershell
node bin\dsh-config-sync.mjs backup --output D:\dsh-backup.zip
```

**新电脑**（先装好 DSH 本体）

```powershell
# 1. 校验归档，确认传输没损坏
node bin\dsh-config-sync.mjs verify --input D:\dsh-backup.zip

# 2. 预览：看清楚会写入什么、插件增删情况
node bin\dsh-config-sync.mjs restore --input D:\dsh-backup.zip --profile desktop

# 3. 应用
node bin\dsh-config-sync.mjs restore --input D:\dsh-backup.zip --profile desktop --apply
```

**4. 安装插件**（归档不含 `node_modules`，第 3 步会打印完整命令）

```powershell
D:\Dsh\resources\runtime\cli\bin\dsh.cmd plugin --profile desktop add dsh-pet@0.3.7
D:\Dsh\resources\runtime\cli\bin\dsh.cmd plugin --profile desktop add dsh-mnemon@0.5.29
# …按第 3 步输出的清单逐个装
```

**5. 重启 DSH。**

## 备份类别

| 类别 | 默认 | 内容 |
|---|---|---|
| `profile-config` | ✅ | `package.json`、`pnpm-lock.yaml`、`cordis.yml`、`cordis.patch.yml` 等 |
| `home-config` | ✅ | `storages/workspace.json`、`telemetry/` 等全局设置 |
| `plugin-state` | ✅ | 各插件在 `DSH_HOME` 下的状态目录 |
| `credentials` | ❌ | 登录凭据，需 `password`，AES-256-GCM 加密 |
| `sessions` | ❌ | 会话记录，体积大 |

## 安全说明

- 明文凭据**从不**进入归档。代码里有一条独立防线：任何成员名命中凭据模式都会直接报错中止，而不是默默写进去。
- `workbuddy-vault/` 存的是明文 token，它在 `plugin-state` 里会被自动排除并给出提示——这是实测发现的真实风险点。
- 加密用 scrypt（N=2¹⁵）派生密钥 + AES-256-GCM，口令错误或归档被篡改都会解密失败，不会还原出似是而非的内容。
- **忘记口令 = 凭据无法恢复**，需要在新电脑重新登录。

## 测试

```powershell
node --test test/          # 或直接：node test/sync.test.mjs
```

覆盖 ZIP 往返与损坏检测、加密往返与错误口令、清单排除规则、凭据隔离、预览不落盘、还原点、篡改检测和 CLI。

> 在受限沙箱里，涉及子进程的 4 个 CLI 用例会因 `spawn EPERM` 跳过——那是沙箱禁止管道 stdio，不是插件缺陷。

## 目录结构

```
dsh-config-sync/
├── bin/dsh-config-sync.mjs   # 独立 CLI（DSH 起不来时的救援通道）
├── lib/
│   ├── index.js              # 插件入口，注册 5 个工具
│   ├── inventory.js          # 决定备份什么（核心策略所在）
│   ├── archive.js            # 备份 / 预览 / 还原 / 校验
│   ├── crypto.js             # 口令加密
│   └── zip.js                # 零依赖 ZIP 读写
├── test/sync.test.mjs
└── cordis.patch.yml
```

零运行时依赖：ZIP 和加密都用 Node 内置模块实现，避免在"正在修环境"的机器上还要先装依赖。
