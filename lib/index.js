/**
 * dsh-config-sync — DSH plugin entry point.
 *
 * Registers five model-facing tools that together make "back up every plugin
 * and setting on this machine, then sync it to the next one" a two-command
 * operation:
 *
 *   backup_dsh_config        create a portable .zip archive
 *   restore_dsh_config       preview (default) or apply an archive
 *   verify_dsh_config        prove an archive is intact before trusting it
 *   dsh_config_status        see what this machine would back up
 *   list_dsh_backups         find archives inside a directory
 *
 * Design boundaries, stated because they are what make this safe to hand to an
 * agent:
 *   - `restore` PREVIEWS unless `apply: true` is passed explicitly;
 *   - every apply writes a restore point of the current profile first;
 *   - credentials are excluded by default and never written in plaintext;
 *   - no network access at all — the archive is a local file, and plugin
 *     reinstallation is handed back as commands for the user to run.
 *
 * The plugin imports `@deepseek-ai/dsh-tools` for `defineTool`, but degrades to
 * a plain-object registration when that module is unavailable, so a profile
 * mid-repair can still load it and use the CLI.
 *
 * @module dsh-config-sync
 */

import { readdir, stat } from 'node:fs/promises'
import { join } from 'node:path'

import {
  backup,
  formatBytes,
  planRestore,
  restore,
  status,
  verify,
} from './archive.js'
import { CATEGORIES, defaultCategories, resolveCategories } from './inventory.js'

export const name = 'dsh-config-sync'

/** Services this plugin needs. `tools` is the only hard requirement. */
export const inject = ['tools']

/** Resolve DSH_HOME the same way the rest of DSH does. */
function dshHome () {
  return process.env.DSH_HOME ?? join(process.env.USERPROFILE ?? process.env.HOME ?? '.', '.dsh')
}

/** Resolve the active profile, preferring the environment DSH itself set. */
function activeProfile (explicit) {
  return explicit ?? process.env.DSH_PROFILE ?? 'desktop'
}

/** A filesystem-safe timestamp for default archive names. */
function stamp (date = new Date()) {
  return date.toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19)
}

/**
 * Load `defineTool` if the host provides it.
 *
 * A plugin that hard-fails on a missing SDK module cannot help repair the very
 * profile that is missing it, so this is a soft dependency on purpose.
 */
async function loadDefineTool () {
  try {
    const mod = await import('@deepseek-ai/dsh-tools')
    return typeof mod.defineTool === 'function' ? mod.defineTool : null
  } catch {
    return null
  }
}

/** Render a backup report for the model and the user. */
function renderBackup (r) {
  if (r.mode === 'dry-run') {
    const lines = [
      '【备份预览】未写入任何文件。',
      `将归档 ${r.wouldArchive} 个文件。`,
      `类别：${r.categories.join('、')}`,
      `插件：${r.plugins.length} 个`,
      ...renderCategoryCounts(r.byCategory),
    ]
    return [...lines, ...renderWarnings(r.warnings), ...renderSkipped(r.skipped)].join('\n')
  }
  return [
    '【备份完成】',
    `归档：${r.output}`,
    `大小：${formatBytes(r.archiveBytes)}（原始 ${formatBytes(r.uncompressedBytes)}）`,
    `文件：${r.files} 个`,
    `插件：${r.plugins.length} 个`,
    ...renderCategoryCounts(r.byCategory),
    r.secretsIncluded
      ? '登录凭据：已包含（AES-256-GCM 加密，需口令解密）'
      : '登录凭据：未包含（新电脑上需重新登录）',
    '',
    '下一步：把上面这个 .zip 拷到下一台电脑，然后运行 restore_dsh_config。',
    ...renderWarnings(r.warnings),
    ...renderSkipped(r.skipped),
  ].filter(Boolean).join('\n')
}

function renderCategoryCounts (byCategory = {}) {
  const entries = Object.entries(byCategory)
  if (entries.length === 0) return []
  return [`分类：${entries.map(([k, v]) => `${CATEGORIES[k]?.label ?? k} ${v}`).join('｜')}`]
}

function renderWarnings (warnings = []) {
  if (warnings.length === 0) return []
  return ['', '注意：', ...warnings.map((w) => `  - ${w}`)]
}

function renderSkipped (skipped = []) {
  if (skipped.length === 0) return []
  // Only the count plus a few examples: a full skip list can run to hundreds of
  // lines (every node_modules subtree), which buries the actual result.
  const head = skipped.slice(0, 5).map((s) => `  - ${s.path}（${s.reason}）`)
  const more = skipped.length > 5 ? [`  …另有 ${skipped.length - 5} 项`] : []
  return ['', `已跳过 ${skipped.length} 项：`, ...head, ...more]
}

/** Render a restore plan or result. */
function renderRestore (r) {
  const lines = []
  if (r.applied !== true) {
    lines.push('【还原预览】默认不写入任何文件。确认无误后，用 apply: true 真正执行。')
  } else {
    lines.push('【还原完成】')
  }
  lines.push(
    `归档：${r.input}`,
    `生成时间：${r.createdAt ?? '未知'}`,
    r.source ? `来源机器：${r.source.host}（${r.source.platform}/${r.source.arch}）` : '',
    `目标 profile：${r.profile}${r.profileExists ? '' : '（不存在，将创建）'}`,
    `待写入文件：${r.fileCount} 个`,
    `插件：${r.pluginCount} 个`,
  )

  if (r.wouldAdd?.length) lines.push(`新增插件 ${r.wouldAdd.length} 个：${r.wouldAdd.join('、')}`)
  if (r.wouldRemove?.length) lines.push(`移除插件 ${r.wouldRemove.length} 个：${r.wouldRemove.join('、')}`)
  if (r.wouldAdd?.length === 0 && r.wouldRemove?.length === 0 && r.pluginCount > 0) {
    lines.push('插件清单与目标一致，无需增删。')
  }

  if (r.applied === true) {
    lines.push(`已写入：${r.writtenCount} 个文件`)
    if (r.restorePoint) {
      lines.push(`还原点（覆盖前快照）：${r.restorePoint}`)
    }
    if (r.failed?.length) {
      lines.push(`失败 ${r.failed.length} 项：`)
      for (const f of r.failed) lines.push(`  - ${f.member}：${f.error}`)
    }
    if (r.credentialsRestored) lines.push('登录凭据：已解密并写入')
    if (r.credentialsError) lines.push(`登录凭据还原失败：${r.credentialsError}`)
  }

  if (r.installCommands?.length) {
    lines.push(
      '',
      '还需要手动安装插件（归档不含 node_modules，这是有意设计）：',
      `  dsh plugin --profile ${r.profile} add <包名>   # 逐个安装`,
      ...r.installCommands.map((c) => `  例：dsh plugin --profile ${r.profile} add ${c}`).slice(0, 3),
      '',
      '装完重启 DSH 生效。命令清单见归档内 manifest.json 的 plugins[].install。',
    )
  } else if (r.applied !== true && r.pluginCount > 0) {
    lines.push('', '应用后仍需手动安装插件（归档不含 node_modules）。')
  }

  return [...lines.filter(Boolean), ...renderWarnings(r.warnings)].join('\n')
}

/** Build the tool definitions, with or without the SDK helper. */
function toolSpecs () {
  const specs = [
    {
      name: 'backup_dsh_config',
      description:
        '把本机 DSH 的插件与设置备份成一个可移植的 .zip 归档。\n\n' +
        '备份内容：profile 的 package.json / pnpm-lock.yaml / cordis.patch.yml 等配置、' +
        'DSH_HOME 下的全局设置、各插件自己的状态目录，以及（可选）加密的登录凭据。\n' +
        '不备份 node_modules（插件按 lockfile 记录的版本重装，换机器才干净），也不备份运行时、' +
        'Electron、日志和缓存。\n\n' +
        '登录凭据默认不含；若要包含必须同时提供 password，凭据会以 AES-256-GCM 加密写入，' +
        '归档内不存在明文。\n\n' +
        '先用 dryRun: true 预览，确认后再正式备份。',
      parameters: {
        output: {
          type: 'string',
          description: '归档输出路径。省略时写到 DSH_HOME/backups/dsh-backup-<profile>-<时间>.zip。',
        },
        profile: { type: 'string', description: '要备份的 profile 名。默认取 DSH_PROFILE 环境变量。' },
        categories: {
          type: 'array',
          items: { type: 'string' },
          description:
            '要包含的类别，可选值：profile-config、home-config、plugin-state、credentials、sessions。' +
            '默认前三项（不含凭据与会话）。',
        },
        withSessions: { type: 'boolean', description: '是否连同会话记录一起备份。体积较大，默认否。' },
        password: { type: 'string', description: '加密登录凭据用的口令。仅在选择 credentials 类别时需要。' },
        dryRun: { type: 'boolean', description: '只预览将备份哪些内容，不写文件。' },
      },
      run: async (args) => {
        const profile = activeProfile(args.profile)
        const home = dshHome()
        const output = args.output ?? join(home, 'backups', `dsh-backup-${profile}-${stamp()}.zip`)
        return backup({
          dshHome: home,
          profile,
          output,
          categories: args.categories,
          withSessions: args.withSessions === true,
          password: args.password,
          dryRun: args.dryRun === true,
        })
      },
      render: renderBackup,
    },
    {
      name: 'restore_dsh_config',
      description:
        '从备份归档还原/同步 DSH 的插件与设置到本机，用于把上一台电脑的环境搬到新电脑。\n\n' +
        '**默认只预览不写入**：先调一次看计划（会列出将写入的文件、插件增删、风险提示），' +
        '确认后再带 apply: true 执行。\n\n' +
        '真正应用前会自动把当前 profile 的配置快照到时间戳还原点目录，所以误操作可以退回。' +
        '若目标 profile 存在归档里没有的插件，默认拒绝执行，需显式传 overwritePlugins: true。\n\n' +
        '归档不含 node_modules，还原后插件需要按返回的安装清单手动重装，重启 DSH 生效。\n' +
        '凭据只有同时传 password 与 withCredentials: true 才会解密写入。',
      parameters: {
        input: { type: 'string', required: true, description: '备份 .zip 的路径。' },
        profile: { type: 'string', description: '目标 profile 名，默认 desktop。' },
        apply: { type: 'boolean', description: '设为 true 才真正写入；省略或 false 只预览。' },
        password: { type: 'string', description: '解密归档内登录凭据的口令。' },
        withCredentials: { type: 'boolean', description: '设为 true 才把解密后的凭据写入本机。' },
        overwritePlugins: {
          type: 'boolean',
          description: '允许用归档的插件清单覆盖目标 profile 现有的插件登记。',
        },
      },
      run: async (args) => {
        const profile = activeProfile(args.profile)
        const home = dshHome()
        if (args.apply === true) {
          return restore({
            dshHome: home,
            profile,
            input: args.input,
            apply: true,
            password: args.password,
            withCredentials: args.withCredentials === true,
            overwritePlugins: args.overwritePlugins === true,
          })
        }
        const { plan } = await planRestore({ dshHome: home, profile, input: args.input, password: args.password })
        return { ...plan, applied: false }
      },
      render: renderRestore,
    },
    {
      name: 'verify_dsh_config',
      description:
        '校验一个备份归档是否完整可用：逐个成员核对大小与 sha256，并列出插件清单、' +
        '包含的类别、是否含加密凭据。在换电脑还原之前、或归档经过网盘/U盘传输之后建议先跑一次。',
      parameters: {
        input: { type: 'string', required: true, description: '备份 .zip 的路径。' },
      },
      run: async (args) => verify(args.input),
      render: (r) => {
        const lines = [
          r.ok ? '【校验通过】归档完整。' : '【校验失败】归档已损坏，不要用它还原。',
          `归档：${r.input}`,
          `生成时间：${r.createdAt ?? '未知'}`,
          r.source ? `来源机器：${r.source.host}（${r.source.platform}/${r.source.arch}）` : '',
          `类别：${(r.categories ?? []).join('、')}`,
          `文件：${r.fileCount} 个｜插件：${r.pluginCount} 个`,
          r.secretsIncluded ? '含加密的登录凭据（需口令解密）' : '不含登录凭据',
        ].filter(Boolean)
        if (r.problems.length > 0) {
          lines.push('', '问题明细：', ...r.problems.map((p) => `  - ${p}`))
        }
        if (r.plugins.length > 0) {
          lines.push('', `插件清单（${r.plugins.length}）：`, ...r.plugins.map((p) => `  - ${p.name}@${p.spec}`))
        }
        return [...lines, ...renderWarnings(r.warnings)].join('\n')
      },
    },
    {
      name: 'dsh_config_status',
      description:
        '查看本机 DSH 当前的插件与设置情况：装了哪些插件及其版本、活动 profile、' +
        '各类设置文件数量、以及现在做一次备份会包含多少个文件。在备份前了解现状时使用。',
      parameters: {
        profile: { type: 'string', description: '要查看的 profile 名，默认取 DSH_PROFILE。' },
      },
      run: async (args) => status({ dshHome: dshHome(), profile: activeProfile(args.profile) }),
      render: (r) => [
        `DSH_HOME：${r.dshHome}`,
        `活动 profile：${r.profile}${r.profileExists ? '' : '（目录不存在）'}`,
        `插件 ${r.plugins.length} 个：`,
        // One marker per problem kind, because the fix differs: an unregistered
        // plugin wants a bundles entry, a non-plugin wants to be uninstalled.
        ...r.plugins.map((p) => {
          if (p.kind === 'unregistered') return `  - ${p.name}@${p.spec}  ⚠ 已安装但未登记进 bundles，不会加载`
          if (p.kind === 'not-a-plugin') return `  - ${p.name}@${p.spec}  ⚠ 不是 DSH 插件（无 bundle 清单），永远不会加载，建议卸载`
          return `  - ${p.name}@${p.spec}`
        }),
        '',
        `默认备份将包含 ${r.wouldArchive} 个文件（类别：${r.categories.join('、')}）`,
        ...renderCategoryCounts(r.byCategory),
        ...renderWarnings(r.warnings),
      ].join('\n'),
    },
    {
      name: 'list_dsh_backups',
      description: '列出某个目录里已有的 DSH 备份归档，含大小与修改时间，方便挑选要还原哪一个。',
      parameters: {
        directory: { type: 'string', description: '要搜索的目录，默认 DSH_HOME/backups。' },
      },
      run: async (args) => {
        const dir = args.directory ?? join(dshHome(), 'backups')
        let names = []
        try {
          names = await readdir(dir)
        } catch {
          return { directory: dir, exists: false, archives: [] }
        }
        const archives = []
        for (const n of names) {
          if (!/\.zip$/i.test(n)) continue
          const info = await stat(join(dir, n))
          archives.push({
            name: n,
            path: join(dir, n),
            bytes: info.size,
            modified: info.mtime.toISOString(),
          })
        }
        archives.sort((a, b) => (a.modified < b.modified ? 1 : -1))
        return { directory: dir, exists: true, archives }
      },
      render: (r) => {
        if (!r.exists) return `目录不存在：${r.directory}\n还没有任何备份。`
        if (r.archives.length === 0) return `目录里没有备份归档：${r.directory}`
        return [
          `共 ${r.archives.length} 个备份（${r.directory}）：`,
          ...r.archives.map((a) => `  - ${a.name}  ${formatBytes(a.bytes)}  ${a.modified.slice(0, 19).replace('T', ' ')}`),
        ].join('\n')
      },
    },
  ]
  return specs
}

/**
 * Register the tools on a Cordis context.
 *
 * @param {object} ctx plugin context, must expose `tools.register`
 */
export async function apply (ctx) {
  const defineTool = await loadDefineTool()
  const specs = toolSpecs()

  for (const spec of specs) {
    const definition = {
      name: spec.name,
      description: spec.description,
      parameters: spec.parameters,
      execute: async (args) => spec.run(args ?? {}),
      output: {
        schema: { type: 'object', additionalProperties: true },
        render: (_args, value) => [{ type: 'text', text: spec.render(value) }],
      },
    }
    ctx.tools.register(defineTool ? defineTool(definition) : definition)
  }
}

/** Metadata the DSH plugin manager can show without loading the plugin. */
export const metadata = {
  categories: Object.fromEntries(Object.entries(CATEGORIES).map(([id, c]) => [id, c.label])),
  defaultCategories: defaultCategories(),
  resolveCategories,
}

export { backup, restore, verify, status, planRestore, formatBytes }
