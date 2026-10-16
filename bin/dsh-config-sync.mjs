#!/usr/bin/env node
/**
 * dsh-config-sync — standalone CLI.
 *
 * Exists because the tool's most valuable job happens when DSH is not in a
 * usable state: a fresh machine with no plugins, or a profile whose plugin set
 * broke the UI. The plugin's own tools require a running DSH; this entry point
 * requires nothing but Node.
 *
 * Usage:
 *   dsh-config-sync status   [--profile <p>]
 *   dsh-config-sync backup   [--profile <p>] [--output <zip>] [--categories a,b] [--with-sessions]
 *                            [--password <pw>] [--dry-run]
 *   dsh-config-sync verify   --input <zip>
 *   dsh-config-sync restore  --input <zip> [--profile <p>] [--apply] [--password <pw>]
 *                            [--with-credentials] [--overwrite-plugins]
 *   dsh-config-sync list     [--directory <dir>]
 *
 * @module dsh-config-sync/cli
 */

import { readdir, stat } from 'node:fs/promises'
import { join } from 'node:path'

import { backup, formatBytes, planRestore, restore, status, verify } from '../lib/archive.js'

const USAGE = `dsh-config-sync — DSH 插件与设置备份/同步 CLI

用法：
  dsh-config-sync status   [--profile <名>]
  dsh-config-sync backup   [--profile <名>] [--output <zip>] [--categories a,b]
                           [--with-sessions] [--password <口令>] [--dry-run]
  dsh-config-sync verify   --input <zip>
  dsh-config-sync restore  --input <zip> [--profile <名>] [--apply]
                           [--password <口令>] [--with-credentials] [--overwrite-plugins]
  dsh-config-sync list     [--directory <目录>]

说明：
  backup  默认不含登录凭据；加 --categories credentials 时必须同时给 --password。
          --with-sessions 会连同会话记录一起备份（体积较大）。
  restore 默认只预览，必须显式加 --apply 才写入。
          写入前会自动把当前 profile 配置快照到 .dsh-config-sync-restore-point-* 目录。

退出码：0 成功；1 出错；2 用法错误。
`

/** Minimal argv parser: `--key value`, `--flag`, and `--key=value`. */
function parseArgs (argv) {
  const flags = {}
  const positional = []
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i]
    if (token === '--') {
      positional.push(...argv.slice(i + 1))
      break
    }
    if (token.startsWith('--')) {
      const body = token.slice(2)
      const eq = body.indexOf('=')
      if (eq >= 0) {
        flags[body.slice(0, eq)] = body.slice(eq + 1)
      } else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
        flags[body] = argv[i + 1]
        i += 1
      } else {
        flags[body] = true
      }
    } else {
      positional.push(token)
    }
  }
  return { flags, positional }
}

/**
 * Prefer the CLI flag, then DSH's own environment, then the platform default.
 *
 * Unlike the in-DSH tools, this cannot assume DSH set DSH_HOME for it.
 */
function resolveHome (flags) {
  return flags.home ?? process.env.DSH_HOME ??
    join(process.env.USERPROFILE ?? process.env.HOME ?? '.', '.dsh')
}

function resolveProfile (flags) {
  return flags.profile ?? process.env.DSH_PROFILE ?? 'desktop'
}

function timestamp () {
  return new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19)
}

async function main () {
  const argv = process.argv.slice(2)
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h' || argv[0] === 'help') {
    process.stdout.write(USAGE)
    return 0
  }

  const command = argv[0]
  const { flags } = parseArgs(argv.slice(1))
  const home = resolveHome(flags)
  const profile = resolveProfile(flags)

  switch (command) {
    case 'status': {
      const r = await status({ dshHome: home, profile })
      console.log(`DSH_HOME：${r.dshHome}`)
      console.log(`活动 profile：${r.profile}${r.profileExists ? '' : '（目录不存在）'}`)
      console.log(`插件 ${r.plugins.length} 个：`)
        for (const p of r.plugins) {
          if (p.kind === 'unregistered') console.log(`  - ${p.name}@${p.spec}  ⚠ 已安装但未登记进 bundles，不会加载`)
          else if (p.kind === 'not-a-plugin') console.log(`  - ${p.name}@${p.spec}  ⚠ 不是 DSH 插件（无 bundle 清单），永远不会加载，建议卸载`)
          else console.log(`  - ${p.name}@${p.spec}`)
        }
      console.log('')
      console.log(`默认备份将包含 ${r.wouldArchive} 个文件（类别：${r.categories.join('、')}）`)
      for (const [k, v] of Object.entries(r.byCategory)) console.log(`  ${k}: ${v}`)
      for (const w of r.warnings) console.log(`注意：${w}`)
      return 0
    }

    case 'backup': {
      const output = flags.output ?? join(home, 'backups', `dsh-backup-${profile}-${timestamp()}.zip`)
      const categories = typeof flags.categories === 'string'
        ? flags.categories.split(',').map((s) => s.trim()).filter(Boolean)
        : undefined
      const r = await backup({
        dshHome: home,
        profile,
        output,
        categories,
        withSessions: flags['with-sessions'] === true,
        password: typeof flags.password === 'string' ? flags.password : undefined,
        dryRun: flags['dry-run'] === true,
      })
      if (r.mode === 'dry-run') {
        console.log(`【预览】将归档 ${r.wouldArchive} 个文件，未写入任何内容。`)
        console.log(`类别：${r.categories.join('、')}`)
        for (const [k, v] of Object.entries(r.byCategory)) console.log(`  ${k}: ${v}`)
      } else {
        console.log(`【备份完成】${r.output}`)
        console.log(`大小：${formatBytes(r.archiveBytes)}（原始 ${formatBytes(r.uncompressedBytes)}）`)
        console.log(`文件 ${r.files} 个｜插件 ${r.plugins.length} 个`)
        console.log(r.secretsIncluded ? '登录凭据：已包含（加密）' : '登录凭据：未包含')
      }
      for (const w of r.warnings) console.log(`注意：${w}`)
      return 0
    }

    case 'verify': {
      if (typeof flags.input !== 'string') {
        console.error('verify 需要 --input <zip>')
        return 2
      }
      const r = await verify(flags.input)
      console.log(r.ok ? '【校验通过】归档完整。' : '【校验失败】归档已损坏，不要用它还原。')
      console.log(`生成时间：${r.createdAt ?? '未知'}`)
      console.log(`文件 ${r.fileCount} 个｜插件 ${r.pluginCount} 个`)
      console.log(r.secretsIncluded ? '含加密凭据' : '不含凭据')
      for (const p of r.problems) console.log(`  - ${p}`)
      return r.ok ? 0 : 1
    }

    case 'restore': {
      if (typeof flags.input !== 'string') {
        console.error('restore 需要 --input <zip>')
        return 2
      }
      const common = {
        dshHome: home,
        profile,
        input: flags.input,
        password: typeof flags.password === 'string' ? flags.password : undefined,
      }
      if (flags.apply !== true) {
        const { plan } = await planRestore(common)
        console.log('【还原预览】未加 --apply，不会写入任何文件。')
        console.log(`归档：${plan.input}`)
        console.log(`目标 profile：${plan.profile}${plan.profileExists ? '' : '（不存在，将创建）'}`)
        console.log(`待写入 ${plan.fileCount} 个文件｜插件 ${plan.pluginCount} 个`)
        if (plan.wouldAdd.length) console.log(`新增插件：${plan.wouldAdd.join('、')}`)
        if (plan.wouldRemove.length) console.log(`移除插件：${plan.wouldRemove.join('、')}`)
        console.log('')
        console.log('确认后加 --apply 执行。')
        for (const w of plan.warnings) console.log(`注意：${w}`)
        return 0
      }
      const r = await restore({
        ...common,
        apply: true,
        withCredentials: flags['with-credentials'] === true,
        overwritePlugins: flags['overwrite-plugins'] === true,
      })
      console.log('【还原完成】')
      console.log(`写入 ${r.writtenCount} 个文件`)
      if (r.restorePoint) console.log(`还原点：${r.restorePoint}`)
      for (const f of r.failed) console.log(`失败：${f.member}：${f.error}`)
      if (r.credentialsRestored) console.log('登录凭据：已写入')
      if (r.credentialsError) console.log(`凭据还原失败：${r.credentialsError}`)
      if (r.installCommands.length > 0) {
        console.log('')
        console.log('还需安装这些插件（归档不含 node_modules）：')
        for (const c of r.installCommands) console.log(`  dsh plugin --profile ${profile} add ${c}`)
        console.log('装完重启 DSH 生效。')
      }
      for (const w of r.warnings) console.log(`注意：${w}`)
      return 0
    }

    case 'list': {
      const dir = flags.directory ?? join(home, 'backups')
      let names = []
      try {
        names = await readdir(dir)
      } catch {
        console.log(`目录不存在：${dir}`)
        return 0
      }
      const rows = []
      for (const n of names) {
        if (!/\.zip$/i.test(n)) continue
        const info = await stat(join(dir, n))
        rows.push(`${n}  ${formatBytes(info.size)}  ${info.mtime.toISOString().slice(0, 19).replace('T', ' ')}`)
      }
      console.log(rows.length === 0 ? `目录里没有备份归档：${dir}` : rows.join('\n'))
      return 0
    }

    default:
      console.error(`未知命令：${command}\n`)
      process.stderr.write(USAGE)
      return 2
  }
}

main().then(
  (code) => { process.exitCode = code },
  (error) => {
    console.error(`错误：${error.message}`)
    process.exitCode = 1
  },
)
