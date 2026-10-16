/**
 * dsh-config-sync — decide what a DSH backup actually contains.
 *
 * The hard part of this plugin is not zipping files, it is knowing which files
 * ARE the configuration and which are just as well reinstalled. Two rules drive
 * every decision here:
 *
 *   1. Never archive `node_modules`. A profile's plugin payload is hundreds of
 *      megabytes and is exactly reproducible from `package.json` +
 *      `pnpm-lock.yaml` — including the git and tarball installs, which the
 *      lockfile pins to a commit. Archiving it would make every backup huge and
 *      would still be the wrong bytes on a different machine.
 *   2. Never archive what the machine, not the user, owns. Runtime binaries,
 *      the Electron shell, logs and caches are all rebuildable, and copying a
 *      Windows runtime onto a fresh install is how a "restore" ends up breaking
 *      a working DSH.
 *
 * So an archive is: the profile's config files, the home-level settings, each
 * plugin's own state, and a manifest that lets the restore machine rebuild the
 * plugin tree from npm. Credentials are a separate, opt-in, encrypted category.
 *
 * @module dsh-config-sync/inventory
 */

import { createHash } from 'node:crypto'
import { readdir, readFile, stat } from 'node:fs/promises'
import { hostname, platform, arch, release } from 'node:os'
import { join, relative, sep } from 'node:path'

/** Format version of the archive this module describes. */
export const ARCHIVE_FORMAT = 1

/**
 * Categories a backup can include.
 *
 * `default: true` marks the set used when the caller does not choose. Secrets
 * and session transcripts are deliberately opt-in: a backup is a thing users
 * copy to USB sticks and cloud drives, and neither belongs in that flow by
 * default.
 */
export const CATEGORIES = {
  'profile-config': {
    label: 'profile 配置',
    description: 'profile 根目录下的 package.json、pnpm-lock.yaml、cordis.yml、cordis.patch.yml 等，决定装了哪些插件及其版本与配置。',
    default: true,
  },
  'home-config': {
    label: '全局设置',
    description: 'DSH_HOME 下的 storages/workspace.json 等全局设置与工作区列表。',
    default: true,
  },
  'plugin-state': {
    label: '插件数据',
    description: '各插件自己在 DSH_HOME 下写的状态目录（如 dsh-pet、dsh-market、telemetry）。',
    default: true,
  },
  credentials: {
    label: '登录凭据',
    description: '.credentials.yaml（含 DeepSeek API key 与登录令牌）。默认不备份；启用后以口令加密的独立文件写出，不会明文落盘。',
    default: false,
  },
  sessions: {
    label: '会话记录',
    description: '聊天会话与工作区会话日志。体积大且属于历史记录而非设置，默认不备份。',
    default: false,
  },
}

/** The category set used when the caller expresses no preference. */
export function defaultCategories () {
  return Object.entries(CATEGORIES).filter(([, c]) => c.default).map(([id]) => id)
}

/**
 * Validate a caller-supplied category list.
 * @param {string[]|undefined} requested
 * @returns {string[]}
 */
export function resolveCategories (requested) {
  if (requested === undefined || requested === null || requested.length === 0) {
    return defaultCategories()
  }
  const list = Array.isArray(requested) ? requested : [requested]
  const unknown = list.filter((id) => !(id in CATEGORIES))
  if (unknown.length > 0) {
    throw new Error(`未知的备份类别：${unknown.join('、')}。可选：${Object.keys(CATEGORIES).join('、')}`)
  }
  // Preserve the canonical order so two equivalent requests produce byte-equal
  // archives, which is what makes the sha256 in the manifest meaningful.
  return Object.keys(CATEGORIES).filter((id) => list.includes(id))
}

/**
 * Directory names never worth archiving, wherever they appear.
 *
 * `.plugin-manager/logs` is thousands of pnpm transcripts; `node_modules` and
 * the caches speak for themselves.
 */
const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'logs',
  '.cache',
  'cache',
  'Cache',
  'tmp',
  'temp',
])

/** Per-file ceiling. A config file larger than this is not a config file. */
const MAX_CONFIG_FILE_BYTES = 32 * 1024 * 1024

/** DSH_HOME entries that are machine-owned or rebuildable, never settings. */
const HOME_SKIP = new Set([
  'profiles', // handled as profile-config
  'sessions', // handled as the sessions category
  'dsh-runtimes', // 270MB of runtime binaries
  'electron', // 340MB Electron shell
  'logs',
  'node_modules',
  '__pycache__',
  '.cache',
  // Permission-repair scratch written by unrelated tooling. It is a record of
  // one machine's ACL state, meaningless on another, and its `.ps1` member is a
  // generated script we should not be redistributing.
  'acl-recovery',
  'acl-reports',
])

/**
 * Home directories that hold CREDENTIALS under a plugin's own name.
 *
 * This is the plugin-state category's one real trap: not every secret lives in
 * `.credentials.yaml`. `workbuddy-vault` stores a live `accessToken` in plain
 * JSON, so archiving it as ordinary plugin state would put a working bearer
 * token into an unencrypted file that the user is told is safe to copy to a USB
 * stick. Named here so they are routed through the encrypted credential path
 * instead — or, when no password was given, left out entirely with a warning.
 */
const CREDENTIAL_DIRS = new Set([
  'workbuddy-vault',
])

/** Files matching these names are credentials wherever they appear. */
const CREDENTIAL_FILE_PATTERN = /(^|[.\\/-])(credentials|credential|auth|token|secret|apikey|api-key)s?([.\\/-]|$)|\.credentials\./i

/** Windows filenames that cannot be represented in an archive on any OS. */
function isPortableName (name) {
  return !/[<>:"|?*\u0000-\u001f]/.test(name) && !/[. ]$/.test(name)
}

/**
 * Recursively list files under a root, applying the skip rules.
 *
 * Returns entries as `{ absolute, relative }` with forward-slash relative paths
 * so archive member names are identical on Windows and POSIX hosts.
 *
 * @param {string} root
 * @param {{exclude?: (relPath: string) => boolean, maxFileBytes?: number, onSkip?: (relPath: string, reason: string) => void}} [options]
 */
export async function walkFiles (root, options = {}) {
  const out = []
  const { exclude, maxFileBytes = MAX_CONFIG_FILE_BYTES, onSkip } = options

  async function visit (dir, prefix) {
    let entries
    try {
      entries = await readdir(dir, { withFileTypes: true })
    } catch (error) {
      onSkip?.(prefix || '.', `无法读取目录：${error.code ?? error.message}`)
      return
    }

    for (const entry of entries) {
      const relPath = prefix === '' ? entry.name : `${prefix}/${entry.name}`
      if (exclude?.(relPath) === true) {
        onSkip?.(relPath, '按规则排除')
        continue
      }
      // A symlink or junction could point anywhere — into the runtime, or out
      // of the home entirely. Backing one up would either duplicate hundreds of
      // megabytes or archive a path the target machine cannot resolve.
      if (entry.isSymbolicLink()) {
        onSkip?.(relPath, '符号链接/联接，跳过')
        continue
      }
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) {
          onSkip?.(relPath, '可重建或噪音目录')
          continue
        }
        if (!isPortableName(entry.name)) {
          onSkip?.(relPath, '名称在跨平台归档中不安全')
          continue
        }
        await visit(join(dir, entry.name), relPath)
        continue
      }
      if (!entry.isFile()) continue
      if (!isPortableName(entry.name)) {
        onSkip?.(relPath, '名称在跨平台归档中不安全')
        continue
      }

      const absolute = join(dir, entry.name)
      let info
      try {
        info = await stat(absolute)
      } catch (error) {
        onSkip?.(relPath, `无法读取：${error.code ?? error.message}`)
        continue
      }
      if (info.size > maxFileBytes) {
        onSkip?.(relPath, `超过单文件上限 ${Math.round(maxFileBytes / 1024 / 1024)}MB`)
        continue
      }
      out.push({ absolute, relative: relPath, size: info.size, mtime: info.mtime })
    }
  }

  await visit(root, '')
  out.sort((a, b) => (a.relative < b.relative ? -1 : a.relative > b.relative ? 1 : 0))
  return out
}

/** Is this a profile config file (as opposed to plugin payload)? */
function isProfileConfigFile (name) {
  return /\.(json|jsonc|ya?ml)$/i.test(name) || name === 'compatibility.json'
}

/**
 * Read the plugin set a profile declares.
 *
 * `dsh.profile.bundles` is the load-order list and `dependencies` is the install
 * list; both are needed, because a plugin registered in one but not the other
 * silently does not load (a documented footgun). Returning them separately lets
 * the restore report a mismatch instead of reproducing one.
 *
 * @param {string} profileDir
 * @returns {Promise<{name?: string, dependencies: Record<string,string>, bundles: string[]}>}
 */
export async function readProfileManifest (profileDir) {
  const file = join(profileDir, 'package.json')
  let raw
  try {
    raw = await readFile(file, 'utf8')
  } catch {
    return { dependencies: {}, bundles: [] }
  }
  let parsed
  try {
    parsed = JSON.parse(raw)
  } catch (error) {
    throw new Error(`profile 的 package.json 无法解析：${error.message}`)
  }
  return {
    name: parsed.name,
    dependencies: parsed.dependencies ?? {},
    bundles: parsed.dsh?.profile?.bundles ?? [],
  }
}

/** Does any known credential directory exist under this home? */
async function anyCredentialDirExists (dshHome) {
  for (const name of CREDENTIAL_DIRS) {
    if (await exists(join(dshHome, name))) return true
  }
  return false
}

/**
 * Does this installed package actually declare itself a DSH plugin?
 *
 * A profile dependency is only loadable as a bundle if it ships a bundle
 * manifest (`dsh.bundle.patch` in package.json) or a cordis patch file. `dsh
 * plugin add` is a pnpm passthrough and happily installs plain CLI tools, which
 * then sit in dependencies forever without loading — and telling the user to
 * "register it in bundles" would be advice for a problem that does not exist,
 * because there is nothing loadable to register. This is the check that
 * separates "forgot to register" from "not a plugin at all".
 *
 * @param {string} profileDir
 * @param {string} name
 * @returns {Promise<boolean>}
 */
export async function isDshPluginPackage (profileDir, name) {
  const pkgDir = join(profileDir, 'node_modules', name)
  let parsed
  try {
    parsed = JSON.parse(await readFile(join(pkgDir, 'package.json'), 'utf8'))
  } catch {
    // Unresolvable dependency: let the existing "not installed" diagnostics
    // speak rather than inventing a verdict.
    return true
  }
  if (parsed.dsh?.bundle?.patch) return true
  // `@deepseek-ai/*` shells are provided by the host itself, never by npm.
  if (name.startsWith('@deepseek-ai/')) return true
  return exists(join(pkgDir, 'cordis.patch.yml'))
}

/**
 * Turn a dependency spec into something a restore can install.
 * @param {string} name
 * @param {string} spec
 */
export function installTargetFor (name, spec) {
  return spec && spec !== '*' ? `${name}@${spec}` : name
}

/** sha256 of a buffer, as the manifest records it. */
export function sha256 (buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

/**
 * Build the full backup plan without reading any file contents.
 *
 * Keeping planning separate from writing means `backup --dry-run` is honest:
 * the same function produces the list the real run will use, so a plan cannot
 * promise files the writer then skips.
 *
 * @param {{dshHome: string, profile: string, categories?: string[], withSessions?: boolean, now?: Date}} params
 */
export async function planBackup (params) {
  const { dshHome, profile, now = new Date() } = params
  const categories = resolveCategories(
    params.withSessions === true && params.categories === undefined
      ? [...defaultCategories(), 'sessions']
      : params.categories,
  )

  const profileDir = join(dshHome, 'profiles', profile)
  if (!(await exists(profileDir))) {
    throw new Error(`找不到 profile 目录：${profileDir}`)
  }

  const files = [] // { member, absolute, category, size? }
  const warnings = []
  const skipped = []

  const push = (member, absolute, category) => {
    files.push({ member, absolute, category })
  }

  // --- profile-config ------------------------------------------------------
  if (categories.includes('profile-config')) {
    let entries
    try {
      entries = await readdir(profileDir, { withFileTypes: true })
    } catch (error) {
      throw new Error(`无法读取 profile 目录：${error.message}`)
    }
    for (const entry of entries) {
      if (!entry.isFile()) continue
      if (!isProfileConfigFile(entry.name)) continue
      // Editor and pnpm backup litter: a `.bak-<timestamp>` of every edit is
      // history the user did not ask to carry to another machine.
      if (/\.bak([-.]|$)/i.test(entry.name)) {
        skipped.push({ path: `${profile}/${entry.name}`, reason: '备份残留文件' })
        continue
      }
      push(`profile/${entry.name}`, join(profileDir, entry.name), 'profile-config')
    }
  }

  // --- home-config ---------------------------------------------------------
  if (categories.includes('home-config')) {
    for (const name of ['storages', 'telemetry']) {
      const root = join(dshHome, name)
      if (!(await exists(root))) continue
      const found = await walkFiles(root, {
        onSkip: (rel, reason) => skipped.push({ path: `${name}/${rel}`, reason }),
      })
      for (const f of found) push(`home/${name}/${f.relative}`, f.absolute, 'home-config')
    }
    // Unknown home-level state directories, discovered rather than listed, so a
    // plugin installed later is covered. Loose files at the home root are
    // deliberately NOT swept in: that is where `.credentials.yaml` and the
    // machine's own id/heartbeat files live.
  }

  // --- plugin-state --------------------------------------------------------
  if (categories.includes('plugin-state')) {
    let entries = []
    try {
      entries = await readdir(dshHome, { withFileTypes: true })
    } catch { /* home unreadable is reported by the profile check above */ }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue
      if (HOME_SKIP.has(entry.name)) continue
      if (entry.name.startsWith('_repair-backup-')) continue
      if (entry.name === 'storages' || entry.name === 'telemetry') continue // home-config owns these
      // Not "plugin state": a directory that holds live credentials must go
      // through the encrypted path, never the plain one.
      if (CREDENTIAL_DIRS.has(entry.name)) continue
      const root = join(dshHome, entry.name)
      const found = await walkFiles(root, {
        onSkip: (rel, reason) => skipped.push({ path: `${entry.name}/${rel}`, reason }),
      })
      for (const f of found) {
        if (CREDENTIAL_FILE_PATTERN.test(f.relative)) {
          skipped.push({ path: `${entry.name}/${f.relative}`, reason: '疑似凭据，改由加密类别处理' })
          continue
        }
        push(`home/${entry.name}/${f.relative}`, f.absolute, 'plugin-state')
      }
    }
    // Any credential-bearing directory the plugin-state pass just skipped is
    // reported, so the user is never silently missing a login they expected.
    for (const name of CREDENTIAL_DIRS) {
      if (!(await exists(join(dshHome, name)))) continue
      if (!categories.includes('credentials')) {
        warnings.push(
          `${name}/ 存放登录凭据（明文 token），未纳入本次备份。` +
          '需要迁移登录状态请把 credentials 加入 categories 并提供 password。',
        )
      }
    }
  }

  // --- credentials (opt-in) ------------------------------------------------
  if (categories.includes('credentials')) {
    const credFile = join(dshHome, '.credentials.yaml')
    if (await exists(credFile)) {
      push('secrets/credentials.yaml', credFile, 'credentials')
    }
    for (const name of CREDENTIAL_DIRS) {
      const root = join(dshHome, name)
      if (!(await exists(root))) continue
      const found = await walkFiles(root, {
        onSkip: (rel, reason) => skipped.push({ path: `${name}/${rel}`, reason }),
      })
      for (const f of found) push(`secrets/${name}/${f.relative}`, f.absolute, 'credentials')
    }
    if (!(await exists(credFile)) && !(await anyCredentialDirExists(dshHome))) {
      warnings.push('请求备份登录凭据，但本机没有找到凭据文件。')
    }
  }

  // --- sessions (opt-in) ---------------------------------------------------
  if (categories.includes('sessions')) {
    const sessionsRoot = join(dshHome, 'sessions')
    if (await exists(sessionsRoot)) {
      const found = await walkFiles(sessionsRoot, {
        onSkip: (rel, reason) => skipped.push({ path: `sessions/${rel}`, reason }),
      })
      for (const f of found) push(`home/sessions/${f.relative}`, f.absolute, 'sessions')
    }
    const caches = join(dshHome, 'storages', 'session_projcache')
    if (await exists(caches)) {
      const found = await walkFiles(caches, {
        onSkip: (rel, reason) => skipped.push({ path: `session_projcache/${rel}`, reason }),
      })
      for (const f of found) push(`home/storages/session_projcache/${f.relative}`, f.absolute, 'sessions')
    }
  }

  const manifest = await readProfileManifest(profileDir)

  // A bundle registered but not installed, or installed but not registered,
  // does not load. Recording the discrepancy now means the restore can warn
  // instead of faithfully copying a profile that is already broken.
  const declaredDeps = Object.keys(manifest.dependencies)

  // Split "installed but unregistered" into two different problems: a real
  // plugin that was forgotten at registration time, versus a package that is
  // not a DSH plugin at all (installed by mistake or pulled in manually). The
  // advice differs completely — the first wants a bundles entry, the second
  // wants to be uninstalled, because there is nothing loadable to register.
  const realPluginsUnregistered = []
  const notPlugins = []
  for (const dep of declaredDeps) {
    const registered = manifest.bundles.includes(dep) ||
      manifest.bundles.some((b) => b.startsWith(`${dep}/`))
    if (registered) continue
    if (dep.startsWith('@deepseek-ai/') || await isDshPluginPackage(profileDir, dep)) {
      realPluginsUnregistered.push(dep)
    } else {
      notPlugins.push(dep)
    }
  }
  const installedButUnregistered = manifest.bundles.filter(
    (b) => !b.startsWith('@deepseek-ai/') && !declaredDeps.includes(b),
  )
  if (realPluginsUnregistered.length > 0) {
    warnings.push(`这些插件已安装但未登记进 dsh.profile.bundles，重启后不会加载：${realPluginsUnregistered.join('、')}`)
  }
  if (notPlugins.length > 0) {
    warnings.push(
      `这些依赖不是 DSH 插件（没有 bundle 清单/cordis.patch.yml），装在这里永远不会加载，建议卸载：${notPlugins.join('、')}`,
    )
  }
  if (installedButUnregistered.length > 0) {
    warnings.push(`这些 bundle 已登记但不在 dependencies 中：${installedButUnregistered.join('、')}`)
  }

  const plugins = []
  for (const [name, spec] of Object.entries(manifest.dependencies)) {
    const registered = manifest.bundles.includes(name) ||
      manifest.bundles.some((b) => b.startsWith(`${name}/`))
    // `kind` tells three cases apart so the UI never tells a user to "register"
    // a package that has nothing loadable to register:
    //   plugin       — has a bundle manifest and is registered
    //   unregistered — a real plugin missing from the bundles list
    //   not-a-plugin — a plain package `dsh plugin add` accepted by mistake
    const kind = registered
      ? 'plugin'
      : (name.startsWith('@deepseek-ai/') || await isDshPluginPackage(profileDir, name))
        ? 'unregistered'
        : 'not-a-plugin'
    plugins.push({ name, spec, install: installTargetFor(name, spec), registered, kind })
  }

  return {
    format: ARCHIVE_FORMAT,
    createdAt: now.toISOString(),
    source: {
      host: safeHostname(),
      platform: platform(),
      arch: arch(),
      osRelease: release(),
      dshHome,
      profile,
    },
    categories,
    plugins,
    bundles: manifest.bundles,
    files,
    skipped,
    warnings,
  }
}

/** hostname() throws on some locked-down hosts; a backup must not die for it. */
function safeHostname () {
  try {
    return hostname()
  } catch {
    return 'unknown'
  }
}

/** exists() that cannot throw. */
export async function exists (path) {
  try {
    await stat(path)
    return true
  } catch {
    return false
  }
}

/** Convert an OS-specific path to the member-name form used inside archives. */
export function toMemberPath (absolutePath, root) {
  return relative(root, absolutePath).split(sep).join('/')
}
