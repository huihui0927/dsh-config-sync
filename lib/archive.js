/**
 * dsh-config-sync — build and apply backup archives.
 *
 * `backup()` is the read half and `restore()` is the write half; both go
 * through the same manifest, so what a restore applies is exactly what a backup
 * recorded, and a mismatch is reported rather than half-applied.
 *
 * The restore path is the dangerous one, so it is built around three rules:
 *
 *   - Preview by default. `restore(..., {apply: false})` returns the full plan
 *     without touching the profile, and the tool surfaces that as the default.
 *   - Always back up what is about to be overwritten. Every apply run first
 *     snapshots the current profile config into a timestamped restore-point
 *     directory, so a bad sync is one copy away from undone.
 *   - Never silently overwrite an unknown machine. If the target profile also
 *     declares plugins, the plan says which ones would be removed, and the
 *     caller has to ask for that explicitly.
 *
 * @module dsh-config-sync/archive
 */

import { mkdir, readFile, writeFile, copyFile, readdir } from 'node:fs/promises'
import { dirname, join } from 'node:path'

import { decryptBuffer, encryptBuffer, isEncryptedBuffer } from './crypto.js'
import {
  ARCHIVE_FORMAT,
  CATEGORIES,
  defaultCategories,
  exists,
  installTargetFor,
  planBackup,
  readProfileManifest,
  resolveCategories,
  sha256,
  toMemberPath,
  walkFiles,
} from './inventory.js'
import { MAX_ENTRY_BYTES, readZip, writeZip } from './zip.js'

/** Manifest member name. Always first so a reader can see the plan early. */
const MANIFEST_MEMBER = 'manifest.json'

/** Human-readable notes member. */
const README_MEMBER = 'RESTORE-README.txt'

/** Where the archive keeps the encrypted credential bundle. */
const SECRET_MEMBER = 'secrets/credentials.enc'

/** Credentials are never written to plaintext members, under any option. */
const FORBIDDEN_PLAINTEXT = ['.credentials.yaml']
/**
 * Turn a byte count into something a person reads.
 * @param {number} bytes
 */
export function formatBytes (bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  let value = bytes
  let i = 0
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024
    i += 1
  }
  return `${value < 10 && i > 0 ? value.toFixed(1) : Math.round(value)} ${units[i]}`
}

/**
 * Create a backup archive.
 *
 * @param {object} params
 * @param {string} params.dshHome
 * @param {string} params.profile
 * @param {string} params.output archive path to create
 * @param {string[]} [params.categories]
 * @param {boolean} [params.withSessions]
 * @param {string} [params.password] encrypts the credential category
 * @param {boolean} [params.dryRun] plan only, write nothing
 * @returns {Promise<object>} a report the tool renders
 */
export async function backup (params) {
  const { dshHome, profile, output } = params
  const plan = await planBackup({
    dshHome,
    profile,
    categories: params.categories,
    withSessions: params.withSessions,
  })

  const credentialFiles = plan.files.filter((f) => f.category === 'credentials')
  if (credentialFiles.length > 0 && !params.password) {
    throw new Error(
      '选择了备份登录凭据，但没有提供加密口令。为避免 API key 明文落盘，' +
      '请提供 password，或从类别中去掉 credentials。',
    )
  }

  const byCategory = {}
  for (const file of plan.files) {
    byCategory[file.category] = (byCategory[file.category] ?? 0) + 1
  }

  if (params.dryRun === true) {
    return {
      mode: 'dry-run',
      output,
      wouldArchive: plan.files.length,
      byCategory,
      plugins: plan.plugins,
      categories: plan.categories,
      warnings: plan.warnings,
      skipped: plan.skipped,
    }
  }

  // --- credential bundle ---------------------------------------------------
  // Encrypted and embedded, never written as a loose file: the archive is an
  // ordinary file the user may copy anywhere, and it must not be the thing that
  // leaks a token.
  //
  // Packed as JSON with base64 payloads rather than as delimited text: member
  // names can be nested (`secrets/workbuddy-vault/cn/<id>.json`), and a
  // delimiter-based format would need escaping rules that are easy to get
  // subtly wrong on binary or on a body containing the delimiter.
  let secretBundle = null
  if (credentialFiles.length > 0) {
    const bundle = { version: 1, files: {} }
    for (const file of credentialFiles) {
      const data = await readFile(file.absolute)
      bundle.files[file.member] = data.toString('base64')
    }
    secretBundle = await encryptBuffer(JSON.stringify(bundle), params.password)
  }

  // --- members -------------------------------------------------------------
  // Order is fixed (manifest, readme, config, state, secrets) so two runs over
  // unchanged inputs produce the same member order.
  const entries = []
  const checksums = {}
  let uncompressedBytes = 0

  const add = async (member, absolute, data) => {
    const buffer = data ?? await readFile(absolute)
    // Defence in depth: even if a future category forgets, a plaintext
    // credential must never reach the archive.
    if (FORBIDDEN_PLAINTEXT.some((n) => member.toLowerCase().endsWith(n))) {
      throw new Error(`拒绝把凭据明文写入归档：${member}`)
    }
    uncompressedBytes += buffer.length
    checksums[member] = sha256(buffer)
    return buffer
  }

  const ordered = [...plan.files].sort((a, b) => (a.member < b.member ? -1 : 1))
  const payloads = []
  for (const file of ordered) {
    if (file.category === 'credentials') continue // handled as the bundle
    const buffer = await add(file.member, file.absolute)
    payloads.push({ member: file.member, buffer })
  }

  const manifest = {
    format: plan.format,
    generator: 'dsh-config-sync',
    createdAt: plan.createdAt,
    source: plan.source,
    categories: plan.categories,
    counts: { files: payloads.length + (secretBundle ? 1 : 0), byCategory },
    pluginCount: plan.plugins.length,
    plugins: plan.plugins,
    bundles: plan.bundles,
    secretsIncluded: secretBundle !== null,
    secretsEncrypted: secretBundle !== null,
    files: [
      ...payloads.map((p) => ({ member: p.member, size: p.buffer.length, sha256: checksums[p.member] })),
      ...(secretBundle
        ? [{ member: SECRET_MEMBER, size: secretBundle.length, sha256: sha256(secretBundle), encrypted: true }]
        : []),
    ],
    warnings: plan.warnings,
    skipped: plan.skipped,
  }
  const manifestBuffer = Buffer.from(JSON.stringify(manifest, null, 2), 'utf8')

  entries.push({ name: MANIFEST_MEMBER, data: manifestBuffer })
  entries.push({ name: README_MEMBER, data: Buffer.from(renderRestoreReadme(manifest), 'utf8') })
  for (const p of payloads) entries.push({ name: p.member, data: p.buffer })
  if (secretBundle) entries.push({ name: SECRET_MEMBER, data: secretBundle })

  await mkdir(dirname(output), { recursive: true })
  const written = await writeZip(output, entries)
  const archiveBytes = (await readFile(output)).length

  return {
    mode: 'backup',
    output,
    format: ARCHIVE_FORMAT,
    createdAt: manifest.createdAt,
    files: manifest.counts.files,
    byCategory,
    plugins: plan.plugins,
    categories: plan.categories,
    secretsIncluded: secretBundle !== null,
    archiveBytes,
    uncompressedBytes: written.uncompressedBytes,
    ratio: uncompressedBytes > 0 ? archiveBytes / uncompressedBytes : 1,
    warnings: plan.warnings,
    skipped: plan.skipped,
  }
}

/** The plain-text note a person reads after opening the zip. */
function renderRestoreReadme (manifest) {
  const lines = [
    'DSH 配置备份归档 / DSH configuration backup archive',
    '='.repeat(52),
    '',
    `生成时间：${manifest.createdAt}`,
    `来源机器：${manifest.source.host} (${manifest.source.platform}/${manifest.source.arch})`,
    `来源 profile：${manifest.source.profile}`,
    `包含类别：${manifest.categories.join('、')}`,
    `插件数量：${manifest.pluginCount}`,
    `文件数量：${manifest.counts.files}`,
    '',
    '这个归档里没有 node_modules：插件本体不备份，还原时按 manifest.json 里记录的',
    '包名与版本重新安装，因此在另一台电脑上得到的是干净、正确的依赖树。',
    '',
  ]

  if (manifest.secretsIncluded) {
    lines.push(
      '本归档包含登录凭据（secrets/credentials.enc），已用口令 AES-256-GCM 加密。',
      '存档内不存在凭据明文；还原时必须提供同一个口令才能解密。',
      '如果忘记了口令，这部分内容无法恢复，需要在新电脑上重新登录。',
      '',
    )
  } else {
    lines.push(
      '本归档不包含登录凭据：还原后需要在新电脑上重新登录 DeepSeek 账号。',
      '',
    )
  }

  lines.push('还原方式（任选其一）：', '')
  lines.push('1) 在 DSH 里让 agent 调用 restore_dsh_config 工具，先预览再应用；')
  lines.push('2) 命令行：')
  lines.push('   dsh-config-sync restore --input <本归档> --profile <目标 profile>')
  lines.push('   加 --apply 才真正写入；默认只预览。')
  lines.push('')
  lines.push('完整插件清单见 manifest.json 的 plugins 数组。')
  return lines.join('\n')
}

/**
 * Work out exactly what applying an archive would do, without doing it.
 *
 * This is the single source of truth for the preview text AND for `restore()`,
 * so the preview cannot drift from the real behaviour.
 *
 * @param {object} params
 * @param {string} params.dshHome
 * @param {string} params.profile
 * @param {string} params.input archive path
 * @param {string} [params.password]
 */
export async function planRestore (params) {
  const { dshHome, profile, input } = params
  if (!(await exists(input))) throw new Error(`找不到备份归档：${input}`)

  const entries = await readZip(input)
  const manifestRaw = entries.get(MANIFEST_MEMBER)
  if (!manifestRaw) throw new Error('这不是本插件生成的备份：归档内缺少 manifest.json')

  let manifest
  try {
    manifest = JSON.parse(manifestRaw.toString('utf8'))
  } catch (error) {
    throw new Error(`manifest.json 无法解析：${error.message}`)
  }
  if (manifest.format !== ARCHIVE_FORMAT) {
    throw new Error(`归档格式版本 ${manifest.format} 不受支持（本插件支持 ${ARCHIVE_FORMAT}）`)
  }

  // Verify every payload against the manifest before planning a single write.
  // A corrupt member discovered mid-apply would leave a half-restored profile.
  const corrupt = []
  for (const record of manifest.files ?? []) {
    const data = entries.get(record.member)
    if (!data) {
      corrupt.push(`${record.member}（缺失）`)
      continue
    }
    if (data.length !== record.size) {
      corrupt.push(`${record.member}（大小不符）`)
      continue
    }
    if (sha256(data) !== record.sha256) corrupt.push(`${record.member}（校验和不符）`)
  }
  if (corrupt.length > 0) {
    throw new Error(`归档已损坏，已中止还原以免写坏 profile：\n  - ${corrupt.join('\n  - ')}`)
  }

  const profileDir = join(dshHome, 'profiles', profile)
  const profileExists = await exists(profileDir)

  // What would change on disk.
  const writes = []
  for (const record of manifest.files ?? []) {
    if (record.member === SECRET_MEMBER) continue
    writes.push({
      member: record.member,
      target: targetPathFor(record.member, dshHome, profile),
      category: categoryOfMember(record.member),
      size: record.size,
    })
  }

  // Shell profiles (`@deepseek-ai/dsh-base`, `dsh-web-app`) are part of every
  // profile and are not user plugins; excluding them from the "would be removed"
  // list is the difference between a useful warning and noise.
  const incoming = new Set((manifest.plugins ?? []).map((p) => p.name))
  const current = profileExists ? await readProfileManifest(profileDir) : { dependencies: {}, bundles: [] }
  const currentPlugins = Object.keys(current.dependencies ?? {})
  const wouldRemove = currentPlugins.filter((name) => !incoming.has(name))
  const wouldAdd = [...incoming].filter((name) => !currentPlugins.includes(name))
  const unchanged = [...incoming].filter((name) => currentPlugins.includes(name))

  const secrets = entries.get(SECRET_MEMBER)
  const plan = {
    mode: 'restore-plan',
    input,
    profile,
    profileDir,
    profileExists,
    createdAt: manifest.createdAt,
    source: manifest.source,
    categories: manifest.categories,
    secretsIncluded: manifest.secretsIncluded === true,
    secretsPresent: secrets !== undefined,
    fileCount: writes.length,
    writes,
    plugins: manifest.plugins ?? [],
    pluginCount: (manifest.plugins ?? []).length,
    wouldAdd,
    wouldRemove,
    unchanged,
    registeredBundles: manifest.bundles ?? [],
    warnings: [...(manifest.warnings ?? [])],
  }

  if (plan.secretsIncluded && !secrets) {
    plan.warnings.push('归档声称包含加密凭据，但找不到 secrets/credentials.enc。')
  }
  if (plan.secretsIncluded && secrets && !params.password) {
    plan.warnings.push('归档含加密凭据，但未提供口令——还原时会跳过凭据（其余设置照常还原）。')
  }
  if (!plan.profileExists) {
    plan.warnings.push(`目标 profile 目录不存在（${profileDir}），还原会创建它，但插件需要手动安装才能加载。`)
  }
  if (wouldRemove.length > 0) {
    plan.warnings.push(`目标 profile 已有 ${wouldRemove.length} 个归档中没有的插件，应用后它们的登记会被移除：${wouldRemove.join('、')}`)
  }
  if (manifest.source?.platform && manifest.source.platform !== process.platform) {
    plan.warnings.push(
      `归档来自 ${manifest.source.platform}，本机是 ${process.platform}：` +
      '设置文件通常通用，但含绝对路径的配置需要手动核对。',
    )
  }

  return { plan, manifest, entries }
}

/**
 * Map an archive member back to the absolute path it restores to.
 *
 * Member names are always forward-slash (that is what the writer normalises
 * to), so they are split and rejoined with the host separator rather than fed
 * to `join` as one string — on Windows a forward-slash member would otherwise
 * become a single oddly-named file.
 */
export function targetPathFor (member, dshHome, profile) {
  if (member.startsWith('profile/')) {
    return join(dshHome, 'profiles', profile, ...member.slice('profile/'.length).split('/'))
  }
  if (member.startsWith('home/')) {
    return join(dshHome, ...member.slice('home/'.length).split('/'))
  }
  throw new Error(`无法定位归档成员的目标路径：${member}`)
}

/** Which category a member belongs to, for the preview grouping. */
function categoryOfMember (member) {
  if (member.startsWith('profile/')) return 'profile-config'
  if (member.startsWith('home/storages/') || member.startsWith('home/telemetry/')) return 'home-config'
  if (member.startsWith('home/sessions/')) return 'sessions'
  if (member.startsWith('secrets/')) return 'credentials'
  return 'plugin-state'
}

/**
 * Restore an archive onto this machine.
 *
 * @param {object} params
 * @param {string} params.dshHome
 * @param {string} params.profile
 * @param {string} params.input
 * @param {boolean} [params.apply] false = preview only (the default in the tool)
 * @param {string} [params.password]
 * @param {boolean} [params.overwritePlugins] allow removing current plugin entries
 * @param {boolean} [params.withCredentials] actually write decrypted credentials
 * @returns {Promise<object>}
 */
export async function restore (params) {
  const { dshHome, profile, input } = params
  const { plan, entries } = await planRestore({ dshHome, profile, input, password: params.password })

  if (params.apply !== true) {
    return { ...plan, applied: false }
  }

  if (plan.wouldRemove.length > 0 && params.overwritePlugins !== true) {
    throw new Error(
      `目标 profile 有 ${plan.wouldRemove.length} 个归档里没有的插件（${plan.wouldRemove.join('、')}）。` +
      '如果确认要用归档覆盖插件清单，请重试并设置 overwritePlugins: true。',
    )
  }

  const profileDir = plan.profileDir

  // --- restore point -------------------------------------------------------
  // Snapshot the profile's current config before the first write. Named after
  // the moment, so repeated syncs accumulate a history rather than clobbering
  // one slot.
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const restorePoint = join(dshHome, 'profiles', `.dsh-config-sync-restore-point-${profile}-${stamp}`)
  const saved = []
  if (plan.profileExists) {
    await mkdir(restorePoint, { recursive: true })
    for (const entry of await readdir(profileDir, { withFileTypes: true })) {
      if (!entry.isFile()) continue
      if (!/\.(json|jsonc|ya?ml)$/i.test(entry.name)) continue
      await copyFile(join(profileDir, entry.name), join(restorePoint, entry.name))
      saved.push(entry.name)
    }
    await writeFile(
      join(restorePoint, 'RESTORE-POINT.json'),
      JSON.stringify({ createdAt: new Date().toISOString(), source: input, profile, files: saved }, null, 2),
      'utf8',
    )
  }

  // --- apply ---------------------------------------------------------------
  const written = []
  const failed = []
  for (const record of plan.writes) {
    const data = entries.get(record.member)
    if (!data) {
      failed.push({ member: record.member, error: '归档中缺少该成员' })
      continue
    }
    try {
      await mkdir(dirname(record.target), { recursive: true })
      await writeFile(record.target, data)
      written.push(record.member)
    } catch (error) {
      failed.push({ member: record.member, error: `${error.code ?? ''} ${error.message}`.trim() })
    }
  }

  // --- credentials ---------------------------------------------------------
  // Decrypted credentials are written only on an explicit second opt-in, so
  // restoring a colleague's settings cannot silently adopt their account.
  let credentialsRestored = false
  let credentialsError = null
  const secretBlob = entries.get(SECRET_MEMBER)
  if (plan.secretsIncluded && secretBlob) {
    if (params.withCredentials !== true) {
      plan.warnings.push('归档含加密凭据，但未设置 withCredentials，已跳过凭据还原。')
    } else if (!params.password) {
      plan.warnings.push('归档含加密凭据，但未提供口令，已跳过凭据还原。')
    } else {
      try {
        const plaintext = await decryptBuffer(secretBlob, params.password)
        const bundle = JSON.parse(plaintext.toString('utf8'))
        if (bundle?.version !== 1 || typeof bundle.files !== 'object' || bundle.files === null) {
          throw new Error('凭据内容格式无法识别')
        }
        // Members are `secrets/<...>`; the path below `secrets/` is restored
        // relative to DSH_HOME, which keeps a nested vault directory nested.
        for (const [member, base64] of Object.entries(bundle.files)) {
          const rel = member.replace(/^secrets\//, '')
          if (rel === member || rel.includes('..')) {
            throw new Error(`凭据成员路径不合法：${member}`)
          }
          const dest = join(dshHome, ...rel.split('/'))
          await mkdir(dirname(dest), { recursive: true })
          await writeFile(dest, Buffer.from(String(base64), 'base64'))
        }
        credentialsRestored = true
      } catch (error) {
        credentialsError = error.message
      }
    }
  }

  // --- plugin install plan -------------------------------------------------
  // The archive cannot carry node_modules, so the restore hands back the exact
  // install commands instead of pretending the plugins are already there.
  const installCommands = plan.plugins
    .filter((p) => p.install)
    .map((p) => p.install)

  return {
    ...plan,
    applied: true,
    mode: 'restore',
    written,
    writtenCount: written.length,
    failed,
    restorePoint: plan.profileExists ? restorePoint : null,
    restorePointFiles: saved,
    credentialsRestored,
    credentialsError,
    installCommands,
  }
}

/**
 * Verify an archive without applying it: every member present, sized and
 * checksummed, plus a summary of what it holds.
 */
export async function verify (input) {
  const entries = await readZip(input)
  const manifestRaw = entries.get(MANIFEST_MEMBER)
  if (!manifestRaw) throw new Error('归档内缺少 manifest.json，不是本插件生成的备份。')
  const manifest = JSON.parse(manifestRaw.toString('utf8'))

  const problems = []
  for (const record of manifest.files ?? []) {
    const data = entries.get(record.member)
    if (!data) problems.push(`${record.member}: 缺失`)
    else if (data.length !== record.size) problems.push(`${record.member}: 大小不符`)
    else if (sha256(data) !== record.sha256) problems.push(`${record.member}: 校验和不符`)
  }

  return {
    input,
    ok: problems.length === 0,
    problems,
    createdAt: manifest.createdAt,
    source: manifest.source,
    categories: manifest.categories,
    pluginCount: manifest.pluginCount ?? (manifest.plugins ?? []).length,
    plugins: manifest.plugins ?? [],
    fileCount: (manifest.files ?? []).length,
    secretsIncluded: manifest.secretsIncluded === true,
    members: [...entries.keys()],
    warnings: manifest.warnings ?? [],
  }
}

/**
 * Summarise the local machine's current state, for "what would I back up?".
 */
export async function status (params) {
  const { dshHome, profile } = params
  const profileDir = join(dshHome, 'profiles', profile)
  const manifest = await readProfileManifest(profileDir)
  const plan = await planBackup({ dshHome, profile, categories: params.categories, withSessions: params.withSessions })

  const byCategory = {}
  for (const file of plan.files) byCategory[file.category] = (byCategory[file.category] ?? 0) + 1

  const homeEntries = []
  for (const entry of await readdir(dshHome, { withFileTypes: true }).catch(() => [])) {
    if (entry.isDirectory()) homeEntries.push(entry.name)
  }

  return {
    dshHome,
    profile,
    profileDir,
    profileExists: await exists(profileDir),
    plugins: plan.plugins,
    bundles: manifest.bundles,
    categories: plan.categories,
    byCategory,
    wouldArchive: plan.files.length,
    homeDirs: homeEntries,
    warnings: plan.warnings,
  }
}

/** Re-export so callers do not need a second import path. */
export { defaultCategories, CATEGORIES, resolveCategories, installTargetFor, walkFiles, toMemberPath, exists }
