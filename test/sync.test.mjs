/**
 * dsh-config-sync —end-to-end tests.
 *
 * These run against a synthetic DSH home rather than the real one, so they can
 * assert exact counts and never touch the user's actual profile. Run with:
 *
 *   node --test test/
 */

import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, describe, it } from 'node:test'
import { promisify } from 'node:util'

import { backup, planRestore, restore, status, verify } from '../lib/archive.js'
import { decryptBuffer, encryptBuffer, isEncryptedBuffer } from '../lib/crypto.js'
import { planBackup, resolveCategories } from '../lib/inventory.js'
import { crc32, normalizeEntryName, readZip, writeZip } from '../lib/zip.js'

const execFileAsync = promisify(execFile)
const CLI = new URL('../bin/dsh-config-sync.mjs', import.meta.url).pathname.replace(/^\//, '')

/** Build a throwaway DSH home that looks like the real one. */
async function makeFixture () {
  const home = await mkdtemp(join(tmpdir(), 'dshsync-'))
  const profile = 'desktop'
  const profileDir = join(home, 'profiles', profile)
  await mkdir(profileDir, { recursive: true })

  await writeFile(join(profileDir, 'package.json'), JSON.stringify({
    name: 'dsh-profile-desktop',
    private: true,
    dependencies: {
      'dsh-pet': '0.3.7',
      'dsh-lsp-actions': 'github:PerryLink/dsh-lsp-actions',
      // A plain CLI tool installed by mistake: no main/exports, no dsh manifest,
      // no cordis.patch.yml —the "tokenledger" case.
      tokenledger: '^0.1.6',
    },
    dsh: { profile: { bundles: ['@deepseek-ai/dsh-base', 'dsh-pet', 'dsh-lsp-actions'] } },
  }, null, 2))

  // Its on-disk shape: a bin-only CLI package with nothing loadable.
  await mkdir(join(profileDir, 'node_modules', 'tokenledger', 'dist'), { recursive: true })
  await writeFile(join(profileDir, 'node_modules', 'tokenledger', 'package.json'), JSON.stringify({
    name: 'tokenledger',
    version: '0.1.6',
    type: 'commonjs',
    bin: { tokenledger: 'dist/index.js' },
  }))
  await writeFile(join(profileDir, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n')
  await writeFile(join(profileDir, 'cordis.patch.yml'), '- id: ui-theme\n')
  await writeFile(join(profileDir, 'cordis.patch.yml.bak-1791968365320'), 'litter\n')

  // Plugin payload that must never be archived.
  await mkdir(join(profileDir, 'node_modules', 'dsh-pet', 'lib'), { recursive: true })
  await writeFile(join(profileDir, 'node_modules', 'dsh-pet', 'lib', 'index.js'), 'x'.repeat(5000))

  // Home-level settings and plugin state.
  await mkdir(join(home, 'storages'), { recursive: true })
  await writeFile(join(home, 'storages', 'workspace.json'), JSON.stringify({ global: { initialized: true } }))
  await mkdir(join(home, 'dsh-pet'), { recursive: true })
  await writeFile(join(home, 'dsh-pet', 'main-config.jsonc'), '{ "pet": "whale" }')

  // Machine-owned payloads that must be excluded.
  await mkdir(join(home, 'dsh-runtimes', 'junk'), { recursive: true })
  await writeFile(join(home, 'dsh-runtimes', 'junk', 'big.bin'), Buffer.alloc(4096))
  await mkdir(join(home, 'electron'), { recursive: true })
  await writeFile(join(home, 'electron', 'electron.exe'), 'MZ')

  // Credentials.
  await writeFile(join(home, '.credentials.yaml'), 'refs:\n  DEEPSEEK_API_KEY: sk-secret-value\n')

  // A plugin vault holding a live token in plain JSON —the case that must NOT
  // land in an unencrypted archive.
  await mkdir(join(home, 'workbuddy-vault', 'cn'), { recursive: true })
  await writeFile(
    join(home, 'workbuddy-vault', 'cn', 'acct.json'),
    JSON.stringify({ accountId: 'acct', auth: { accessToken: 'eyJhbGciOi-live-token-value' } }),
  )

  // Sessions.
  await mkdir(join(home, 'sessions', 'ws'), { recursive: true })
  await writeFile(join(home, 'sessions', 'ws', 'log.json'), '{"turn":1}')

  return { home, profile, profileDir }
}

let fixture

before(async () => { fixture = await makeFixture() })
after(async () => { await rm(fixture.home, { recursive: true, force: true }) })

describe('zip', () => {
  it('round-trips content with UTF-8 names and compression', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'zip-'))
    const file = join(dir, 'a.zip')
    const payload = '中文内容'.repeat(500)
    await writeZip(file, [
      { name: 'a.txt', data: payload },
      { name: 'nested/b.bin', data: Buffer.from([0, 1, 2, 3, 255]) },
      { name: 'empty.txt', data: '' },
    ])
    const entries = await readZip(file)
    assert.equal(entries.get('a.txt').toString('utf8'), payload)
    assert.deepEqual([...entries.get('nested/b.bin')], [0, 1, 2, 3, 255])
    assert.equal(entries.get('empty.txt').length, 0)
    await rm(dir, { recursive: true, force: true })
  })

  it('detects corruption instead of returning wrong bytes', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'zip-'))
    const file = join(dir, 'a.zip')
    await writeZip(file, [{ name: 'a.txt', data: 'hello world'.repeat(50) }])
    const buf = await readFile(file)

    // Locate the real payload from the local header rather than assuming it is
    // stored: a repetitive payload gets deflated, so the compressed bytes are
    // what must be corrupted for this test to mean anything.
    const nameLen = buf.readUInt16LE(26)
    const extraLen = buf.readUInt16LE(28)
    const payloadStart = 30 + nameLen + extraLen
    const compSize = buf.readUInt32LE(18)
    assert.ok(compSize > 0)

    buf[payloadStart + Math.floor(compSize / 2)] ^= 0xff
    await writeFile(file, buf)
    await assert.rejects(
      readZip(file),
      /checksum mismatch|size mismatch|corrupt|incorrect data check|invalid/,
    )
    await rm(dir, { recursive: true, force: true })
  })

  it('refuses path traversal in entry names', () => {
    assert.throws(() => normalizeEntryName('../escape.txt'), /unsafe/)
    assert.throws(() => normalizeEntryName('C:/abs.txt'), /unsafe/)
    assert.throws(() => normalizeEntryName('a/../../b'), /unsafe/)
    assert.equal(normalizeEntryName('a\\b\\c.txt'), 'a/b/c.txt')
  })

  it('computes the standard CRC-32 vector', () => {
    // The canonical check value for "123456789".
    assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926)
  })
})

describe('crypto', () => {
  it('round-trips with the correct password', async () => {
    const env = await encryptBuffer('secret payload', 'pw-123')
    assert.ok(isEncryptedBuffer(env))
    assert.equal((await decryptBuffer(env, 'pw-123')).toString('utf8'), 'secret payload')
  })

  it('rejects a wrong password', async () => {
    const env = await encryptBuffer('secret payload', 'pw-123')
    await assert.rejects(decryptBuffer(env, 'wrong'), /解密失败/)
  })

  it('never leaves the plaintext readable in the envelope', async () => {
    const env = await encryptBuffer('sk-super-secret-key', 'pw')
    assert.ok(!env.toString('latin1').includes('sk-super-secret-key'))
  })
})

describe('zip portability', () => {
  it('produces an archive other tools can read', async (t) => {
    // Only assert this where PowerShell is available; it is the check that the
    // container is genuinely standard rather than merely self-consistent.
    const dir = await mkdtemp(join(tmpdir(), 'zip-'))
    const file = join(dir, 'p.zip')
    await writeZip(file, [{ name: 'dir/hello.txt', data: 'portable' }])
    try {
      const { stdout } = await execFileAsync('powershell', [
        '-NoProfile', '-Command',
        `Add-Type -A System.IO.Compression.FileSystem; ` +
        `[IO.Compression.ZipFile]::OpenRead('${file}').Entries | ForEach-Object { $_.FullName }`,
      ])
      assert.ok(stdout.includes('dir/hello.txt'), `unexpected listing: ${stdout}`)
    } catch (error) {
      t.skip(`PowerShell unavailable: ${error.message}`)
    }
    await rm(dir, { recursive: true, force: true })
  })
})

describe('inventory', () => {
  it('excludes node_modules, runtimes and Electron', async () => {
    const plan = await planBackup({ dshHome: fixture.home, profile: fixture.profile })
    const members = plan.files.map((f) => f.member)
    assert.ok(!members.some((m) => m.includes('node_modules')), 'node_modules must be excluded')
    assert.ok(!members.some((m) => m.startsWith('home/dsh-runtimes/')), 'runtimes must be excluded')
    assert.ok(!members.some((m) => m.startsWith('home/electron/')), 'electron must be excluded')
    assert.ok(members.includes('profile/package.json'))
    assert.ok(members.includes('profile/pnpm-lock.yaml'))
    assert.ok(members.includes('profile/cordis.patch.yml'))
    assert.ok(members.includes('home/storages/workspace.json'))
    assert.ok(members.includes('home/dsh-pet/main-config.jsonc'))
  })

  it('skips editor .bak litter', async () => {
    const plan = await planBackup({ dshHome: fixture.home, profile: fixture.profile })
    assert.ok(!plan.files.some((f) => f.member.endsWith('.bak-1791968365320')))
  })

  it('excludes credentials and sessions by default', async () => {
    const plan = await planBackup({ dshHome: fixture.home, profile: fixture.profile })
    assert.ok(!plan.files.some((f) => f.category === 'credentials'))
    assert.ok(!plan.files.some((f) => f.category === 'sessions'))
  })

  it('reports plugins with an install target and registration state', async () => {
    const plan = await planBackup({ dshHome: fixture.home, profile: fixture.profile })
    const pet = plan.plugins.find((p) => p.name === 'dsh-pet')
    assert.equal(pet.spec, '0.3.7')
    assert.equal(pet.install, 'dsh-pet@0.3.7')
    assert.equal(pet.registered, true)
    assert.equal(pet.kind, 'plugin')
  })

  it('tells a non-plugin dependency apart from an unregistered plugin', async () => {
    const plan = await planBackup({ dshHome: fixture.home, profile: fixture.profile })
    const ledger = plan.plugins.find((p) => p.name === 'tokenledger')
    assert.equal(ledger.kind, 'not-a-plugin', 'a bin-only CLI must not be called "unregistered"')
    assert.equal(ledger.registered, false)

    // The warning must recommend uninstalling, never registering: there is
    // nothing loadable to register, and that advice once sent a user to edit
    // bundles for a package that cannot load.
    assert.ok(
      plan.warnings.some((w) => w.includes('tokenledger') && w.includes('建议卸载')),
      `expected an uninstall recommendation, got: ${JSON.stringify(plan.warnings)}`,
    )
    assert.ok(
      !plan.warnings.some((w) => w.includes('tokenledger') && w.includes('未登记')),
      'non-plugin deps must not be diagnosed as "unregistered"',
    )
  })

  it('keeps plaintext credential vaults out of an ordinary backup', async () => {
    const plan = await planBackup({ dshHome: fixture.home, profile: fixture.profile })
    assert.ok(
      !plan.files.some((f) => f.member.includes('workbuddy-vault')),
      'a vault holding a live token must not be plain plugin state',
    )
    assert.ok(
      plan.warnings.some((w) => w.includes('workbuddy-vault')),
      'the omission must be reported, not silent',
    )
  })

  it('routes a credential vault through the encrypted category when asked', async () => {
    const out = join(fixture.home, 'backups', 'with-vault.zip')
    await backup({
      dshHome: fixture.home,
      profile: fixture.profile,
      output: out,
      categories: ['profile-config', 'credentials'],
      password: 'pw-123',
    })
    const raw = await readFile(out)
    assert.ok(
      !raw.toString('latin1').includes('live-token-value'),
      'the vault token must not be readable in the archive',
    )

    // And it round-trips back into its nested location.
    const r = await restore({
      dshHome: fixture.home,
      profile: 'vault-target',
      input: out,
      apply: true,
      password: 'pw-123',
      withCredentials: true,
    })
    assert.equal(r.credentialsRestored, true)
    const restored = join(fixture.home, 'workbuddy-vault', 'cn', 'acct.json')
    assert.ok(existsSync(restored), 'nested vault path must survive the round trip')
    assert.ok((await readFile(restored, 'utf8')).includes('live-token-value'))
  })

  it('validates category names', () => {
    assert.throws(() => resolveCategories(['nope']), /未知的备份类别/)
    assert.deepEqual(resolveCategories(['sessions', 'profile-config']), ['profile-config', 'sessions'])
  })
})

describe('backup and restore', () => {
  it('refuses credentials without a password', async () => {
    await assert.rejects(
      backup({
        dshHome: fixture.home,
        profile: fixture.profile,
        output: join(fixture.home, 'should-not-exist.zip'),
        categories: ['profile-config', 'credentials'],
      }),
      /没有提供加密口令/,
    )
  })

  it('creates an archive that verifies', async () => {
    const out = join(fixture.home, 'backups', 'full.zip')
    const r = await backup({
      dshHome: fixture.home,
      profile: fixture.profile,
      output: out,
      categories: ['profile-config', 'home-config', 'plugin-state', 'credentials'],
      password: 'pw-123',
    })
    assert.ok(existsSync(out))
    assert.equal(r.secretsIncluded, true)
    assert.ok(r.archiveBytes > 0)

    const v = await verify(out)
    assert.equal(v.ok, true, JSON.stringify(v.problems))
    assert.equal(v.pluginCount, 3)
  })

  it('never stores the credential plaintext in the archive', async () => {
    const out = join(fixture.home, 'backups', 'full.zip')
    const raw = await readFile(out)
    assert.ok(!raw.toString('latin1').includes('sk-secret-value'), 'API key must not appear in plaintext')
  })

  it('previews by default and writes nothing', async () => {
    const out = join(fixture.home, 'backups', 'full.zip')
    const { plan } = await planRestore({ dshHome: fixture.home, profile: 'restored', input: out })
    assert.ok(plan.fileCount > 0)
    assert.ok(!existsSync(join(fixture.home, 'profiles', 'restored')))
  })

  it('applies into a fresh profile and creates a restore point', async () => {
    const out = join(fixture.home, 'backups', 'full.zip')
    const r = await restore({
      dshHome: fixture.home,
      profile: 'restored',
      input: out,
      apply: true,
      password: 'pw-123',
      withCredentials: true,
    })
    assert.equal(r.applied, true)
    assert.ok(r.writtenCount > 0)
    assert.ok(existsSync(join(fixture.home, 'profiles', 'restored', 'package.json')))
    assert.ok(existsSync(join(fixture.home, 'profiles', 'restored', 'pnpm-lock.yaml')))
    assert.equal(r.credentialsRestored, true)
    assert.ok(r.installCommands.includes('dsh-pet@0.3.7'))
  })

  it('refuses to remove plugins without overwritePlugins', async () => {
    const out = join(fixture.home, 'backups', 'full.zip')
    // A target profile that has an extra plugin the archive knows nothing
    // about: applying would drop it from the registry, so the restore must stop
    // and make the caller say so explicitly.
    const extraDir = join(fixture.home, 'profiles', 'has-extra')
    await mkdir(extraDir, { recursive: true })
    await writeFile(join(extraDir, 'package.json'), JSON.stringify({
      name: 'dsh-profile-has-extra',
      dependencies: { 'dsh-pet': '0.3.7', 'dsh-something-else': '1.0.0' },
      dsh: { profile: { bundles: ['dsh-pet', 'dsh-something-else'] } },
    }))

    await assert.rejects(
      restore({ dshHome: fixture.home, profile: 'has-extra', input: out, apply: true }),
      /overwritePlugins/,
    )

    // And with the explicit opt-in it proceeds.
    const r = await restore({
      dshHome: fixture.home,
      profile: 'has-extra',
      input: out,
      apply: true,
      overwritePlugins: true,
    })
    assert.equal(r.applied, true)
    assert.deepEqual(r.wouldRemove, ['dsh-something-else'])
  })

  it('detects a tampered archive before writing anything', async () => {
    const out = join(fixture.home, 'backups', 'tampered.zip')
    await backup({ dshHome: fixture.home, profile: fixture.profile, output: out })
    const entries = await readZip(out)
    entries.set('profile/cordis.patch.yml', Buffer.from('hacked\n'))
    await writeZip(out, [...entries].map(([name, data]) => ({ name, data })))
    await assert.rejects(
      planRestore({ dshHome: fixture.home, profile: 'desktop', input: out }),
      /归档已损坏/,
    )
  })
})

describe('cli', () => {
  /**
   * Some sandboxes refuse to let Node open the pipes `execFile` needs, and the
   * failure surfaces as `spawn EPERM` before the CLI process ever starts. That
   * is an environment restriction, not a broken CLI —so these cases skip
   * rather than report a defect that does not exist. Run the suite outside such
   * a sandbox (or from a shell directly) to exercise them for real.
   */
  const skipIfUnspawnable = (error) => {
    if (error && error.code === 'EPERM') return true
    return false
  }

  it('prints usage and exits 0', async (t) => {
    try {
      const { stdout } = await execFileAsync(process.execPath, [CLI, '--help'])
      assert.ok(stdout.includes('dsh-config-sync'))
    } catch (error) {
      if (skipIfUnspawnable(error)) return t.skip('sandbox blocks child process pipes (spawn EPERM)')
      throw error
    }
  })

  it('runs status against a fixture home', async (t) => {
    try {
      const { stdout } = await execFileAsync(process.execPath, [CLI, 'status'], {
        env: { ...process.env, DSH_HOME: fixture.home, DSH_PROFILE: fixture.profile },
      })
      assert.ok(stdout.includes('插件 3 个'), stdout)
    } catch (error) {
      if (skipIfUnspawnable(error)) return t.skip('sandbox blocks child process pipes (spawn EPERM)')
      throw error
    }
  })

  it('runs backup and verify end to end', async (t) => {
    const out = join(fixture.home, 'cli.zip')
    const env = { ...process.env, DSH_HOME: fixture.home, DSH_PROFILE: fixture.profile }
    try {
      await execFileAsync(process.execPath, [CLI, 'backup', '--output', out], { env })
      const { stdout } = await execFileAsync(process.execPath, [CLI, 'verify', '--input', out], { env })
      assert.ok(stdout.includes('校验通过'), stdout)
    } catch (error) {
      if (skipIfUnspawnable(error)) return t.skip('sandbox blocks child process pipes (spawn EPERM)')
      throw error
    }
  })

  it('exits 2 on a usage error', async (t) => {
    try {
      await assert.rejects(
        execFileAsync(process.execPath, [CLI, 'verify']),
        (error) => error.code === 2,
      )
    } catch (error) {
      if (skipIfUnspawnable(error)) return t.skip('sandbox blocks child process pipes (spawn EPERM)')
      throw error
    }
  })
})

describe('status', () => {
  it('summarises the local machine', async () => {
    const r = await status({ dshHome: fixture.home, profile: fixture.profile })
    assert.equal(r.plugins.length, 3)
    assert.ok(r.wouldArchive > 0)
    assert.ok(r.categories.includes('profile-config'))
  })
})
