/**
 * dsh-config-sync — dependency-free ZIP reader and writer.
 *
 * Why hand-rolled instead of a library: this plugin is installed into somebody
 * else's DSH profile, so every dependency it declares becomes something that
 * must resolve, download and keep working on the *next* machine — including a
 * machine that is being repaired precisely because its plugin set broke. Node
 * already ships zlib and the ZIP container is small enough to implement
 * honestly, so this module owns the ~250 lines rather than the install graph.
 *
 * Scope: exactly the subset this plugin produces and reads back — stored and
 * deflated entries, UTF-8 names, no encryption, no ZIP64. `writeZip` refuses a
 * payload that would need ZIP64 instead of quietly emitting a broken archive,
 * and `readZip` verifies CRC-32 on every entry so a truncated or corrupted
 * backup fails loudly rather than restoring half a profile.
 *
 * @module dsh-config-sync/zip
 */

import { once } from 'node:events'
import { createWriteStream } from 'node:fs'
import { readFile, stat } from 'node:fs/promises'
import { promisify } from 'node:util'
import { deflateRaw, inflateRaw } from 'node:zlib'

const deflateRawAsync = promisify(deflateRaw)
const inflateRawAsync = promisify(inflateRaw)

/** ZIP record signatures. */
const SIG_LOCAL = 0x04034b50
const SIG_CENTRAL = 0x02014b50
const SIG_EOCD = 0x06054b50

/** General-purpose flag bit 11: the entry name is UTF-8, not CP437. */
const FLAG_UTF8 = 0x0800

const METHOD_STORE = 0
const METHOD_DEFLATE = 8

/** ZIP32 hard ceilings. Past these the format needs ZIP64, which we refuse. */
const MAX_ENTRIES = 0xffff
const MAX_ZIP32 = 0xffffffff

/** Largest entry we will buffer in memory. Config state is nowhere near this. */
export const MAX_ENTRY_BYTES = 256 * 1024 * 1024

/** Standard CRC-32 (IEEE 802.3) table, built once per process. */
const CRC_TABLE = (() => {
  const table = new Int32Array(256)
  for (let i = 0; i < 256; i += 1) {
    let c = i
    for (let k = 0; k < 8; k += 1) c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    table[i] = c
  }
  return table
})()

/**
 * CRC-32 of a buffer, as ZIP stores it.
 * @param {Buffer} buffer
 * @returns {number} unsigned 32-bit checksum
 */
export function crc32 (buffer) {
  let crc = -1
  for (let i = 0; i < buffer.length; i += 1) {
    crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buffer[i]) & 0xff]
  }
  return (crc ^ -1) >>> 0
}

/**
 * Convert a timestamp to the DOS date/time pair ZIP headers use.
 *
 * The format cannot represent anything before 1980, so an older mtime is
 * clamped rather than wrapping into a nonsense year.
 */
function dosDateTime (value) {
  const d = value instanceof Date ? value : new Date(value ?? Date.now())
  const year = Math.max(1980, d.getFullYear())
  return {
    dosTime: (d.getHours() << 11) | (d.getMinutes() << 5) | (Math.floor(d.getSeconds() / 2)),
    dosDate: ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  }
}

/**
 * Normalise an entry name to the forward-slash, relative form ZIP requires.
 * Rejects anything that could escape the extraction root.
 */
export function normalizeEntryName (name) {
  const value = String(name).replace(/\\/g, '/').replace(/^\.?\//, '')
  if (value === '' || value.startsWith('/') || /^[a-zA-Z]:/.test(value)) {
    throw new Error(`refusing unsafe zip entry name: ${name}`)
  }
  const parts = []
  for (const part of value.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') throw new Error(`refusing unsafe zip entry name: ${name}`)
    parts.push(part)
  }
  if (parts.length === 0) throw new Error(`refusing unsafe zip entry name: ${name}`)
  return parts.join('/')
}

/**
 * Write a ZIP archive.
 *
 * Entries are streamed one at a time, so peak memory is bounded by the largest
 * single file rather than by the archive. Each entry may carry `data` (a Buffer
 * or string) or `path` (a file to read).
 *
 * @param {string} outPath archive to create
 * @param {Array<{name: string, data?: Buffer|string, path?: string, mtime?: Date, store?: boolean}>} entries
 * @param {{level?: number}} [options]
 * @returns {Promise<{files: number, bytes: number, uncompressedBytes: number}>}
 */
export async function writeZip (outPath, entries, options = {}) {
  const level = options.level ?? 9
  const stream = createWriteStream(outPath)
  const central = []
  let offset = 0
  let fileCount = 0
  let uncompressedBytes = 0

  const write = async (buffer) => {
    offset += buffer.length
    if (!stream.write(buffer)) await once(stream, 'drain')
  }

  try {
    for (const entry of entries) {
      const name = normalizeEntryName(entry.name)
      const isDir = name.endsWith('/')
      let data
      let mtime = entry.mtime

      if (isDir) {
        data = Buffer.alloc(0)
      } else if (entry.data !== undefined) {
        data = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(String(entry.data), 'utf8')
      } else if (entry.path !== undefined) {
        const info = await stat(entry.path)
        if (info.isDirectory()) {
          // Directory markers are synthesised by the caller; a real directory
          // reaching here would silently become an empty file.
          throw new Error(`writeZip: ${entry.path} is a directory, expected a file`)
        }
        if (info.size > MAX_ENTRY_BYTES) {
          throw new Error(`writeZip: ${entry.path} exceeds ${MAX_ENTRY_BYTES} bytes`)
        }
        mtime = mtime ?? info.mtime
        data = await readFile(entry.path)
      } else {
        throw new Error(`writeZip: entry ${name} has neither data nor path`)
      }

      if (fileCount + 1 > MAX_ENTRIES) {
        throw new Error(`writeZip: more than ${MAX_ENTRIES} entries needs ZIP64`)
      }
      if (offset > MAX_ZIP32) {
        throw new Error('writeZip: archive exceeds 4 GiB and would need ZIP64')
      }

      const nameBuf = Buffer.from(name, 'utf8')
      const { dosTime, dosDate } = dosDateTime(mtime)
      const crc = isDir ? 0 : crc32(data)

      // Storing beats deflating when the payload is already incompressible.
      let method = METHOD_STORE
      let payload = data
      if (!isDir && data.length > 0 && entry.store !== true) {
        const deflated = await deflateRawAsync(data, { level })
        if (deflated.length < data.length) {
          method = METHOD_DEFLATE
          payload = deflated
        }
      }

      const local = Buffer.alloc(30)
      local.writeUInt32LE(SIG_LOCAL, 0)
      local.writeUInt16LE(20, 4) // version needed to extract
      local.writeUInt16LE(FLAG_UTF8, 6)
      local.writeUInt16LE(method, 8)
      local.writeUInt16LE(dosTime, 10)
      local.writeUInt16LE(dosDate, 12)
      local.writeUInt32LE(crc, 14)
      local.writeUInt32LE(payload.length, 18)
      local.writeUInt32LE(data.length, 22)
      local.writeUInt16LE(nameBuf.length, 26)
      local.writeUInt16LE(0, 28) // extra field length

      const localOffset = offset
      await write(local)
      await write(nameBuf)
      await write(payload)

      central.push({
        name: nameBuf,
        method,
        crc,
        compSize: payload.length,
        uncompSize: data.length,
        dosTime,
        dosDate,
        localOffset,
        isDir,
      })

      fileCount += 1
      uncompressedBytes += data.length
    }

    // The central directory's start offset must be captured BEFORE writing it —
    // this is the offset the EOCD records, and every reader seeks there to find
    // the entries. Capturing it afterwards would point at the EOCD itself.
    const cdOffset = offset
    let cdSize = 0
    for (const e of central) {
      const header = Buffer.alloc(46)
      header.writeUInt32LE(SIG_CENTRAL, 0)
      header.writeUInt16LE(20, 4) // version made by
      header.writeUInt16LE(20, 6) // version needed
      header.writeUInt16LE(FLAG_UTF8, 8)
      header.writeUInt16LE(e.method, 10)
      header.writeUInt16LE(e.dosTime, 12)
      header.writeUInt16LE(e.dosDate, 14)
      header.writeUInt32LE(e.crc, 16)
      header.writeUInt32LE(e.compSize, 20)
      header.writeUInt32LE(e.uncompSize, 24)
      header.writeUInt16LE(e.name.length, 28)
      header.writeUInt16LE(0, 30) // extra
      header.writeUInt16LE(0, 32) // comment
      header.writeUInt16LE(0, 34) // disk number start
      header.writeUInt16LE(0, 36) // internal attributes
      // External attributes: Unix mode in the high word, so an unzip on Linux
      // or macOS restores sensible permissions instead of 000.
      header.writeUInt32LE(e.isDir ? 0x41ed0010 : 0x81a40000, 38)
      header.writeUInt32LE(e.localOffset, 42)
      await write(header)
      await write(e.name)
      cdSize += header.length + e.name.length
    }

    const eocd = Buffer.alloc(22)
    eocd.writeUInt32LE(SIG_EOCD, 0)
    eocd.writeUInt16LE(0, 4) // this disk
    eocd.writeUInt16LE(0, 6) // disk with central directory
    eocd.writeUInt16LE(fileCount, 8)
    eocd.writeUInt16LE(fileCount, 10)
    eocd.writeUInt32LE(cdSize, 12)
    eocd.writeUInt32LE(cdOffset, 16)
    eocd.writeUInt16LE(0, 20) // comment length
    await write(eocd)
  } catch (error) {
    stream.destroy()
    throw error
  }

  stream.end()
  await once(stream, 'finish')

  return { files: fileCount, bytes: offset, uncompressedBytes }
}

/**
 * Read every entry of a ZIP archive into memory.
 *
 * Every entry is CRC-checked and size-checked, so a corrupt archive throws
 * here — before anything is written to a profile.
 *
 * @param {string} zipPath
 * @returns {Promise<Map<string, Buffer>>} entry name -> contents, in directory order
 */
export async function readZip (zipPath) {
  const buffer = await readFile(zipPath)
  if (buffer.length < 22) throw new Error('not a zip archive: file is too short')

  // The EOCD sits at the end, after an optional comment of up to 64 KiB.
  const lowest = Math.max(0, buffer.length - 22 - 0xffff)
  let eocd = -1
  for (let i = buffer.length - 22; i >= lowest; i -= 1) {
    if (buffer.readUInt32LE(i) === SIG_EOCD) {
      eocd = i
      break
    }
  }
  if (eocd < 0) throw new Error('not a zip archive: end-of-central-directory not found')

  const total = buffer.readUInt16LE(eocd + 10)
  const cdSize = buffer.readUInt32LE(eocd + 12)
  const cdOffset = buffer.readUInt32LE(eocd + 16)
  if (total === 0xffff || cdOffset === 0xffffffff) {
    throw new Error('ZIP64 archives are not supported')
  }
  if (cdOffset + cdSize > buffer.length) {
    throw new Error('corrupt zip: central directory lies outside the file')
  }

  const entries = new Map()
  let p = cdOffset
  for (let i = 0; i < total; i += 1) {
    if (p + 46 > buffer.length || buffer.readUInt32LE(p) !== SIG_CENTRAL) {
      throw new Error('corrupt zip: bad central directory entry')
    }
    const method = buffer.readUInt16LE(p + 10)
    const crc = buffer.readUInt32LE(p + 16)
    const compSize = buffer.readUInt32LE(p + 20)
    const uncompSize = buffer.readUInt32LE(p + 24)
    const nameLen = buffer.readUInt16LE(p + 28)
    const extraLen = buffer.readUInt16LE(p + 30)
    const commentLen = buffer.readUInt16LE(p + 32)
    const localOffset = buffer.readUInt32LE(p + 42)
    const name = buffer.toString('utf8', p + 46, p + 46 + nameLen)
    p += 46 + nameLen + extraLen + commentLen

    if (localOffset + 30 > buffer.length || buffer.readUInt32LE(localOffset) !== SIG_LOCAL) {
      throw new Error(`corrupt zip: bad local header for ${name}`)
    }
    const lNameLen = buffer.readUInt16LE(localOffset + 26)
    const lExtraLen = buffer.readUInt16LE(localOffset + 28)
    const dataStart = localOffset + 30 + lNameLen + lExtraLen
    if (dataStart + compSize > buffer.length) {
      throw new Error(`corrupt zip: truncated payload for ${name}`)
    }

    const raw = buffer.subarray(dataStart, dataStart + compSize)
    let data
    if (method === METHOD_STORE) {
      data = Buffer.from(raw)
    } else if (method === METHOD_DEFLATE) {
      data = await inflateRawAsync(raw)
    } else {
      throw new Error(`unsupported compression method ${method} for ${name}`)
    }

    if (data.length !== uncompSize) throw new Error(`size mismatch for ${name}`)
    if (crc32(data) !== crc) throw new Error(`checksum mismatch for ${name}`)

    entries.set(name, data)
  }

  return entries
}
