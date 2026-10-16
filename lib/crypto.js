/**
 * dsh-config-sync — password-based encryption for the credential bundle.
 *
 * Credentials are OFF by default. When the user explicitly opts in, they land
 * in the archive as this module's binary envelope rather than as YAML, so a
 * backup that contains a DeepSeek API key never becomes a file you can read by
 * accident — it is either encrypted or it is not there at all.
 *
 * Primitives are the platform's own: scrypt for the key (memory-hard, so a
 * stolen archive is expensive to attack offline) and AES-256-GCM for the
 * payload (authenticated, so a tampered archive fails to decrypt instead of
 * yielding a plausible-looking wrong plaintext).
 *
 * Envelope layout, all big-endian-free fixed fields:
 *
 *   magic  "DSHCS1\n"      7 bytes
 *   salt                   16 bytes   scrypt salt
 *   iv                     12 bytes   GCM nonce
 *   tag                    16 bytes   GCM auth tag
 *   ciphertext             variable   AES-256-GCM(plaintext)
 *
 * @module dsh-config-sync/crypto
 */

import { createCipheriv, createDecipheriv, randomBytes, scrypt, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'

const scryptAsync = promisify(scrypt)

const MAGIC = Buffer.from('DSHCS1\n', 'utf8')
const SALT_BYTES = 16
const IV_BYTES = 12
const TAG_BYTES = 16
const KEY_BYTES = 32
const HEADER_BYTES = MAGIC.length + SALT_BYTES + IV_BYTES + TAG_BYTES

/**
 * scrypt cost parameters.
 *
 * N=2^15 with r=8 needs 128*N*r = 32 MiB, which is exactly Node's default
 * `maxmem` — so the default would throw. `maxmem` is raised explicitly rather
 * than lowering N: the memory hardness is the entire point of choosing scrypt.
 */
const SCRYPT_OPTIONS = { N: 2 ** 15, r: 8, p: 1, maxmem: 96 * 1024 * 1024 }

/**
 * Encrypt a payload with a password.
 * @param {Buffer|string} plaintext
 * @param {string} password
 * @returns {Promise<Buffer>} the binary envelope
 */
export async function encryptBuffer (plaintext, password) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('encryptBuffer: a non-empty password is required')
  }
  const data = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8')
  const salt = randomBytes(SALT_BYTES)
  const iv = randomBytes(IV_BYTES)
  const key = await scryptAsync(password, salt, KEY_BYTES, SCRYPT_OPTIONS)

  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const ciphertext = Buffer.concat([cipher.update(data), cipher.final()])
  const tag = cipher.getAuthTag()

  return Buffer.concat([MAGIC, salt, iv, tag, ciphertext])
}

/**
 * Decrypt an envelope produced by {@link encryptBuffer}.
 *
 * A wrong password and a corrupted archive are both indistinguishable from
 * GCM's point of view — it fails authentication either way. The error says so
 * instead of guessing, because guessing wrong here would send the user hunting
 * for file corruption that does not exist.
 *
 * @param {Buffer} envelope
 * @param {string} password
 * @returns {Promise<Buffer>} the plaintext
 */
export async function decryptBuffer (envelope, password) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('decryptBuffer: a non-empty password is required')
  }
  const buffer = Buffer.isBuffer(envelope) ? envelope : Buffer.from(envelope)
  if (buffer.length < HEADER_BYTES) {
    throw new Error('encrypted bundle is truncated')
  }
  if (!timingSafeEqual(buffer.subarray(0, MAGIC.length), MAGIC)) {
    throw new Error('encrypted bundle has an unrecognised header')
  }

  let p = MAGIC.length
  const salt = buffer.subarray(p, p += SALT_BYTES)
  const iv = buffer.subarray(p, p += IV_BYTES)
  const tag = buffer.subarray(p, p += TAG_BYTES)
  const ciphertext = buffer.subarray(p)

  const key = await scryptAsync(password, salt, KEY_BYTES, SCRYPT_OPTIONS)
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(tag)

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()])
  } catch {
    throw new Error('解密失败：口令错误，或该文件已被损坏/篡改。')
  }
}

/**
 * Cheap structural test used to tell an encrypted bundle from a plain archive
 * member without attempting a decrypt.
 * @param {Buffer} buffer
 * @returns {boolean}
 */
export function isEncryptedBuffer (buffer) {
  return Buffer.isBuffer(buffer) &&
    buffer.length >= HEADER_BYTES &&
    buffer.subarray(0, MAGIC.length).equals(MAGIC)
}
