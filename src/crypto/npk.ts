import { gcm } from '@noble/ciphers/aes.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hexToBytes, randomBytes } from '@noble/hashes/utils.js'
import { KeytrError, DecryptionError, EncryptionError } from '../errors.js'
import { safeZero } from './builtins.js'

/**
 * Stored records ("npk1") from the passkey-held Nostr keys proposal:
 *
 *   prf_input = SHA-256(UTF-8("nostr-passkey:store:v1"))
 *   key       = HKDF-SHA256(PRF(prf_input), hkdf_salt, "nostr-passkey:store:v1", 32)
 *   aad       = "NPK" || 0x01 || type || len(rp_id) || rp_id || author(32) || len(cred) (u16 BE) || cred
 *   record    = "NPK" || 0x01 || type || iv(12) || hkdf_salt(32) || AES-256-GCM(key, iv, plaintext, aad)
 *
 * Separate from v1 nsec blobs and v4 payloads: different PRF input, HKDF info, AAD and layout.
 */
const LABEL = new TextEncoder().encode('nostr-passkey:store:v1')
export const NPK_STORE_PRF_INPUT: Uint8Array = sha256(LABEL)
export const NPK_MAX_PLAINTEXT_BYTES = 65536

/** Record types; the type byte is the index + 1. */
export const NPK_TYPES = ['key', 'seed', 'vault'] as const
export type NpkType = (typeof NPK_TYPES)[number]

const HEADER_BYTES = 5 + 12 + 32
const TAG_BYTES = 16
export const NPK_MAX_RECORD_BYTES = HEADER_BYTES + NPK_MAX_PLAINTEXT_BYTES + TAG_BYTES

/** The values the AAD binds a record to. */
export interface NpkRecordContext {
  type: NpkType
  rpId: string
  /** Author public key, 64 lowercase hex chars */
  author: string
  credentialId: Uint8Array
}

export function npkTypeByte(type: string): number {
  const i = NPK_TYPES.indexOf(type as NpkType)
  if (i < 0) throw new KeytrError(`Unknown stored record type "${type}"`)
  return i + 1
}

export function buildNpkAad({ type, rpId, author, credentialId }: NpkRecordContext): Uint8Array {
  const rp = new TextEncoder().encode(typeof rpId === 'string' ? rpId : '')
  if (rp.length === 0 || rp.length > 255) throw new KeytrError('Invalid relying party ID')
  if (typeof author !== 'string' || !/^[0-9a-f]{64}$/.test(author)) throw new KeytrError('Invalid record author')
  if (!(credentialId instanceof Uint8Array) || credentialId.length === 0 || credentialId.length > 0xffff) {
    throw new KeytrError('Invalid credential ID')
  }
  return new Uint8Array([
    0x4e, 0x50, 0x4b, 0x01, npkTypeByte(type), rp.length, ...rp, ...hexToBytes(author),
    credentialId.length >> 8, credentialId.length & 0xff, ...credentialId,
  ])
}

export function deriveNpkKey(keyMaterial: Uint8Array, hkdfSalt: Uint8Array): Uint8Array {
  if (keyMaterial.length !== 32) throw new KeytrError('PRF output must be 32 bytes')
  return hkdf(sha256, keyMaterial, hkdfSalt, LABEL, 32)
}

export type EncryptNpkRecordOptions = NpkRecordContext & { plaintext: Uint8Array; keyMaterial: Uint8Array }

/**
 * Encrypt with a given salt and IV. Only for reproducing test vectors:
 * reusing an IV with the same key breaks AES-GCM. Not exported from the package.
 */
export function encryptNpkRecordWith(options: EncryptNpkRecordOptions, hkdfSalt: Uint8Array, iv: Uint8Array): Uint8Array {
  const aad = buildNpkAad(options)
  const { plaintext } = options
  if (!plaintext.length || plaintext.length > NPK_MAX_PLAINTEXT_BYTES) throw new EncryptionError(`Stored record plaintext must be 1 to ${NPK_MAX_PLAINTEXT_BYTES} bytes`)
  if (options.type === 'key' && plaintext.length !== 32) throw new EncryptionError('A key record holds exactly 32 bytes')
  const key = deriveNpkKey(options.keyMaterial, hkdfSalt)
  try {
    return new Uint8Array([...aad.subarray(0, 5), ...iv, ...hkdfSalt, ...gcm(key, iv, aad).encrypt(plaintext)])
  } finally {
    safeZero(key)
  }
}

/** Encrypt a stored record with a fresh random salt and IV. */
export function encryptNpkRecord(options: EncryptNpkRecordOptions): Uint8Array {
  return encryptNpkRecordWith(options, randomBytes(32), randomBytes(12))
}

/** The record type from its public header. Throws on anything that is not a supported npk1 record. */
export function npkRecordType(record: Uint8Array): NpkType {
  if (!(record instanceof Uint8Array) || record.length <= HEADER_BYTES + TAG_BYTES || record.length > NPK_MAX_RECORD_BYTES ||
    record[0] !== 0x4e || record[1] !== 0x50 || record[2] !== 0x4b || record[3] !== 0x01 || !NPK_TYPES[record[4] - 1]) {
    throw new DecryptionError('Not a supported stored record')
  }
  return NPK_TYPES[record[4] - 1]
}

/** Authenticate and decrypt a stored record. The type is read from the header, never guessed from the length. */
export function decryptNpkRecord(options: Omit<NpkRecordContext, 'type'> & { record: Uint8Array; keyMaterial: Uint8Array }): { type: NpkType; plaintext: Uint8Array } {
  const { record } = options
  const type = npkRecordType(record)
  const aad = buildNpkAad({ ...options, type })
  const key = deriveNpkKey(options.keyMaterial, record.subarray(17, HEADER_BYTES))
  let plaintext: Uint8Array
  try {
    plaintext = gcm(key, record.subarray(5, 17), aad).decrypt(record.subarray(HEADER_BYTES))
  } catch {
    throw new DecryptionError('Stored record decryption failed - wrong passkey, context or corrupted data')
  } finally {
    safeZero(key)
  }
  if (type === 'key' && plaintext.length !== 32) {
    safeZero(plaintext)
    throw new DecryptionError('A key record must hold exactly 32 bytes')
  }
  return { type, plaintext }
}
