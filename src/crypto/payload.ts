import { gcm } from '@noble/ciphers/aes.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { randomBytes } from '@noble/hashes/utils.js'
import { base64, base64url } from '@scure/base'
import { KeytrError, DecryptionError } from '../errors.js'
import { safeZero } from './builtins.js'

/** Draft typed-payload protocol. Does not alter v1 nsec or legacy v3. */
export const PAYLOAD_VERSION = 4
export const MAX_PAYLOAD_BYTES = 64 * 1024
const HEADER_BYTES = 45
const TAG_BYTES = 16
const MAX_ENCODED_BYTES = 4 * Math.ceil((MAX_PAYLOAD_BYTES + HEADER_BYTES + TAG_BYTES) / 3)
const HKDF_CONTEXT = new TextEncoder().encode('keytr payload encryption v4')

export type PayloadType = 'seed' | 'vault'
export interface PayloadContext {
  credentialId: Uint8Array
  /** Event author and discoverable credential's userHandle. */
  pubkey: string
  rpId: string
  payloadType: PayloadType
  /** Application-owned, versioned serialization identifier. */
  schema: string
}
export type EncryptPayloadOptions = PayloadContext & { keyMaterial: Uint8Array; payload: Uint8Array }
export type DecryptPayloadOptions = PayloadContext & { keyMaterial: Uint8Array; encryptedBlob: string }

export function validatePayloadContext(context: PayloadContext): void {
  if (!(context.credentialId instanceof Uint8Array) || context.credentialId.length < 1 || context.credentialId.length > 1024) throw new KeytrError('Invalid credential ID')
  if (!/^[0-9a-f]{64}$/.test(context.pubkey)) throw new KeytrError('Invalid payload author')
  if (typeof context.rpId !== 'string' || context.rpId.length > 253 || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(context.rpId) || context.rpId.split('.').some(label => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) throw new KeytrError('Invalid relying party ID')
  if (context.payloadType !== 'seed' && context.payloadType !== 'vault') throw new KeytrError('Unsupported payload type')
  if (typeof context.schema !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$/.test(context.schema)) throw new KeytrError('Invalid payload schema')
}

function aad(context: PayloadContext): Uint8Array {
  validatePayloadContext(context)
  return new TextEncoder().encode(JSON.stringify(['keytr', PAYLOAD_VERSION, context.payloadType, context.schema, context.rpId, context.pubkey, base64url.encode(context.credentialId)]))
}

/** Strictly bound content before allocating its decoded buffer. */
export function decodePayloadBlob(content: string): Uint8Array {
  if (typeof content !== 'string' || content.length > MAX_ENCODED_BYTES) throw new DecryptionError('Payload exceeds size limit')
  let blob: Uint8Array
  try { blob = base64.decode(content) } catch { throw new DecryptionError('Invalid payload base64') }
  if (base64.encode(blob) !== content || blob.length <= HEADER_BYTES + TAG_BYTES || blob.length > MAX_PAYLOAD_BYTES + HEADER_BYTES + TAG_BYTES || blob[0] !== PAYLOAD_VERSION) throw new DecryptionError('Invalid payload size or version')
  return blob
}

/** Encrypt opaque application bytes; callers own schema validation and plaintext cleanup. */
export function encryptPayload(options: EncryptPayloadOptions): string {
  const additionalData = aad(options)
  if (options.keyMaterial.length !== 32) throw new KeytrError('PRF output must be 32 bytes')
  if (!(options.payload instanceof Uint8Array) || !options.payload.length || options.payload.length > MAX_PAYLOAD_BYTES) throw new KeytrError('Invalid payload size')
  const iv = randomBytes(12)
  const salt = randomBytes(32)
  const key = hkdf(sha256, options.keyMaterial, salt, HKDF_CONTEXT, 32)
  try {
    const ciphertext = gcm(key, iv, additionalData).encrypt(options.payload)
    const blob = new Uint8Array(HEADER_BYTES + ciphertext.length)
    blob[0] = PAYLOAD_VERSION
    blob.set(iv, 1)
    blob.set(salt, 13)
    blob.set(ciphertext, HEADER_BYTES)
    return base64.encode(blob)
  } finally { safeZero(key) }
}

/** Authenticate the full context before returning any plaintext bytes. */
export function decryptPayload(options: DecryptPayloadOptions): Uint8Array {
  const additionalData = aad(options)
  if (options.keyMaterial.length !== 32) throw new KeytrError('PRF output must be 32 bytes')
  const blob = decodePayloadBlob(options.encryptedBlob)
  const key = hkdf(sha256, options.keyMaterial, blob.subarray(13, 45), HKDF_CONTEXT, 32)
  try {
    return gcm(key, blob.subarray(1, 13), additionalData).decrypt(blob.subarray(45))
  } catch { throw new DecryptionError('Payload decryption failed - wrong passkey or corrupted data') }
  finally { safeZero(key) }
}
