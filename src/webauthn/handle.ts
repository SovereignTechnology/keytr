import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { KIH_MODE_BYTE, KIH_USER_ID_SIZE, PRF_USER_ID_SIZE } from '../types.js'
import { KeytrError } from '../errors.js'

/**
 * Tagged passkey handles from the passkey-held Nostr keys proposal:
 *
 *   "NPK" || 0x01 || 0x01 || parameter set (1) || random (16)   derived, 22 bytes
 *   "NPK" || 0x01 || 0x02 || author public key (32)             stored, 37 bytes
 */
export type HandleClassification =
  | { mode: 'derived'; parameterSet: number }
  /** `legacy: 'raw-pubkey'` (32 bytes) is only probably stored: confirm it with a record. */
  | { mode: 'stored'; author: string; legacy?: 'raw-pubkey' }
  /** Withdrawn keytr v3 key-in-handle, read-only for migration. */
  | { mode: 'stored'; legacy: 'key-in-handle' }
  | { mode: 'unsupported' }
  | { mode: 'unknown' }

/** Classify a WebAuthn userHandle in the order the proposal requires. Never throws. */
export function classifyHandle(userHandle: Uint8Array | ArrayBuffer | null | undefined): HandleClassification {
  if (!userHandle || userHandle.byteLength === 0) return { mode: 'unknown' }
  const h = userHandle instanceof Uint8Array ? userHandle : new Uint8Array(userHandle)

  // 32 and 33 bytes come first: a public key may start with "NPK", and tagged handles never have these lengths.
  if (h.length === PRF_USER_ID_SIZE) return { mode: 'stored', author: bytesToHex(h), legacy: 'raw-pubkey' }
  if (h.length === KIH_USER_ID_SIZE && h[0] === KIH_MODE_BYTE) return { mode: 'stored', legacy: 'key-in-handle' }
  if (h.length >= 3 && h[0] === 0x4e && h[1] === 0x50 && h[2] === 0x4b) {
    if (h[3] === 0x01 && h[4] === 0x01 && h.length === 22) return { mode: 'derived', parameterSet: h[5] }
    if (h[3] === 0x01 && h[4] === 0x02 && h.length === 37) return { mode: 'stored', author: bytesToHex(h.subarray(5)) }
    return { mode: 'unsupported' }
  }
  return { mode: 'unknown' }
}

/** The 37-byte tagged stored handle for an author public key (64 lowercase hex chars). */
export function buildStoredHandle(author: string): Uint8Array {
  if (typeof author !== 'string' || !/^[0-9a-f]{64}$/.test(author)) {
    throw new KeytrError('Stored handle author must be a lowercase 32-byte hex public key')
  }
  return new Uint8Array([0x4e, 0x50, 0x4b, 0x01, 0x02, ...hexToBytes(author)])
}
