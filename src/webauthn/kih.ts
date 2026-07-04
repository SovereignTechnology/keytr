import {
  KIH_MODE_BYTE,
  KIH_KEY_SIZE,
  KIH_USER_ID_SIZE,
  PRF_USER_ID_SIZE,
  type KeytrMode,
} from '../types.js'
import { KeytrError } from '../errors.js'
import { safeSlice } from '../crypto/builtins.js'

/**
 * Legacy Key-in-Handle (KiH) helpers — decrypt/login only.
 *
 * KiH registration was removed in v0.8.0 (the encryption key stored in
 * user.id is interceptable in JS memory). These helpers remain so existing
 * KiH credentials can still be recognized and decrypted during login and
 * migration (see migrateFromKih). They will be removed when KiH decryption
 * is dropped in a future release.
 */

/**
 * Detect whether a userHandle represents a PRF or legacy KiH credential.
 * - 32 bytes → PRF (userHandle is the raw pubkey)
 * - 33 bytes with byte[0] === 0x03 → KiH (userHandle is [0x03 || key])
 */
export function detectMode(userHandle: Uint8Array): KeytrMode {
  if (userHandle.length === KIH_USER_ID_SIZE && userHandle[0] === KIH_MODE_BYTE) {
    return 'kih'
  }
  if (userHandle.length === PRF_USER_ID_SIZE) {
    return 'prf'
  }

  // Truncation detection: if shorter than expected, the authenticator likely truncated user.id
  if (userHandle.length < PRF_USER_ID_SIZE) {
    throw new KeytrError(
      `userHandle is ${userHandle.length} bytes, expected ${PRF_USER_ID_SIZE} (PRF) or ${KIH_USER_ID_SIZE} (KiH). ` +
      `The authenticator may have truncated user.id — this passkey cannot be used for decryption.`
    )
  }

  throw new KeytrError(
    `Unrecognized userHandle format: ${userHandle.length} bytes` +
    (userHandle.length === KIH_USER_ID_SIZE
      ? `, byte[0]=0x${userHandle[0].toString(16).padStart(2, '0')} (expected 0x${KIH_MODE_BYTE.toString(16).padStart(2, '0')})`
      : `. Expected ${PRF_USER_ID_SIZE} (PRF) or ${KIH_USER_ID_SIZE} (KiH).`)
  )
}

/**
 * Extract the 32-byte encryption key from a legacy KiH userHandle.
 * Validates the expected format: 33 bytes with 0x03 prefix.
 * Caller should verify detectMode() === 'kih' first.
 */
export function extractKey(userHandle: Uint8Array): Uint8Array {
  if (userHandle.length < KIH_USER_ID_SIZE) {
    throw new KeytrError(
      `userHandle is ${userHandle.length} bytes, expected ${KIH_USER_ID_SIZE}. ` +
      `The authenticator may have truncated user.id — the encryption key is incomplete.`
    )
  }
  if (userHandle.length !== KIH_USER_ID_SIZE || userHandle[0] !== KIH_MODE_BYTE) {
    throw new KeytrError(
      `Unrecognized userHandle format: ${userHandle.length} bytes, ` +
      `byte[0]=0x${userHandle[0].toString(16).padStart(2, '0')} (expected 0x${KIH_MODE_BYTE.toString(16).padStart(2, '0')})`
    )
  }
  return safeSlice(userHandle, 1, 1 + KIH_KEY_SIZE)
}
