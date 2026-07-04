import { describe, it, expect } from 'vitest'
import { detectMode, extractKey } from '../../src/webauthn/kih.js'
import { KIH_MODE_BYTE, KIH_USER_ID_SIZE, KIH_KEY_SIZE, PRF_USER_ID_SIZE } from '../../src/types.js'
import { randomBytes } from '@noble/hashes/utils.js'

function makeKihHandle(): Uint8Array {
  const handle = new Uint8Array(KIH_USER_ID_SIZE)
  handle[0] = KIH_MODE_BYTE
  handle.set(randomBytes(KIH_KEY_SIZE), 1)
  return handle
}

describe('detectMode', () => {
  it('detects PRF from a 32-byte userHandle (the pubkey)', () => {
    expect(detectMode(randomBytes(PRF_USER_ID_SIZE))).toBe('prf')
  })

  it('detects legacy KiH from a 33-byte 0x03-prefixed userHandle', () => {
    expect(detectMode(makeKihHandle())).toBe('kih')
  })

  it('throws for a 33-byte handle with the wrong prefix', () => {
    const handle = new Uint8Array(KIH_USER_ID_SIZE)
    handle[0] = 0x01
    expect(() => detectMode(handle)).toThrow('Unrecognized userHandle format')
  })

  it('throws (truncation) for a handle shorter than 32 bytes', () => {
    expect(() => detectMode(randomBytes(16))).toThrow('truncated')
  })

  it('throws for an unrecognized length (e.g. 40 bytes)', () => {
    expect(() => detectMode(randomBytes(40))).toThrow('Unrecognized userHandle format')
  })
})

describe('extractKey', () => {
  it('extracts the 32-byte key from a legacy KiH userHandle', () => {
    const handle = makeKihHandle()
    const key = extractKey(handle)
    expect(key.length).toBe(KIH_KEY_SIZE)
    expect(key).toEqual(handle.slice(1))
  })

  it('throws for a wrong-size handle', () => {
    expect(() => extractKey(randomBytes(32))).toThrow('userHandle is 32 bytes')
  })

  it('throws for a wrong prefix byte', () => {
    const handle = new Uint8Array(KIH_USER_ID_SIZE)
    handle[0] = 0x01
    expect(() => extractKey(handle)).toThrow('Unrecognized userHandle format')
  })

  it('returns an independent copy (not a view)', () => {
    const handle = makeKihHandle()
    const key = extractKey(handle)
    key[0] = 0xff
    expect(handle[1]).not.toBe(0xff)
  })
})
