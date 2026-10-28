import { describe, it, expect } from 'vitest'
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js'
import vectors from '../fixtures/passkey-key-mode-vectors.json'
import { classifyHandle, buildStoredHandle } from '../../src/webauthn/handle.js'
import { detectMode } from '../../src/webauthn/kih.js'
import { PasskeyModeError, KeytrError } from '../../src/errors.js'

describe('classifyHandle (spec vectors)', () => {
  it.each(vectors.handles)('$description', ({ handle, expect: want }) => {
    const got = classifyHandle(handle === null ? null : hexToBytes(handle))
    expect(got.mode).toBe(want.mode)
    if ('parameter_set' in want) expect(got).toMatchObject({ parameterSet: want.parameter_set })
    if ('author' in want) expect(got).toMatchObject({ author: want.author })
    if ('legacy' in want) expect(got).toMatchObject({ legacy: want.legacy })
    // confirm_record marks the only classification that still needs a record: the 32-byte handle.
    if ('confirm_record' in want) expect(got).toMatchObject({ legacy: 'raw-pubkey' })
    if (!('legacy' in want) && got.mode === 'stored') expect('legacy' in got).toBe(false)
  })

  it('treats empty and ArrayBuffer handles consistently', () => {
    expect(classifyHandle(new Uint8Array())).toEqual({ mode: 'unknown' })
    expect(classifyHandle(undefined)).toEqual({ mode: 'unknown' })
    const stored = vectors.handles.find(h => h.description === 'tagged stored')!.handle!
    expect(classifyHandle(hexToBytes(stored).buffer as ArrayBuffer)).toMatchObject({ mode: 'stored' })
  })
})

describe('buildStoredHandle', () => {
  it('builds the 37-byte tagged stored handle', () => {
    const author = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    const handle = buildStoredHandle(author)
    expect(bytesToHex(handle)).toBe(vectors.handles.find(h => h.description === 'tagged stored')!.handle)
    expect(classifyHandle(handle)).toEqual({ mode: 'stored', author })
  })

  it('rejects malformed authors', () => {
    for (const author of ['', 'AB'.repeat(32), 'ab'.repeat(31), 'zz'.repeat(32)]) {
      expect(() => buildStoredHandle(author)).toThrow(KeytrError)
    }
  })
})

describe('detectMode keeps v1 behaviour and types tagged handles', () => {
  it('still reports 32-byte handles as PRF, including ones starting with "NPK", and 33-byte 0x03 handles as KiH', () => {
    expect(detectMode(new Uint8Array(32).fill(9))).toBe('prf')
    expect(detectMode(hexToBytes('4e504b' + '11'.repeat(29)))).toBe('prf')
    const kih = new Uint8Array(33); kih[0] = 0x03
    expect(detectMode(kih)).toBe('kih')
  })

  it.each([
    ['derived', '4e504b01010100112233445566778899aabbccddeeff', 'derived'],
    ['unsupported', '4e504b02010000000000000000000000000000000000', 'unsupported'],
    ['tagged stored', bytesToHex(buildStoredHandle('ab'.repeat(32))), 'unsupported'],
  ])('throws PasskeyModeError for a %s handle', (_name, handle, reason) => {
    const err = (() => { try { detectMode(hexToBytes(handle)) } catch (e) { return e } })()
    expect(err).toBeInstanceOf(PasskeyModeError)
    expect((err as PasskeyModeError).reason).toBe(reason)
  })

  it('keeps the existing error for other lengths', () => {
    expect(() => detectMode(new Uint8Array(16))).toThrow(/truncated/)
    expect(() => detectMode(new TextEncoder().encode('3f2b8c1e-9d4a-4e7b-b5c2-1a6f0e8d7c94'))).toThrow(/Unrecognized/)
  })
})
