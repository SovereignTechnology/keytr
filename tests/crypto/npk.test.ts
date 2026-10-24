import { describe, it, expect } from 'vitest'
import { hexToBytes, bytesToHex } from '@noble/hashes/utils.js'
import { base64 } from '@scure/base'
import vectors from '../fixtures/passkey-key-mode-vectors.json'
import {
  NPK_STORE_PRF_INPUT, NPK_TYPES, NPK_MAX_PLAINTEXT_BYTES,
  buildNpkAad, deriveNpkKey, encryptNpkRecord, encryptNpkRecordWith, decryptNpkRecord, npkRecordType,
} from '../../src/crypto/npk.js'
import { encryptNsec } from '../../src/crypto/encrypt.js'
import { decryptNsec } from '../../src/crypto/decrypt.js'
import { decryptPayload } from '../../src/crypto/payload.js'
import { PRF_SALT } from '../../src/types.js'

const v = vectors.stored.records[0]
const prf = hexToBytes(v.prf_output)
const context = { type: 'key' as const, rpId: v.rp_id, author: v.author, credentialId: hexToBytes(v.credential_id) }
const { type: _type, ...openContext } = context

describe('npk1 stored record vector', () => {
  it('uses SHA-256("nostr-passkey:store:v1") as the PRF input and the spec type bytes', () => {
    expect(bytesToHex(NPK_STORE_PRF_INPUT)).toBe(vectors.stored.prf_input)
    expect(Object.fromEntries(NPK_TYPES.map((name, i) => [name, i + 1]))).toEqual(vectors.stored.payload_types)
    expect(bytesToHex(NPK_STORE_PRF_INPUT)).not.toBe(bytesToHex(PRF_SALT))
  })

  it('derives the AES key and AAD', () => {
    expect(bytesToHex(deriveNpkKey(prf, hexToBytes(v.hkdf_salt)))).toBe(v.aes_key)
    expect(bytesToHex(buildNpkAad(context))).toBe(v.aad)
  })

  it('reproduces the record exactly with the fixed salt and IV', () => {
    const record = encryptNpkRecordWith({ ...context, plaintext: hexToBytes(v.plaintext), keyMaterial: prf }, hexToBytes(v.hkdf_salt), hexToBytes(v.iv))
    expect(record.length).toBe(v.record_length)
    expect(bytesToHex(record)).toBe(v.record)
    expect(base64.encode(record)).toBe(v.record_base64)
  })

  it('decrypts the vector record back', () => {
    const { type, plaintext } = decryptNpkRecord({ ...openContext, record: hexToBytes(v.record), keyMaterial: prf })
    expect(type).toBe('key')
    expect(bytesToHex(plaintext)).toBe(v.plaintext)
  })
})

describe('npk1 AAD binding', () => {
  const record = hexToBytes(v.record)
  const base = { ...openContext, record, keyMaterial: prf }

  it.each([
    ['rp', { rpId: 'example.org' }],
    ['author', { author: 'ab'.repeat(32) }],
    ['credential', { credentialId: new Uint8Array(16).fill(0xab) }],
    ['PRF output', { keyMaterial: new Uint8Array(32).fill(8) }],
  ])('rejects a changed %s', (_name, change) => {
    expect(() => decryptNpkRecord({ ...base, ...change })).toThrow(/decryption failed/)
  })

  it('rejects a changed or unknown type byte', () => {
    const asSeed = record.slice(); asSeed[4] = 0x02
    expect(() => decryptNpkRecord({ ...base, record: asSeed })).toThrow(/decryption failed/)
    const unknown = record.slice(); unknown[4] = 0x04
    expect(() => npkRecordType(unknown)).toThrow(/Not a supported/)
  })

  it('rejects corrupted ciphertext, wrong prefix, wrong version and short records', () => {
    const flipped = record.slice(); flipped[flipped.length - 1] ^= 1
    expect(() => decryptNpkRecord({ ...base, record: flipped })).toThrow()
    const prefix = record.slice(); prefix[0] = 0x4f
    expect(() => npkRecordType(prefix)).toThrow()
    const version = record.slice(); version[3] = 0x02
    expect(() => npkRecordType(version)).toThrow()
    expect(() => npkRecordType(record.subarray(0, 65))).toThrow()
  })
})

describe('npk1 limits and separation from keytr formats', () => {
  const vault = { ...context, type: 'vault' as const, keyMaterial: prf }

  it('accepts 65,536 bytes of plaintext and rejects 65,537', () => {
    const record = encryptNpkRecord({ ...vault, plaintext: new Uint8Array(NPK_MAX_PLAINTEXT_BYTES).fill(0x20) })
    expect(decryptNpkRecord({ ...openContext, record, keyMaterial: prf }).plaintext.length).toBe(NPK_MAX_PLAINTEXT_BYTES)
    expect(() => encryptNpkRecord({ ...vault, plaintext: new Uint8Array(NPK_MAX_PLAINTEXT_BYTES + 1) })).toThrow(/65536/)
    const oversized = new Uint8Array(record.length + 1); oversized.set(record)
    expect(() => npkRecordType(oversized)).toThrow()
  })

  it('requires exactly 32 bytes for a key record', () => {
    expect(() => encryptNpkRecord({ ...context, keyMaterial: prf, plaintext: new Uint8Array(33) })).toThrow(/32 bytes/)
    expect(() => encryptNpkRecord({ ...context, keyMaterial: prf, plaintext: new Uint8Array() })).toThrow()
  })

  it('uses fresh salt and IV', () => {
    const a = encryptNpkRecord({ ...context, keyMaterial: prf, plaintext: hexToBytes(v.plaintext) })
    const b = encryptNpkRecord({ ...context, keyMaterial: prf, plaintext: hexToBytes(v.plaintext) })
    expect(bytesToHex(a)).not.toBe(bytesToHex(b))
  })

  it('never opens as a v1 nsec blob or a v4 payload, and v1 blobs never open as npk1', () => {
    const record = base64.encode(hexToBytes(v.record))
    expect(() => decryptNsec({ encryptedBlob: record, keyMaterial: prf, credentialId: context.credentialId })).toThrow()
    expect(() => decryptPayload({ encryptedBlob: record, keyMaterial: prf, credentialId: context.credentialId, pubkey: v.author, rpId: v.rp_id, payloadType: 'vault', schema: 'x.y' })).toThrow()
    const v1 = encryptNsec({ nsecBytes: hexToBytes(v.plaintext), keyMaterial: prf, credentialId: context.credentialId })
    expect(decryptNsec({ encryptedBlob: v1, keyMaterial: prf, credentialId: context.credentialId })).toEqual(hexToBytes(v.plaintext))
    expect(() => decryptNpkRecord({ ...openContext, record: base64.decode(v1), keyMaterial: prf })).toThrow()
  })

  it('validates context fields', () => {
    expect(() => buildNpkAad({ ...context, author: 'AB'.repeat(32) })).toThrow()
    expect(() => buildNpkAad({ ...context, rpId: '' })).toThrow()
    expect(() => buildNpkAad({ ...context, rpId: 'a'.repeat(256) })).toThrow()
    expect(() => buildNpkAad({ ...context, credentialId: new Uint8Array() })).toThrow()
    expect(() => buildNpkAad({ ...context, type: 'nsec' as any })).toThrow(/Unknown stored record type/)
  })
})
