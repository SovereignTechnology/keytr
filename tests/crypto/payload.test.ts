import { describe, it, expect } from 'vitest'
import { base64 } from '@scure/base'
import { gcm } from '@noble/ciphers/aes.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { encryptPayload, decryptPayload, MAX_PAYLOAD_BYTES } from '../../src/crypto/payload.js'
import { decryptNsec } from '../../src/crypto/decrypt.js'

const keyMaterial = new Uint8Array(32).fill(7)
const context = { credentialId: new Uint8Array([1, 2, 3]), pubkey: 'ab'.repeat(32), rpId: 'example.com', payloadType: 'vault' as const, schema: 'org.example.vault.v1' }
const bytes = new TextEncoder().encode('{"accounts":["first","second"]}')

describe('typed PRF payloads', () => {
  it.each(['seed', 'vault'] as const)('round trips %s without changing caller buffers', payloadType => {
    const options = { ...context, payloadType, keyMaterial }
    const encryptedBlob = encryptPayload({ ...options, payload: bytes })
    expect(decryptPayload({ ...options, encryptedBlob })).toEqual(bytes)
    expect(keyMaterial).toEqual(new Uint8Array(32).fill(7))
    expect(() => decryptNsec({ keyMaterial, credentialId: context.credentialId, encryptedBlob })).toThrow()
  })
  it('uses the documented layout, HKDF context and AAD', () => {
    const encryptedBlob = encryptPayload({ ...context, keyMaterial, payload: bytes })
    const blob = base64.decode(encryptedBlob)
    expect(blob[0]).toBe(4)
    expect(blob.length).toBe(45 + bytes.length + 16)
    const key = hkdf(sha256, keyMaterial, blob.slice(13, 45), new TextEncoder().encode('keytr payload encryption v4'), 32)
    const aad = new TextEncoder().encode(JSON.stringify(['keytr', 4, 'vault', context.schema, context.rpId, context.pubkey, 'AQID']))
    expect(gcm(key, blob.slice(1, 13), aad).decrypt(blob.slice(45))).toEqual(bytes)
  })
  it('authenticates type, schema, RP, author and credential', () => {
    const encryptedBlob = encryptPayload({ ...context, keyMaterial, payload: bytes })
    for (const change of [{ payloadType: 'seed' }, { schema: 'org.example.vault.v2' }, { rpId: 'other.example.com' }, { pubkey: 'cd'.repeat(32) }, { credentialId: new Uint8Array([4]) }, { keyMaterial: new Uint8Array(32) }]) {
      expect(() => decryptPayload({ ...context, keyMaterial, encryptedBlob, ...change } as any)).toThrow()
    }
  })
  it('rejects corrupted and unknown-version ciphertext', () => {
    const blob = base64.decode(encryptPayload({ ...context, keyMaterial, payload: bytes }))
    blob[blob.length - 1] ^= 1
    expect(() => decryptPayload({ ...context, keyMaterial, encryptedBlob: base64.encode(blob) })).toThrow()
    blob[0] = 3
    expect(() => decryptPayload({ ...context, keyMaterial, encryptedBlob: base64.encode(blob) })).toThrow()
  })
  it('bounds payloads, base64, credentials and schema before crypto', () => {
    for (const payload of [new Uint8Array(), new Uint8Array(MAX_PAYLOAD_BYTES + 1)]) expect(() => encryptPayload({ ...context, keyMaterial, payload })).toThrow()
    for (const encryptedBlob of ['', '!', 'A'.repeat(4 * Math.ceil((MAX_PAYLOAD_BYTES + 61) / 3) + 4)]) expect(() => decryptPayload({ ...context, keyMaterial, encryptedBlob })).toThrow()
    for (const change of [{ credentialId: new Uint8Array() }, { schema: '' }, { schema: 'x'.repeat(129) }, { rpId: 'https://example.com' }, { pubkey: 'invalid' }, { payloadType: 'nsec' }]) expect(() => encryptPayload({ ...context, keyMaterial, payload: bytes, ...change } as any)).toThrow()
  })
  it('uses fresh randomness and accepts the maximum payload', () => {
    const options = { ...context, keyMaterial, payload: new Uint8Array(MAX_PAYLOAD_BYTES) }
    const first = encryptPayload(options)
    expect(encryptPayload(options)).not.toBe(first)
    expect(decryptPayload({ ...options, encryptedBlob: first }).length).toBe(MAX_PAYLOAD_BYTES)
  })
})
