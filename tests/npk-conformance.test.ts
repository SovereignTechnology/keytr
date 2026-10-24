import { vi } from 'vitest'
import { HDKey } from '@scure/bip32'
import { describe, it, expect } from 'vitest'
import { hexToBytes } from '@noble/hashes/utils.js'
import { decodeNpkSecret, encodeNpkSecret, npkSecretKeys } from '../src/crypto/npk-secret.js'
import { decryptStoredSecret } from '../src/stored.js'
import { encryptNpkRecord } from '../src/crypto/npk.js'
import { buildNpkEvent, verifyNpkEvent } from '../src/nostr/npk.js'
import vectors from './passkey-conformance-vectors.json'

describe('companion vault conformance', () => {
  for (const vector of vectors.stored.vault_plaintexts) {
    it(vector.description, () => {
      const bytes = 'hex' in vector ? hexToBytes(vector.hex!) : new TextEncoder().encode(vector.text!)
      if (vector.expect === 'invalid') {
        expect(() => decodeNpkSecret('vault', bytes)).toThrow()
      } else {
        const secret = decodeNpkSecret('vault', bytes)
        const keys = npkSecretKeys(secret)
        expect(keys).toHaveLength(vector.expect.usable.length)
        keys.forEach(k => k.secretKey.fill(0))
      }
    })
  }
  for (const vector of vectors.stored.records) {
    it(`opens authenticated ${vector.description} vector`, () => {
      const secret = decryptStoredSecret({ record: hexToBytes(vector.record), keyMaterial: hexToBytes(vector.prf_output), rpId: vector.rp_id, author: vector.author, credentialId: hexToBytes(vector.credential_id) })
      expect(npkSecretKeys(secret).map(k => k.pubkey)).toContain(vector.author)
    })
  }
  it('writes the isolated new kind without version tag', () => {
    const v = vectors.stored.records[0]
    const event = buildNpkEvent({ record: hexToBytes(v.record), credentialId: hexToBytes(v.credential_id), rpId: v.rp_id })
    expect(event.kind).toBe(31778)
    expect(event.tags.some(t => t[0] === 'v')).toBe(false)
  })
})

it('reads the independently signed new-kind vector', () => {
  const v = vectors.stored.records[0]
  expect(verifyNpkEvent(vectors.relay.signed_event.event, { author: v.author, rpId: v.rp_id, credentialId: hexToBytes(v.credential_id) }).record).toEqual(hexToBytes(v.record))
})

it('refuses reserved type02 writes', () => {
  const v = vectors.stored.records[0]
  expect(() => encryptNpkRecord({ type:'seed', plaintext: new TextEncoder().encode('{}'), keyMaterial:hexToBytes(v.prf_output), rpId:v.rp_id, author:v.author, credentialId:hexToBytes(v.credential_id) })).toThrow(/vault/)
})

it('skips a derived account when BIP32 retries a different index', () => {
  const vault = {seed:{entropy:'00'.repeat(16)},accounts:[{kind:'derived',path:"m/44'/1237'/0'/0/0"},{kind:'key',secret:'01'.repeat(32)}]}
  const original = HDKey.prototype.deriveChild
  const spy = vi.spyOn(HDKey.prototype, 'deriveChild').mockImplementationOnce(function (this: HDKey, index: number) { return original.call(this, index + 1) })
  try {
    const secret = decodeNpkSecret('vault', new TextEncoder().encode(JSON.stringify(vault)))
    expect(npkSecretKeys(secret)).toHaveLength(1)
  } finally { spy.mockRestore() }
})

it('rejects an unreadable JSON string before encoding a vault for registration', () => {
  expect(() => encodeNpkSecret({type:'vault',vault:{accounts:[{kind:'key',secret:'01'.repeat(32),label:'\ud800'}]}})).toThrow()
})
