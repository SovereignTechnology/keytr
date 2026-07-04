import { describe, it, expect } from 'vitest'
import { encryptNsec, buildAad } from '../../src/crypto/encrypt.js'
import { decryptNsec } from '../../src/crypto/decrypt.js'
import { randomBytes } from '@noble/hashes/utils.js'
import { KEYTR_VERSION } from '../../src/types.js'

describe('buildAad', () => {
  it('uses KEYTR_VERSION (1, PRF) by default', () => {
    const credId = new Uint8Array([0xaa, 0xbb])
    const aad = buildAad(credId)
    // 'keytr' (5) + version (1) + credId (2) = 8 bytes
    expect(aad.length).toBe(8)
    expect(aad[5]).toBe(KEYTR_VERSION) // default PRF version byte = 1
    expect(KEYTR_VERSION).toBe(1)
  })

  it('accepts a custom version (e.g. 3 for legacy KiH)', () => {
    const credId = new Uint8Array([0xaa, 0xbb])
    const aad = buildAad(credId, 3)
    expect(aad.length).toBe(8)
    expect(aad[5]).toBe(3)
  })

  it('produces different AAD for PRF (1) vs KiH (3) — cross-mode isolation', () => {
    const credId = new Uint8Array([0xaa, 0xbb])
    expect(buildAad(credId, 1)).not.toEqual(buildAad(credId, 3))
  })
})

describe('encryption roundtrip', () => {
  it('encrypts and decrypts correctly', () => {
    const nsecBytes = randomBytes(32)
    const keyMaterial = randomBytes(32)
    const credentialId = randomBytes(16)

    const blob = encryptNsec({ nsecBytes, keyMaterial, credentialId })

    const decrypted = decryptNsec({
      encryptedBlob: blob,
      keyMaterial,
      credentialId,
    })

    expect(decrypted).toEqual(nsecBytes)
  })

  it('fails with wrong key material', () => {
    const nsecBytes = randomBytes(32)
    const keyMaterial = randomBytes(32)
    const credentialId = randomBytes(16)

    const blob = encryptNsec({ nsecBytes, keyMaterial, credentialId })

    const wrongKey = randomBytes(32)
    expect(() => decryptNsec({
      encryptedBlob: blob,
      keyMaterial: wrongKey,
      credentialId,
    })).toThrow()
  })

  it('fails with wrong credential ID (AAD mismatch)', () => {
    const nsecBytes = randomBytes(32)
    const keyMaterial = randomBytes(32)
    const credentialId = randomBytes(16)

    const blob = encryptNsec({ nsecBytes, keyMaterial, credentialId })

    const wrongCred = randomBytes(16)
    expect(() => decryptNsec({
      encryptedBlob: blob,
      keyMaterial,
      credentialId: wrongCred,
    })).toThrow()
  })
})
