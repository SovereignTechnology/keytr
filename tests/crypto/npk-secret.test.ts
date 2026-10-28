import { describe, it, expect } from 'vitest'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { mnemonicToEntropy } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { getPublicKey } from 'nostr-tools/pure'
import { encodeNpkSecret, decodeNpkSecret, deriveSeedKey, npkSecretKeys, type NpkSecret } from '../../src/crypto/npk-secret.js'
import { decryptStoredSecret } from '../../src/stored.js'
import { NPK_MAX_PLAINTEXT_BYTES, encryptNpkRecord } from '../../src/crypto/npk.js'

// NIP-06 test vector
const MNEMONIC = 'leader monkey parrot ring guide accident before fence cannon height naive bean'
const NIP06_SECRET = '7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a'
const NIP06_PUBKEY = '17162c921dc4d2518f9a101db33695df1afb56ab82f5ff3e5da6eec3ca5cd917'
const entropy = bytesToHex(mnemonicToEntropy(MNEMONIC, wordlist))
const imported = '01'.repeat(32)
const importedPubkey = getPublicKey(hexToBytes(imported))

const ctx = { keyMaterial: new Uint8Array(32).fill(7), rpId: 'example.com', credentialId: new Uint8Array(16).fill(0xaa) }

/** Encrypt like setupStored does, for a given author. */
function record(secret: NpkSecret, author: string) {
  return encryptNpkRecord({ ...ctx, type: secret.type, plaintext: encodeNpkSecret(secret), author })
}

describe('seed secrets', () => {
  it("derives m/44'/1237'/0'/0/0 (NIP-06 account 0) from stored entropy", () => {
    const [main] = npkSecretKeys({ type: 'seed', seed: { entropy } })
    expect(bytesToHex(main.secretKey)).toBe(NIP06_SECRET)
    expect(main.pubkey).toBe(NIP06_PUBKEY)
  })

  it('refuses new seed-only records; writers must use a vault', () => {
    expect(() => record({ type: 'seed', seed: { entropy } }, NIP06_PUBKEY)).toThrow(/vault/)
  })

  it('changes keys with a passphrase', () => {
    expect(deriveSeedKey({ entropy, passphrase: 'x' }).pubkey).not.toBe(NIP06_PUBKEY)
  })

  it.each(['', 'ab', 'AB'.repeat(16), 'ab'.repeat(15), 'ab'.repeat(17), 'ab'.repeat(33), 'zz'.repeat(16)])('rejects entropy %j', bad => {
    expect(() => encodeNpkSecret({ type: 'seed', seed: { entropy: bad } })).toThrow()
  })
})

describe('vault secrets', () => {
  const vault = {
    seed: { entropy },
    accounts: [
      { kind: 'derived', path: "m/44'/1237'/0'/0/0", label: 'Personal' },
      { kind: 'derived', path: "m/44'/1237'/0'/0/3", default: true },
      { kind: 'xpub', value: 'from a newer client' },
      { kind: 'derived', path: "m/44'/1237'/3'/0/0" },
      { kind: 'key', secret: imported, label: 'Imported', note: 'kept' },
    ],
    ext: { 'org.example.app': { theme: 'dark' }, 'com.other': { list: [1, 2] } },
    unknownTopLevel: { keep: true },
  }
  const secret: NpkSecret = { type: 'vault', vault }

  it('lists every importable key, skipping unknown kinds and marking the default', () => {
    const keys = npkSecretKeys(secret)
    expect(keys.map(k => k.pubkey)).toEqual([
      NIP06_PUBKEY, deriveSeedKey({ entropy }, "m/44'/1237'/0'/0/3").pubkey,
      deriveSeedKey({ entropy }, "m/44'/1237'/3'/0/0").pubkey, importedPubkey,
    ])
    expect(keys[0].label).toBe('Personal')
    expect(keys.filter(k => k.default).map(k => k.path)).toEqual(["m/44'/1237'/0'/0/3"])
    // The two account layouts give different keys; the path decides, never the position.
    expect(keys[1].pubkey).not.toBe(keys[2].pubkey)
  })

  it('round trips, preserving unknown kinds, ext and unknown fields byte for byte', () => {
    const r = record(secret, importedPubkey)
    const opened = decryptStoredSecret({ ...ctx, record: r, author: importedPubkey })
    expect(opened).toEqual(secret)
    expect(encodeNpkSecret(opened)).toEqual(encodeNpkSecret(secret))
  })

  it('accepts any importable vault account as author and rejects others', () => {
    const third = deriveSeedKey({ entropy }, "m/44'/1237'/0'/0/3").pubkey
    expect(() => decryptStoredSecret({ ...ctx, record: record(secret, third), author: third })).not.toThrow()
    expect(() => decryptStoredSecret({ ...ctx, record: record(secret, 'ab'.repeat(32)), author: 'ab'.repeat(32) })).toThrow(/author/)
  })

  it('validates derivation paths', () => {
    const withPath = (path: unknown) => () => encodeNpkSecret({ type: 'vault', vault: { seed: { entropy }, accounts: [{ kind: 'derived', path: path as string }] } })
    for (const ok of ["m/44'/1237'/0'/0/0", "m/44'/1237'/7'", "m/44'/1237'/0'/0/2147483647"]) expect(withPath(ok)).not.toThrow()
    for (const bad of ["m/44'/1237'", "m/44'/0'/0'/0/0", "m/44'/1237'/0h/0/0", "m/44'/1237'/2147483648", "m/44'/1237'/01'", "m/44'/1237'/0'/", 'x', 7]) {
      expect(npkSecretKeys({ type: 'vault', vault: { seed: { entropy }, accounts: [{kind:'derived',path:bad as string}] } })).toEqual([])
    }
  })

  it('rejects an empty vault but preserves unusable account metadata', () => {
    expect(() => encodeNpkSecret({ type: 'vault', vault: { accounts: [] } })).toThrow()
    const value: NpkSecret = { type: 'vault', vault: { accounts: [
      { kind: 'derived', path: "m/44'/1237'/0'/0/0" },
      { kind: 'key', secret: '00'.repeat(32) },
      { kind: 'future', value: 7 }
    ] } }
    expect(npkSecretKeys(value)).toEqual([])
    expect(JSON.parse(new TextDecoder().decode(encodeNpkSecret(value)))).toEqual(value.vault)
  })

})

describe('author checks and limits', () => {
  it('rejects a record opened under another author, before or after decrypting', () => {
    const secret: NpkSecret = { type: 'key', secretKey: hexToBytes(imported) }
    // The AAD binds the author, so claiming another one fails decryption.
    expect(() => decryptStoredSecret({ ...ctx, record: record(secret, importedPubkey), author: NIP06_PUBKEY })).toThrow(/decryption failed/)
    // A buggy writer that bound the wrong author is caught after decryption.
    expect(() => decryptStoredSecret({ ...ctx, record: record(secret, NIP06_PUBKEY), author: NIP06_PUBKEY })).toThrow(/author/)
  })

  it('rejects secrets over 64 KiB before encrypting', () => {
    const big: NpkSecret = { type: 'vault', vault: { accounts: [{ kind: 'key', secret: imported }], ext: { 'org.example': { pad: 'x'.repeat(NPK_MAX_PLAINTEXT_BYTES) } } } }
    expect(() => encodeNpkSecret(big)).toThrow(/exceeds/)
  })

  it('rejects invalid plaintext on decode', () => {
    expect(() => decodeNpkSecret('seed', new TextEncoder().encode('not json'))).toThrow(/JSON/)
    expect(() => decodeNpkSecret('vault', new Uint8Array([0xff]))).toThrow(/UTF-8/)
    expect(() => decodeNpkSecret('key', new Uint8Array(32))).toThrow()
  })
})
