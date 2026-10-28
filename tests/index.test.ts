import { describe, it, expect, vi, afterEach } from 'vitest'
import { randomBytes } from '@noble/hashes/utils.js'
import { base64url } from '@scure/base'
import type { KeytrCredential, KeyStrategy } from '../src/types.js'
import { KEYTR_VERSION, KEYTR_KIH_VERSION, KIH_MODE_BYTE, KIH_USER_ID_SIZE } from '../src/types.js'

vi.mock('../src/webauthn/natives.js', () => ({
  nativeCreate: undefined,
  nativeGet: undefined,
}))

const originalNavigator = globalThis.navigator
const originalWindow = (globalThis as any).window
const originalPKC = (globalThis as any).PublicKeyCredential

function fakeCredential(credentialId = randomBytes(16)): KeytrCredential {
  return {
    credentialId,
    credentialIdBase64url: base64url.encode(credentialId),
    rpId: 'keytr.org',
    transports: [] as AuthenticatorTransport[],
  }
}

function setNavigator(get?: ReturnType<typeof vi.fn>, create?: ReturnType<typeof vi.fn>) {
  Object.defineProperty(globalThis, 'navigator', {
    value: { credentials: { create: create ?? vi.fn(), get: get ?? vi.fn() } },
    configurable: true,
  })
  if (!globalThis.crypto?.getRandomValues) {
    Object.defineProperty(globalThis, 'crypto', {
      value: { getRandomValues: (a: Uint8Array) => { a.set(randomBytes(a.length)); return a } },
      configurable: true,
    })
  }
}

function restore() {
  Object.defineProperty(globalThis, 'navigator', { value: originalNavigator, configurable: true })
  Object.defineProperty(globalThis, 'window', { value: originalWindow, configurable: true })
  Object.defineProperty(globalThis, 'PublicKeyCredential', { value: originalPKC, configurable: true })
}

describe('high-level wiring', () => {
  afterEach(() => { restore(); vi.restoreAllMocks() })

  it('skips unsupported event kinds and versions before parsing credentials', async () => {
    const { loginWithKeytr } = await import('../src/index.js')
    await expect(loginWithKeytr([
      { kind: 31778, content: '', tags: [['d', 'bad:vault']] },
      { kind: 31777, content: '', tags: [['v', '999'], ['d', 'bad:vault']] }
    ])).rejects.toThrow('No matching passkey found')
  })

  it('setup() threads the derived pubkey into strategy.register', async () => {
    let capturedPubkey: string | undefined
    const stub: KeyStrategy = {
      version: KEYTR_VERSION,
      register: vi.fn(async (opts) => {
        capturedPubkey = opts.pubkey
        return { credential: fakeCredential(), keyMaterial: randomBytes(32) }
      }),
      authenticate: vi.fn(),
      discover: vi.fn(),
    }

    const { setup, nsecToHexPubkey } = await import('../src/index.js')
    const res = await setup({ userName: 'a', userDisplayName: 'A', strategy: stub })

    expect(stub.register).toHaveBeenCalledOnce()
    expect(capturedPubkey).toBe(nsecToHexPubkey(res.nsecBytes))
  })

  it('kihStrategy.register() throws KihRegistrationDisabledError', async () => {
    const { kihStrategy, setup } = await import('../src/index.js')
    const { KihRegistrationDisabledError } = await import('../src/errors.js')

    await expect(
      kihStrategy.register({ userName: 'a', userDisplayName: 'A', pubkey: 'ab'.repeat(32) })
    ).rejects.toBeInstanceOf(KihRegistrationDisabledError)

    await expect(
      setup({ userName: 'a', userDisplayName: 'A', strategy: kihStrategy })
    ).rejects.toBeInstanceOf(KihRegistrationDisabledError)
  })

  it('setup() throws PrfNotSupportedError when the browser reports no PRF', async () => {
    setNavigator()
    // support.ts reads window.PublicKeyCredential AND the global PublicKeyCredential
    const PKC = {
      isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
      getClientCapabilities: async () => ({ 'extensions.prf': false }),
    }
    Object.defineProperty(globalThis, 'PublicKeyCredential', { value: PKC, configurable: true })
    Object.defineProperty(globalThis, 'window', { value: { PublicKeyCredential: PKC }, configurable: true })

    const { setup } = await import('../src/index.js')
    const { PrfNotSupportedError } = await import('../src/errors.js')
    await expect(setup({ userName: 'a', userDisplayName: 'A' })).rejects.toBeInstanceOf(PrfNotSupportedError)
  })

  it('loginWithKeytr decrypts a legacy KiH (v=3) event via the KiH path', async () => {
    const { generateNsec, encryptNsec, buildKeytrEvent, loginWithKeytr } = await import('../src/index.js')

    const nsec = generateNsec()
    const kihKey = randomBytes(32)
    const credentialId = randomBytes(16)
    const blob = encryptNsec({ nsecBytes: nsec, keyMaterial: kihKey, credentialId, version: KEYTR_KIH_VERSION })
    const event = buildKeytrEvent({ credential: fakeCredential(credentialId), encryptedBlob: blob, version: KEYTR_KIH_VERSION })

    const handle = new Uint8Array(KIH_USER_ID_SIZE)
    handle[0] = KIH_MODE_BYTE
    handle.set(kihKey, 1)
    const get = vi.fn().mockResolvedValue({
      type: 'public-key',
      rawId: credentialId.buffer.slice(0),
      response: { userHandle: handle.buffer.slice(0) },
      getClientExtensionResults: () => ({}),
    })
    setNavigator(get)

    const result = await loginWithKeytr([event])
    expect(result.nsecBytes).toEqual(nsec)
    // KiH path: no PRF extension requested
    expect((get.mock.calls[0][0] as CredentialRequestOptions).publicKey as any).not.toHaveProperty('extensions')
  })

  it('loginWithKeytr decrypts a PRF (v=1) event via the PRF path', async () => {
    const { generateNsec, encryptNsec, buildKeytrEvent, loginWithKeytr } = await import('../src/index.js')

    const nsec = generateNsec()
    const prfKey = randomBytes(32)
    const credentialId = randomBytes(16)
    const blob = encryptNsec({ nsecBytes: nsec, keyMaterial: prfKey, credentialId, version: KEYTR_VERSION })
    const event = buildKeytrEvent({ credential: fakeCredential(credentialId), encryptedBlob: blob, version: KEYTR_VERSION })

    const get = vi.fn().mockResolvedValue({
      type: 'public-key',
      rawId: credentialId.buffer.slice(0),
      response: {},
      getClientExtensionResults: () => ({ prf: { results: { first: prfKey.buffer.slice(0) } } }),
    })
    setNavigator(get)

    const result = await loginWithKeytr([event])
    expect(result.nsecBytes).toEqual(nsec)
    // PRF path: PRF extension requested
    expect((get.mock.calls[0][0] as CredentialRequestOptions).publicKey as any).toHaveProperty('extensions')
  })

  it('loginWithKeytr rejects an unsupported event version', async () => {
    const { buildKeytrEvent, loginWithKeytr } = await import('../src/index.js')
    const credentialId = randomBytes(16)
    const event = buildKeytrEvent({ credential: fakeCredential(credentialId), encryptedBlob: 'AAAA', version: 99 })
    setNavigator()
    await expect(loginWithKeytr([event])).rejects.toThrow('Unsupported keytr event version 99')
  })
})
