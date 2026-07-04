import { describe, it, expect, vi, afterEach } from 'vitest'
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js'
import { KIH_MODE_BYTE, KIH_USER_ID_SIZE } from '../../src/types.js'

vi.mock('../../src/webauthn/natives.js', () => ({
  nativeCreate: undefined,
  nativeGet: undefined,
}))

const originalNavigator = globalThis.navigator

function setupGet(get: ReturnType<typeof vi.fn>) {
  Object.defineProperty(globalThis, 'navigator', {
    value: { credentials: { create: vi.fn(), get } },
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
}

function kihHandle(): Uint8Array {
  const h = new Uint8Array(KIH_USER_ID_SIZE)
  h[0] = KIH_MODE_BYTE
  h.set(randomBytes(32), 1)
  return h
}

describe('discoverPasskey (unified)', () => {
  afterEach(() => { restore(); vi.restoreAllMocks() })

  it('PRF: two ceremonies, recovers pubkey + PRF keyMaterial', async () => {
    const pubkeyBytes = randomBytes(32)
    const rawId = randomBytes(16)
    const prfOutput = randomBytes(32)

    const get = vi.fn()
      .mockResolvedValueOnce({ // step 1: discovery
        type: 'public-key',
        rawId: rawId.buffer.slice(0),
        response: { userHandle: pubkeyBytes.buffer.slice(0) },
        getClientExtensionResults: () => ({}),
      })
      .mockResolvedValueOnce({ // step 2: targeted PRF
        type: 'public-key',
        rawId: rawId.buffer.slice(0),
        response: {},
        getClientExtensionResults: () => ({ prf: { results: { first: prfOutput.buffer.slice(0) } } }),
      })
    setupGet(get)

    const { discoverPasskey } = await import('../../src/webauthn/authenticate.js')
    const result = await discoverPasskey()

    expect(get).toHaveBeenCalledTimes(2)
    // step 1: empty allowCredentials, no prf
    const step1 = get.mock.calls[0][0] as CredentialRequestOptions
    expect(step1.publicKey?.allowCredentials).toEqual([])
    expect((step1.publicKey as any)?.extensions?.prf).toBeUndefined()
    // step 2: targeted + prf
    const step2 = get.mock.calls[1][0] as CredentialRequestOptions
    expect(step2.publicKey?.allowCredentials?.length).toBe(1)
    expect((step2.publicKey as any)?.extensions?.prf).toBeDefined()

    expect(result.mode).toBe('prf')
    expect(result.pubkey).toBe(bytesToHex(pubkeyBytes))
    expect(result.keyMaterial).toEqual(prfOutput)
    expect(result.credentialId).toEqual(rawId)
  })

  it('KiH: single ceremony, extracts key from userHandle, no pubkey', async () => {
    const handle = kihHandle()
    const rawId = randomBytes(16)
    const get = vi.fn().mockResolvedValue({
      type: 'public-key',
      rawId: rawId.buffer.slice(0),
      response: { userHandle: handle.buffer.slice(0) },
      getClientExtensionResults: () => ({}),
    })
    setupGet(get)

    const { discoverPasskey } = await import('../../src/webauthn/authenticate.js')
    const result = await discoverPasskey()

    expect(get).toHaveBeenCalledOnce()
    expect(result.mode).toBe('kih')
    expect(result.pubkey).toBeUndefined()
    expect(result.keyMaterial).toEqual(handle.slice(1))
    expect(result.credentialId).toEqual(rawId)
  })

  it('passes mediation on the discovery (step 1) ceremony', async () => {
    const get = vi.fn().mockResolvedValue({
      type: 'public-key',
      rawId: randomBytes(16).buffer.slice(0),
      response: { userHandle: kihHandle().buffer.slice(0) },
      getClientExtensionResults: () => ({}),
    })
    setupGet(get)

    const { discoverPasskey } = await import('../../src/webauthn/authenticate.js')
    await discoverPasskey({ mediation: 'conditional' })

    expect((get.mock.calls[0][0] as CredentialRequestOptions).mediation).toBe('conditional')
  })

  it('throws when the userHandle is empty', async () => {
    const get = vi.fn().mockResolvedValue({
      type: 'public-key',
      rawId: randomBytes(16).buffer.slice(0),
      response: { userHandle: new ArrayBuffer(0) },
      getClientExtensionResults: () => ({}),
    })
    setupGet(get)

    const { discoverPasskey } = await import('../../src/webauthn/authenticate.js')
    await expect(discoverPasskey()).rejects.toThrow('userHandle')
  })

  it('throws when step 2 returns no PRF output', async () => {
    const pubkeyBytes = randomBytes(32)
    const rawId = randomBytes(16)
    const get = vi.fn()
      .mockResolvedValueOnce({
        type: 'public-key',
        rawId: rawId.buffer.slice(0),
        response: { userHandle: pubkeyBytes.buffer.slice(0) },
        getClientExtensionResults: () => ({}),
      })
      .mockResolvedValueOnce({
        type: 'public-key',
        rawId: rawId.buffer.slice(0),
        response: {},
        getClientExtensionResults: () => ({}), // no prf
      })
    setupGet(get)

    const { discoverPasskey } = await import('../../src/webauthn/authenticate.js')
    const { PrfNotSupportedError } = await import('../../src/errors.js')
    await expect(discoverPasskey()).rejects.toBeInstanceOf(PrfNotSupportedError)
  })
})
