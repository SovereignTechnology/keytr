import { describe, it, expect, vi, afterEach } from 'vitest'
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js'
import { base64url } from '@scure/base'
import { PRF_USER_ID_SIZE } from '../../src/types.js'

// Bypass cached native refs so test mocks on navigator.credentials take effect
vi.mock('../../src/webauthn/natives.js', () => ({
  nativeCreate: undefined,
  nativeGet: undefined,
}))

const originalNavigator = globalThis.navigator
const originalWindow = (globalThis as any).window

const PUBKEY = bytesToHex(randomBytes(32)) // 64 hex chars

/** create() result whose PRF output is present at registration (happy path) */
function createWithPrf(prfOutput: Uint8Array, rawId = randomBytes(16)) {
  return vi.fn().mockResolvedValue({
    type: 'public-key',
    rawId: rawId.buffer.slice(0),
    response: { getTransports: () => ['internal', 'hybrid'] },
    getClientExtensionResults: () => ({ prf: { enabled: true, results: { first: prfOutput.buffer.slice(0) } } }),
  })
}

/** create() result that reports prf.enabled but returns no output (YubiKey-style) */
function createEnabledNoOutput(rawId = randomBytes(16)) {
  return vi.fn().mockResolvedValue({
    type: 'public-key',
    rawId: rawId.buffer.slice(0),
    response: { getTransports: () => ['usb'] },
    getClientExtensionResults: () => ({ prf: { enabled: true } }),
  })
}

function setupGlobals(create: ReturnType<typeof vi.fn>, get?: ReturnType<typeof vi.fn>, signal?: ReturnType<typeof vi.fn>) {
  Object.defineProperty(globalThis, 'navigator', {
    value: { credentials: { create, get: get ?? vi.fn() } },
    configurable: true,
  })
  if (!globalThis.crypto?.getRandomValues) {
    Object.defineProperty(globalThis, 'crypto', {
      value: { getRandomValues: (a: Uint8Array) => { a.set(randomBytes(a.length)); return a } },
      configurable: true,
    })
  }
  if (signal) {
    Object.defineProperty(globalThis, 'window', {
      value: { PublicKeyCredential: { signalUnknownCredential: signal } },
      configurable: true,
    })
  }
}

function restoreGlobals() {
  Object.defineProperty(globalThis, 'navigator', { value: originalNavigator, configurable: true })
  Object.defineProperty(globalThis, 'window', { value: originalWindow, configurable: true })
}

describe('registerPasskey (PRF)', () => {
  afterEach(() => {
    restoreGlobals()
    vi.restoreAllMocks()
  })

  it('returns credential + 32-byte keyMaterial in a single ceremony', async () => {
    const prfOutput = randomBytes(32)
    const create = createWithPrf(prfOutput)
    setupGlobals(create)

    const { registerPasskey } = await import('../../src/webauthn/register.js')
    const result = await registerPasskey({ userName: 'alice', userDisplayName: 'Alice', pubkey: PUBKEY })

    expect(create).toHaveBeenCalledOnce()
    expect(result.keyMaterial).toEqual(prfOutput)
    expect(result.credential.prfSupported).toBe(true)
    expect(result.credential.credentialIdBase64url).toBe(base64url.encode(result.credential.credentialId))
  })

  it('requests the PRF extension and stores the pubkey as user.id', async () => {
    const create = createWithPrf(randomBytes(32))
    setupGlobals(create)

    const { registerPasskey } = await import('../../src/webauthn/register.js')
    await registerPasskey({ userName: 'bob', userDisplayName: 'Bob', pubkey: PUBKEY })

    const opts = create.mock.calls[0][0] as CredentialCreationOptions
    expect((opts.publicKey as any).extensions?.prf).toBeDefined()
    const userId = new Uint8Array(opts.publicKey!.user.id as ArrayBuffer)
    expect(userId.length).toBe(PRF_USER_ID_SIZE)
    expect(bytesToHex(userId)).toBe(PUBKEY)
  })

  it('throws when pubkey is missing or malformed', async () => {
    setupGlobals(createWithPrf(randomBytes(32)))
    const { registerPasskey } = await import('../../src/webauthn/register.js')

    await expect(registerPasskey({ userName: 'x', userDisplayName: 'X' } as any)).rejects.toThrow('pubkey')
    await expect(registerPasskey({ userName: 'x', userDisplayName: 'X', pubkey: 'nothex' })).rejects.toThrow('pubkey')
  })

  it('falls back to a targeted get() when PRF output is only available on assertion', async () => {
    const prfOutput = randomBytes(32)
    const rawId = randomBytes(16)
    const create = createEnabledNoOutput(rawId)
    const get = vi.fn().mockResolvedValue({
      type: 'public-key',
      rawId: rawId.buffer.slice(0),
      getClientExtensionResults: () => ({ prf: { results: { first: prfOutput.buffer.slice(0) } } }),
      response: {},
    })
    setupGlobals(create, get)

    const { registerPasskey } = await import('../../src/webauthn/register.js')
    const result = await registerPasskey({ userName: 'yubi', userDisplayName: 'Yubi', pubkey: PUBKEY })

    expect(create).toHaveBeenCalledOnce()
    expect(get).toHaveBeenCalledOnce()
    const getOpts = get.mock.calls[0][0] as CredentialRequestOptions
    expect((getOpts.publicKey as any).extensions?.prf).toBeDefined()
    expect(getOpts.publicKey?.allowCredentials?.length).toBe(1)
    expect(result.keyMaterial).toEqual(prfOutput)
  })

  it('cleans up the orphan credential and throws PrfNotSupportedError when no PRF output', async () => {
    const rawId = randomBytes(16)
    const create = createEnabledNoOutput(rawId)
    const get = vi.fn().mockResolvedValue({
      type: 'public-key',
      rawId: rawId.buffer.slice(0),
      getClientExtensionResults: () => ({}), // still no prf output
      response: {},
    })
    const signal = vi.fn().mockResolvedValue(undefined)
    setupGlobals(create, get, signal)

    const { registerPasskey } = await import('../../src/webauthn/register.js')
    const { PrfNotSupportedError } = await import('../../src/errors.js')

    await expect(
      registerPasskey({ userName: 'z', userDisplayName: 'Z', pubkey: PUBKEY })
    ).rejects.toBeInstanceOf(PrfNotSupportedError)
    expect(signal).toHaveBeenCalledOnce()
    expect(signal.mock.calls[0][0]).toMatchObject({ rpId: 'keytr.org' })
  })

  it('throws WebAuthnError on a null create result', async () => {
    setupGlobals(vi.fn().mockResolvedValue(null))
    const { registerPasskey } = await import('../../src/webauthn/register.js')
    await expect(
      registerPasskey({ userName: 'n', userDisplayName: 'N', pubkey: PUBKEY })
    ).rejects.toThrow('Credential creation returned null')
  })
})
