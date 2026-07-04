import { describe, it, expect, vi, afterEach } from 'vitest'
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js'
import { KIH_MODE_BYTE, KIH_USER_ID_SIZE, KEYTR_VERSION, KEYTR_KIH_VERSION } from '../../src/types.js'

vi.mock('../../src/webauthn/natives.js', () => ({
  nativeCreate: undefined,
  nativeGet: undefined,
}))

const originalNavigator = globalThis.navigator
const PUBKEY = bytesToHex(randomBytes(32))

function kihHandle(): Uint8Array {
  const h = new Uint8Array(KIH_USER_ID_SIZE)
  h[0] = KIH_MODE_BYTE
  h.set(randomBytes(32), 1)
  return h
}

function setupGlobals(overrides?: { create?: ReturnType<typeof vi.fn>; get?: ReturnType<typeof vi.fn> }) {
  const create = overrides?.create ?? vi.fn()
  const get = overrides?.get ?? vi.fn()
  Object.defineProperty(globalThis, 'navigator', {
    value: { credentials: { create, get } },
    configurable: true,
  })
  if (!globalThis.crypto?.getRandomValues) {
    Object.defineProperty(globalThis, 'crypto', {
      value: { getRandomValues: (a: Uint8Array) => { a.set(randomBytes(a.length)); return a } },
      configurable: true,
    })
  }
  return { create, get }
}

function restore() {
  Object.defineProperty(globalThis, 'navigator', { value: originalNavigator, configurable: true })
}

describe('WebAuthn credential lifecycle (PRF)', () => {
  afterEach(() => { restore(); vi.restoreAllMocks() })

  it('authenticatePasskey returns the PRF output', async () => {
    const prfOutput = randomBytes(32)
    setupGlobals({
      get: vi.fn().mockResolvedValue({
        type: 'public-key',
        rawId: randomBytes(16).buffer.slice(0),
        response: {},
        getClientExtensionResults: () => ({ prf: { results: { first: prfOutput.buffer.slice(0) } } }),
      }),
    })

    const { authenticatePasskey } = await import('../../src/webauthn/authenticate.js')
    const key = await authenticatePasskey({ credentialId: randomBytes(16), rpId: 'keytr.org' })
    expect(key).toEqual(prfOutput)
  })

  it('authenticatePasskey requests the PRF extension and throws when absent', async () => {
    const { get } = setupGlobals({
      get: vi.fn().mockResolvedValue({
        type: 'public-key',
        rawId: randomBytes(16).buffer.slice(0),
        response: {},
        getClientExtensionResults: () => ({}),
      }),
    })

    const { authenticatePasskey } = await import('../../src/webauthn/authenticate.js')
    const { PrfNotSupportedError } = await import('../../src/errors.js')
    await expect(
      authenticatePasskey({ credentialId: randomBytes(16), rpId: 'keytr.org' })
    ).rejects.toBeInstanceOf(PrfNotSupportedError)
    expect((get.mock.calls[0][0] as CredentialRequestOptions).publicKey as any).toHaveProperty('extensions')
  })

  it('kihAuthenticatePasskey extracts the key from a legacy userHandle (no PRF ext)', async () => {
    const handle = kihHandle()
    const { get } = setupGlobals({
      get: vi.fn().mockResolvedValue({
        type: 'public-key',
        rawId: randomBytes(16).buffer.slice(0),
        response: { userHandle: handle.buffer.slice(0) },
        getClientExtensionResults: () => ({}),
      }),
    })

    const { kihAuthenticatePasskey } = await import('../../src/webauthn/authenticate.js')
    const key = await kihAuthenticatePasskey({ credentialId: randomBytes(16), rpId: 'keytr.org' })
    expect(key).toEqual(handle.slice(1))
    // legacy path must NOT send a PRF extension
    expect((get.mock.calls[0][0] as CredentialRequestOptions).publicKey as any).not.toHaveProperty('extensions')
  })

  it('kihAuthenticatePasskey throws when the userHandle is empty', async () => {
    setupGlobals({
      get: vi.fn().mockResolvedValue({
        type: 'public-key',
        rawId: randomBytes(16).buffer.slice(0),
        response: { userHandle: new ArrayBuffer(0) },
        getClientExtensionResults: () => ({}),
      }),
    })
    const { kihAuthenticatePasskey } = await import('../../src/webauthn/authenticate.js')
    await expect(
      kihAuthenticatePasskey({ credentialId: randomBytes(16), rpId: 'keytr.org' })
    ).rejects.toThrow('userHandle')
  })

  it('full PRF register → encrypt(v1) → authenticate → decrypt(v1) roundtrip', async () => {
    const prfOutput = randomBytes(32)
    const rawId = randomBytes(16)
    setupGlobals({
      create: vi.fn().mockResolvedValue({
        type: 'public-key',
        rawId: rawId.buffer.slice(0),
        response: { getTransports: () => ['internal'] },
        getClientExtensionResults: () => ({ prf: { enabled: true, results: { first: prfOutput.buffer.slice(0) } } }),
      }),
      get: vi.fn().mockResolvedValue({
        type: 'public-key',
        rawId: rawId.buffer.slice(0),
        response: {},
        getClientExtensionResults: () => ({ prf: { results: { first: prfOutput.buffer.slice(0) } } }),
      }),
    })

    const { registerPasskey } = await import('../../src/webauthn/register.js')
    const { authenticatePasskey } = await import('../../src/webauthn/authenticate.js')
    const { encryptNsec } = await import('../../src/crypto/encrypt.js')
    const { decryptNsec } = await import('../../src/crypto/decrypt.js')

    const { credential, keyMaterial } = await registerPasskey({
      userName: 'alice', userDisplayName: 'Alice', pubkey: PUBKEY,
    })

    const nsecBytes = randomBytes(32)
    const encryptedBlob = encryptNsec({
      nsecBytes, keyMaterial, credentialId: credential.credentialId, version: KEYTR_VERSION,
    })

    const authKey = await authenticatePasskey({
      credentialId: credential.credentialId, rpId: credential.rpId, transports: credential.transports,
    })
    expect(authKey).toEqual(keyMaterial)

    const decrypted = decryptNsec({
      encryptedBlob, keyMaterial: authKey, credentialId: credential.credentialId, version: KEYTR_VERSION,
    })
    expect(decrypted).toEqual(nsecBytes)
    expect(KEYTR_VERSION).toBe(1)
    expect(KEYTR_KIH_VERSION).toBe(3)
  })
})
