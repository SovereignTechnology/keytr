import { describe, it, expect, vi, afterEach } from 'vitest'
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js'
import { NPK_STORE_PRF_INPUT } from '../../src/crypto/npk.js'
import { PRF_SALT } from '../../src/types.js'

vi.mock('../../src/webauthn/natives.js', () => ({ nativeCreate: undefined, nativeGet: undefined }))

const originalNavigator = globalThis.navigator
const AUTHOR = bytesToHex(randomBytes(32))

function setup(create: ReturnType<typeof vi.fn>, get = vi.fn()) {
  Object.defineProperty(globalThis, 'navigator', { value: { credentials: { create, get } }, configurable: true })
}

function created(prf: Record<string, unknown>, rawId = randomBytes(16)) {
  return vi.fn().mockResolvedValue({
    type: 'public-key', rawId: rawId.buffer.slice(0),
    response: { getTransports: () => ['internal'] },
    getClientExtensionResults: () => ({ prf }),
  })
}

describe('registerStoredPasskey', () => {
  afterEach(() => {
    Object.defineProperty(globalThis, 'navigator', { value: originalNavigator, configurable: true })
    vi.restoreAllMocks()
  })

  it('writes the tagged stored handle and evaluates the stored-mode PRF input', async () => {
    const out = randomBytes(32)
    const create = created({ enabled: true, results: { first: out.buffer.slice(0) } })
    setup(create)
    const { registerStoredPasskey } = await import('../../src/webauthn/register.js')
    const result = await registerStoredPasskey({ userName: 'a', userDisplayName: 'A', author: AUTHOR, rpId: 'example.com' })
    const opts = create.mock.calls[0][0].publicKey
    expect(bytesToHex(new Uint8Array(opts.user.id))).toBe('4e504b0102' + AUTHOR)
    expect(new Uint8Array(opts.extensions.prf.eval.first)).toEqual(NPK_STORE_PRF_INPUT)
    expect(opts.authenticatorSelection).toMatchObject({ residentKey: 'required', userVerification: 'required' })
    expect(result.keyMaterial).toEqual(out)
  })

  it('tries one assertion with the same input when no output came back', async () => {
    const out = randomBytes(32)
    const get = vi.fn().mockResolvedValue({ getClientExtensionResults: () => ({ prf: { results: { first: out.buffer.slice(0) } } }) })
    setup(created({}), get)
    const { registerStoredPasskey } = await import('../../src/webauthn/register.js')
    const result = await registerStoredPasskey({ userName: 'a', userDisplayName: 'A', author: AUTHOR })
    expect(new Uint8Array(get.mock.calls[0][0].publicKey.extensions.prf.eval.first)).toEqual(NPK_STORE_PRF_INPUT)
    expect(result.keyMaterial).toEqual(out)
  })

  it('rejects a malformed author before creating a credential', async () => {
    const create = created({})
    setup(create)
    const { registerStoredPasskey } = await import('../../src/webauthn/register.js')
    await expect(registerStoredPasskey({ userName: 'a', userDisplayName: 'A', author: 'xyz' })).rejects.toThrow(/author/)
    expect(create).not.toHaveBeenCalled()
  })

  it('leaves registerPasskey on "keytr-v1" with the raw pubkey handle', async () => {
    const create = created({ enabled: true, results: { first: randomBytes(32).buffer.slice(0) } })
    setup(create)
    const { registerPasskey } = await import('../../src/webauthn/register.js')
    await registerPasskey({ userName: 'a', userDisplayName: 'A', pubkey: AUTHOR })
    const opts = create.mock.calls[0][0].publicKey
    expect(bytesToHex(new Uint8Array(opts.user.id))).toBe(AUTHOR)
    expect(new Uint8Array(opts.extensions.prf.eval.first)).toEqual(PRF_SALT)
  })
})

describe('discoverStoredPasskey', () => {
  afterEach(() => {
    Object.defineProperty(globalThis, 'navigator', { value: originalNavigator, configurable: true })
  })

  it('asks for the stored PRF input in the discovery ceremony and returns the raw handle', async () => {
    const out = randomBytes(32)
    const handle = new Uint8Array([0x4e, 0x50, 0x4b, 1, 1, 1, ...randomBytes(16)])
    const get = vi.fn().mockResolvedValue({
      rawId: randomBytes(16).buffer.slice(0),
      response: { userHandle: handle.buffer.slice(0) },
      getClientExtensionResults: () => ({ prf: { results: { first: out.buffer.slice(0) } } }),
    })
    setup(vi.fn(), get)
    const { discoverStoredPasskey } = await import('../../src/webauthn/authenticate.js')
    const result = await discoverStoredPasskey({ rpId: 'example.com' })
    const opts = get.mock.calls[0][0].publicKey
    expect(opts.allowCredentials).toEqual([])
    expect(new Uint8Array(opts.extensions.prf.eval.first)).toEqual(NPK_STORE_PRF_INPUT)
    expect(result.userHandle).toEqual(handle)
    expect(result.prfOutput).toEqual(out)
  })

  it('returns null for a missing handle and PRF output', async () => {
    const get = vi.fn().mockResolvedValue({ rawId: randomBytes(16).buffer.slice(0), response: {}, getClientExtensionResults: () => ({}) })
    setup(vi.fn(), get)
    const { discoverStoredPasskey } = await import('../../src/webauthn/authenticate.js')
    const result = await discoverStoredPasskey()
    expect(result.prfOutput).toBeNull()
    expect(result.userHandle).toBeNull()
  })
})
