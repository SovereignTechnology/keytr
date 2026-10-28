import { describe, it, expect, vi, beforeEach } from 'vitest'
import { hexToBytes } from '@noble/hashes/utils.js'
import { base64url } from '@scure/base'
import { finalizeEvent, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { registerStoredPasskey } from '../src/webauthn/register.js'
import { authenticatePrf, discoverStoredPasskey } from '../src/webauthn/authenticate.js'
import { fetchKeytrEvents, fetchStoredEvents } from '../src/nostr/relay.js'
import { setupStored, discoverStored } from '../src/stored.js'
import { buildStoredHandle } from '../src/webauthn/handle.js'
import { buildNpkEvent } from '../src/nostr/npk.js'
import { encryptNpkRecord, NPK_STORE_PRF_INPUT } from '../src/crypto/npk.js'
import { encryptNsec } from '../src/crypto/encrypt.js'
import { buildKeytrEvent } from '../src/nostr/event.js'
import { PRF_SALT } from '../src/types.js'
import { PasskeyModeError } from '../src/errors.js'

vi.mock('../src/webauthn/register.js', () => ({ registerPasskey: vi.fn(), registerStoredPasskey: vi.fn() }))
vi.mock('../src/webauthn/authenticate.js', () => ({
  authenticatePasskey: vi.fn(), authenticatePrf: vi.fn(), kihAuthenticatePasskey: vi.fn(),
  discoverPasskey: vi.fn(), discoverStoredPasskey: vi.fn(),
}))
vi.mock('../src/nostr/relay.js', () => ({ fetchKeytrEvents: vi.fn(), fetchStoredEvents: vi.fn(), fetchKeytrEventByDTag: vi.fn(), publishKeytrEvent: vi.fn() }))

const rpId = 'example.com'
const credentialId = new Uint8Array(16).fill(0xaa)
const credential = { credentialId, credentialIdBase64url: base64url.encode(credentialId), rpId, transports: [] as AuthenticatorTransport[] }
const storePrf = new Uint8Array(32).fill(7)
const legacyPrf = new Uint8Array(32).fill(9)
const secretKey = hexToBytes('01'.repeat(32))
const author = getPublicKey(secretKey)
const relays = ['wss://relay.example.com']
const user = { userName: 'a', userDisplayName: 'A', rpId }

function npkEvent(createdAt: number, prf = storePrf) {
  const record = encryptNpkRecord({ type: 'key', plaintext: secretKey, keyMaterial: prf, rpId, author, credentialId })
  return finalizeEvent({ ...buildNpkEvent({ record, credentialId, rpId }), created_at: createdAt }, secretKey)
}

function v1Event() {
  const encryptedBlob = encryptNsec({ nsecBytes: secretKey, keyMaterial: legacyPrf, credentialId })
  return finalizeEvent(buildKeytrEvent({ credential, encryptedBlob }), secretKey)
}

function discovered(userHandle: Uint8Array | null, prfOutput: Uint8Array | null = storePrf.slice()) {
  vi.mocked(discoverStoredPasskey).mockResolvedValue({ credentialId, userHandle, prfOutput })
}

beforeEach(() => {
  vi.resetAllMocks()
  vi.mocked(fetchKeytrEvents).mockResolvedValue([])
  vi.mocked(fetchStoredEvents).mockResolvedValue([])
})

describe('setupStored', () => {
  it('registers a tagged stored passkey, returns an npk1 record and signed event, and zeroes PRF output', async () => {
    const material = storePrf.slice()
    vi.mocked(registerStoredPasskey).mockResolvedValue({ credential, keyMaterial: material })
    const bundle = await setupStored({ type: 'key', secretKey }, user)
    expect(registerStoredPasskey).toHaveBeenCalledWith(expect.objectContaining({ author, rpId }))
    expect(bundle.author).toBe(author)
    expect(bundle.record.subarray(0, 5)).toEqual(new Uint8Array([0x4e, 0x50, 0x4b, 0x01, 0x01]))
    expect(bundle.event.pubkey).toBe(author)
    expect(bundle.event.kind).toBe(31778)
    expect(bundle.event.tags.some(t => t[0] === 'v')).toBe(false)
    expect(verifyEvent(bundle.event)).toBe(true)
    expect(material.every(b => b === 0)).toBe(true)
    expect(secretKey.some(b => b !== 0)).toBe(true)
  })

  it("uses the vault's default account as author", async () => {
    vi.mocked(registerStoredPasskey).mockResolvedValue({ credential, keyMaterial: storePrf.slice() })
    const other = '02'.repeat(32)
    const bundle = await setupStored({ type: 'vault', vault: { accounts: [{ kind: 'key', secret: '01'.repeat(32) }, { kind: 'key', secret: other, default: true }] } }, user)
    expect(bundle.author).toBe(getPublicKey(hexToBytes(other)))
  })

  it('validates the secret before prompting', async () => {
    await expect(setupStored({ type: 'key', secretKey: new Uint8Array(32) }, user)).rejects.toThrow()
    await expect(setupStored({ type: 'vault', vault: { accounts: [{ kind: 'derived', path: "m/44'/1237'/0'/0/0" }] } }, user)).rejects.toThrow(/importable/)
    await expect(setupStored({ type: 'vault', vault: { accounts: [{ kind: 'xpub' }] } }, user)).rejects.toThrow(/importable/)
    expect(registerStoredPasskey).not.toHaveBeenCalled()
  })
})

describe('discoverStored', () => {
  it('opens the newest npk1 record for a tagged stored handle in one ceremony', async () => {
    discovered(buildStoredHandle(author))
    vi.mocked(fetchStoredEvents).mockResolvedValue([npkEvent(1000), npkEvent(2000), v1Event()])
    const result = await discoverStored(relays, { rpId })
    expect(result).toEqual({ format: 'npk1', secret: { type: 'key', secretKey }, author, credentialId, warnings: [] })
    expect(fetchStoredEvents).toHaveBeenCalledWith(author, credentialId, relays, undefined)
    expect(authenticatePrf).not.toHaveBeenCalled()
  })

  it('runs a targeted follow-up with the stored input when discovery returned no PRF', async () => {
    discovered(buildStoredHandle(author), null)
    vi.mocked(authenticatePrf).mockResolvedValue(storePrf.slice())
    vi.mocked(fetchStoredEvents).mockResolvedValue([npkEvent(1000)])
    await discoverStored(relays, { rpId })
    expect(authenticatePrf).toHaveBeenCalledWith(expect.objectContaining({ credentialId, rpId }), NPK_STORE_PRF_INPUT)
  })

  it('recovers an independent immutable key and warns when another copy fails', async () => {
    discovered(buildStoredHandle(author))
    vi.mocked(fetchStoredEvents).mockResolvedValue([npkEvent(1000), npkEvent(2000, new Uint8Array(32).fill(1))])
    const result = await discoverStored(relays, { rpId })
    expect(result.secret).toEqual({ type: 'key', secretKey })
    expect(result.warnings).toHaveLength(1)
  })

  it('reports a missing record for a tagged stored handle', async () => {
    discovered(buildStoredHandle(author))
    await expect(discoverStored(relays, { rpId })).rejects.toMatchObject({ reason: 'record-not-found' })
  })

  it('opens a keytr v1 record for a 32-byte handle with "keytr-v1"', async () => {
    discovered(hexToBytes(author))
    vi.mocked(fetchKeytrEvents).mockResolvedValue([v1Event()])
    vi.mocked(authenticatePrf).mockResolvedValue(legacyPrf.slice())
    const result = await discoverStored(relays, { rpId })
    expect(result).toEqual({ format: 'keytr-v1', secret: { type: 'key', secretKey }, author, credentialId })
    expect(authenticatePrf).toHaveBeenCalledWith(expect.objectContaining({ credentialId, rpId }), PRF_SALT)
  })

  it('treats a 32-byte handle without a v1 record as unknown, without prompting again', async () => {
    discovered(new Uint8Array(32).fill(0x55))
    await expect(discoverStored(relays, { rpId })).rejects.toMatchObject({ reason: 'unknown' })
    expect(authenticatePrf).not.toHaveBeenCalled()
  })

  it.each([
    ['derived 0x01', '4e504b01010100112233445566778899aabbccddeeff', 'derived'],
    ['derived 0x02', '4e504b010102ffeeddccbbaa99887766554433221100', 'derived'],
    ['unsupported version', '4e504b02010000000000000000000000000000000000', 'unsupported'],
    ['key-in-handle', '03' + 'ab'.repeat(32), 'unsupported'],
    ['UUID', '33663262386331652d396434612d346537622d623563322d316136663065386437633934', 'unknown'],
    ['missing', null, 'unknown'],
  ])('refuses a %s handle without touching relays', async (_name, handle, reason) => {
    discovered(handle === null ? null : hexToBytes(handle))
    const err = await discoverStored(relays, { rpId }).catch(e => e)
    expect(err).toBeInstanceOf(PasskeyModeError)
    expect(err.reason).toBe(reason)
    expect(fetchKeytrEvents).not.toHaveBeenCalled()
    expect(authenticatePrf).not.toHaveBeenCalled()
  })
})

it('loginWithKeytr skips npk1 events before prompting', async () => {
  const { loginWithKeytr } = await import('../src/index.js')
  const { authenticatePasskey } = await import('../src/webauthn/authenticate.js')
  await expect(loginWithKeytr([npkEvent(1000)])).rejects.toThrow('No matching passkey')
  expect(authenticatePasskey).not.toHaveBeenCalled()
})
