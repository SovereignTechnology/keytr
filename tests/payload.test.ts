import { describe, it, expect, vi, beforeEach } from 'vitest'
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure'
import { base64url } from '@scure/base'
import { encryptPayload } from '../src/crypto/payload.js'
import { buildPayloadEvent, parsePayloadEvent, verifyPayloadEvent, payloadDTag } from '../src/nostr/payload.js'
import { setupPayload, unlockPayload, discoverPayload } from '../src/payload.js'
import { registerPasskey } from '../src/webauthn/register.js'
import { authenticatePasskey, discoverPasskey } from '../src/webauthn/authenticate.js'
import { fetchKeytrEvents } from '../src/nostr/relay.js'

vi.mock('../src/webauthn/register.js', () => ({ registerPasskey: vi.fn() }))
vi.mock('../src/webauthn/authenticate.js', () => ({ authenticatePasskey: vi.fn(), kihAuthenticatePasskey: vi.fn(), discoverPasskey: vi.fn() }))
vi.mock('../src/nostr/relay.js', () => ({ fetchKeytrEvents: vi.fn() }))
const secret = new Uint8Array(32).fill(1)
const pubkey = getPublicKey(secret)
const credentialId = new Uint8Array([1, 2, 3])
const credential = { credentialId, credentialIdBase64url: base64url.encode(credentialId), rpId: 'example.com', transports: [] }
const context = { credentialId, pubkey, rpId: credential.rpId, payloadType: 'vault' as const, schema: 'org.example.vault.v1' }
const key = new Uint8Array(32).fill(4)
const payload = new TextEncoder().encode('{"accounts":[1,2]}')
function makeEvent() {
  const encryptedBlob = encryptPayload({ ...context, keyMaterial: key, payload })
  return finalizeEvent(buildPayloadEvent({ ...context, credential, encryptedBlob }), secret)
}
beforeEach(() => vi.resetAllMocks())

describe('typed payload event', () => {
  it('builds, parses and verifies a separate coordinate', () => {
    const event = makeEvent()
    expect(parsePayloadEvent(event)).toMatchObject(context)
    expect(payloadDTag(context)).toBe('AQID:vault:org.example.vault.v1')
    expect(verifyPayloadEvent(event, context).encryptedBlob).toBe(event.content)
  })
  it('rejects duplicate and malformed required tags, versions and context', () => {
    const event = makeEvent()
    for (const tag of ['d', 'rp', 'credential', 'v', 'type', 'schema', 'algo', 'kdf']) {
      expect(() => parsePayloadEvent({ ...event, tags: [...event.tags, event.tags.find(t => t[0] === tag)!] })).toThrow()
      expect(() => parsePayloadEvent({ ...event, tags: event.tags.filter(t => t[0] !== tag) })).toThrow()
    }
    for (const [tag, value] of [['v', '3'], ['type', 'nsec'], ['algo', 'other'], ['kdf', 'other'], ['credential', '!'], ['d', 'AQID']]) expect(() => parsePayloadEvent({ ...event, tags: event.tags.map(t => t[0] === tag ? [tag, value] : t) })).toThrow()
    for (const wrong of [{ pubkey: 'cd'.repeat(32) }, { rpId: 'other.example.com' }, { payloadType: 'seed' as const }, { schema: 'org.example.v2' }, { credentialId: new Uint8Array([8]) }]) expect(() => verifyPayloadEvent(event, { ...context, ...wrong })).toThrow()
    expect(() => verifyPayloadEvent({ ...event, sig: '0'.repeat(128) }, context)).toThrow()
    expect(() => parsePayloadEvent({ ...event, kind: 1 })).toThrow()
    expect(() => buildPayloadEvent({ ...context, credential, encryptedBlob: '!' })).toThrow()
  })
  it('does not trust a cached verification symbol after mutation', () => {
    const event = makeEvent()
    event.content = makeEvent().content
    expect(() => verifyPayloadEvent(event, context)).toThrow('signature')
  })
})

describe('typed payload flows', () => {
  it('sets up a vault without returning PRF material', async () => {
    const material = key.slice()
    vi.mocked(registerPasskey).mockResolvedValue({ credential, keyMaterial: material })
    const bundle = await setupPayload(payload, { ...context, userName: 'test', userDisplayName: 'Test' })
    expect(bundle.eventTemplate.tags).toContainEqual(['type', 'vault'])
    expect(material.every(n => n === 0)).toBe(true)
  })
  it('validates before prompting and clears PRF output after unlock', async () => {
    const event = makeEvent()
    await expect(unlockPayload({ ...event, sig: '0'.repeat(128) }, context)).rejects.toThrow()
    expect(authenticatePasskey).not.toHaveBeenCalled()
    const material = key.slice()
    vi.mocked(authenticatePasskey).mockResolvedValue(material)
    expect(await unlockPayload(event, context)).toEqual(payload)
    expect(material.every(n => n === 0)).toBe(true)
  })
  it('discovers the newest payload without npub input and clears PRF material', async () => {
    const material = key.slice()
    vi.mocked(discoverPasskey).mockResolvedValue({ credentialId, pubkey, mode: 'prf', keyMaterial: material })
    const newest = makeEvent()
    const older = finalizeEvent({ ...newest, created_at: newest.created_at - 1 }, secret)
    vi.mocked(fetchKeytrEvents).mockResolvedValue([older, newest])
    expect(await discoverPayload(['wss://example.com'], context)).toEqual({ payload, pubkey })
    expect(material.every(n => n === 0)).toBe(true)
  })
  it.each(['missing', 'network', 'legacy', 'corrupt'] as const)('clears material on %s failure without downgrade', async failure => {
    const material = key.slice()
    vi.mocked(discoverPasskey).mockResolvedValue({ credentialId, pubkey, mode: failure === 'legacy' ? 'kih' : 'prf', keyMaterial: material })
    if (failure === 'network') vi.mocked(fetchKeytrEvents).mockRejectedValue(new Error('offline'))
    else if (failure === 'corrupt') {
      const old = makeEvent()
      const newer = finalizeEvent({ ...old, created_at: old.created_at + 1, content: old.content.slice(0, -4) + 'AAAA' }, secret)
      vi.mocked(fetchKeytrEvents).mockResolvedValue([old, newer])
    } else vi.mocked(fetchKeytrEvents).mockResolvedValue([])
    await expect(discoverPayload(['wss://example.com'], context)).rejects.toThrow()
    expect(material.every(n => n === 0)).toBe(true)
  })
})

it('skips typed events in the existing private-key login API before prompting', async () => {
  const { loginWithKeytr } = await import('../src/index.js')
  await expect(loginWithKeytr([makeEvent()])).rejects.toThrow('No matching passkey')
  expect(authenticatePasskey).not.toHaveBeenCalled()
})

it('rejects an invalid setup before creating a credential', async () => {
  await expect(setupPayload(new Uint8Array(), { ...context, userName: 'test', userDisplayName: 'Test' })).rejects.toThrow()
  expect(registerPasskey).not.toHaveBeenCalled()
})
