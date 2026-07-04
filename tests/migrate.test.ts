import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { randomBytes } from '@noble/hashes/utils.js'
import { finalizeEvent } from 'nostr-tools/pure'
import type { Event } from 'nostr-tools/core'
import { KEYTR_KIH_VERSION, KEYTR_EVENT_KIND, DELETION_EVENT_KIND, KIH_MODE_BYTE, KIH_USER_ID_SIZE } from '../src/types.js'

vi.mock('../src/webauthn/natives.js', () => ({ nativeCreate: undefined, nativeGet: undefined }))
vi.mock('nostr-tools/relay', () => ({ Relay: { connect: vi.fn() } }))

import { Relay } from 'nostr-tools/relay'
const mockRelay = Relay as unknown as { connect: ReturnType<typeof vi.fn> }

const originalNavigator = globalThis.navigator

/** Build a signed legacy KiH (v=3) event owned by `nsec`, encrypted with `kihKey`. */
async function makeOldKihEvent(nsec: Uint8Array, kihKey: Uint8Array, credentialId: Uint8Array): Promise<Event> {
  const { encryptNsec } = await import('../src/crypto/encrypt.js')
  const { buildKeytrEvent } = await import('../src/nostr/event.js')
  const { base64url } = await import('@scure/base')
  const blob = encryptNsec({ nsecBytes: nsec, keyMaterial: kihKey, credentialId, version: KEYTR_KIH_VERSION })
  const template = buildKeytrEvent({
    credential: {
      credentialId,
      credentialIdBase64url: base64url.encode(credentialId),
      rpId: 'keytr.org',
      transports: [] as AuthenticatorTransport[],
    },
    encryptedBlob: blob,
    version: KEYTR_KIH_VERSION,
  })
  return finalizeEvent(template, nsec)
}

function setNavigatorForMigration(kihKey: Uint8Array, discoverCredId: Uint8Array, prfOutput: Uint8Array) {
  const handle = new Uint8Array(KIH_USER_ID_SIZE)
  handle[0] = KIH_MODE_BYTE
  handle.set(kihKey, 1)

  const get = vi.fn().mockResolvedValue({ // discoverPasskey (KiH, single ceremony)
    type: 'public-key',
    rawId: discoverCredId.buffer.slice(0),
    response: { userHandle: handle.buffer.slice(0) },
    getClientExtensionResults: () => ({}),
  })
  const create = vi.fn().mockResolvedValue({ // registerPasskey (PRF)
    type: 'public-key',
    rawId: randomBytes(16).buffer.slice(0),
    response: { getTransports: () => ['internal'] },
    getClientExtensionResults: () => ({ prf: { enabled: true, results: { first: prfOutput.buffer.slice(0) } } }),
  })

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
  return { get, create }
}

function mockRelayReturning(oldEvent: Event, publish: ReturnType<typeof vi.fn>) {
  // Fire callbacks in a microtask (like a real relay) so the SUT has assigned
  // its `sub` handle before oneose() calls sub.close().
  const subscribe = vi.fn((filters: any[], cbs: any) => {
    const sub = { close: vi.fn() }
    queueMicrotask(() => {
      if (filters[0]['#d']) cbs.onevent(oldEvent)
      cbs.oneose()
    })
    return sub
  })
  mockRelay.connect.mockResolvedValue({ subscribe, publish, close: vi.fn() })
  return { subscribe }
}

describe('migrateFromKih', () => {
  beforeEach(() => { vi.clearAllMocks() })
  afterEach(() => {
    Object.defineProperty(globalThis, 'navigator', { value: originalNavigator, configurable: true })
    vi.restoreAllMocks()
  })

  it('migrates a KiH credential: publishes v=1 event then a kind:5 deletion', async () => {
    const { generateNsec, nsecToHexPubkey } = await import('../src/index.js')
    const nsec = generateNsec()
    const pubkey = nsecToHexPubkey(nsec)
    const kihKey = randomBytes(32)
    const credentialId = randomBytes(16)
    const oldEvent = await makeOldKihEvent(nsec, kihKey, credentialId)

    setNavigatorForMigration(kihKey, credentialId, randomBytes(32))
    const publish = vi.fn().mockResolvedValue(undefined)
    mockRelayReturning(oldEvent, publish)

    const { migrateFromKih } = await import('../src/migrate.js')
    const result = await migrateFromKih({
      relays: ['wss://r.example'],
      userName: 'alice',
      userDisplayName: 'Alice',
      signalOldCredential: false,
    })

    expect(result.pubkey).toBe(pubkey)
    expect(result.newEvent.kind).toBe(KEYTR_EVENT_KIND)
    expect(result.newEvent.tags.find(t => t[0] === 'v')?.[1]).toBe('1')
    expect(result.newEvent.pubkey).toBe(pubkey)
    expect(result.deletionEvent.kind).toBe(DELETION_EVENT_KIND)
    expect(result.deletionEvent.tags).toContainEqual(['a', `${KEYTR_EVENT_KIND}:${pubkey}:${result.oldDTag}`])
    expect(result.deletionEvent.tags).toContainEqual(['k', String(KEYTR_EVENT_KIND)])
    expect(result.deletionEvent.tags).toContainEqual(['e', oldEvent.id])
    expect(result.deletionPublished).toBe(true)
    // two publishes: new event, then deletion
    expect(publish).toHaveBeenCalledTimes(2)
    expect((publish.mock.calls[0][0] as Event).kind).toBe(KEYTR_EVENT_KIND)
    expect((publish.mock.calls[1][0] as Event).kind).toBe(DELETION_EVENT_KIND)
  })

  it('refuses when the discovered passkey is already PRF', async () => {
    // discover returns a 32-byte pubkey handle → PRF, plus a step-2 PRF assertion
    const pubkeyBytes = randomBytes(32)
    const rawId = randomBytes(16)
    const prfOutput = randomBytes(32)
    const get = vi.fn()
      .mockResolvedValueOnce({ type: 'public-key', rawId: rawId.buffer.slice(0), response: { userHandle: pubkeyBytes.buffer.slice(0) }, getClientExtensionResults: () => ({}) })
      .mockResolvedValueOnce({ type: 'public-key', rawId: rawId.buffer.slice(0), response: {}, getClientExtensionResults: () => ({ prf: { results: { first: prfOutput.buffer.slice(0) } } }) })
    Object.defineProperty(globalThis, 'navigator', { value: { credentials: { create: vi.fn(), get } }, configurable: true })

    const { migrateFromKih } = await import('../src/migrate.js')
    await expect(migrateFromKih({
      relays: ['wss://r.example'], userName: 'a', userDisplayName: 'A', signalOldCredential: false,
    })).rejects.toThrow('already a PRF credential')
  })

  it('aborts (no deletion) when the new event fails to publish', async () => {
    const { generateNsec } = await import('../src/index.js')
    const nsec = generateNsec()
    const kihKey = randomBytes(32)
    const credentialId = randomBytes(16)
    const oldEvent = await makeOldKihEvent(nsec, kihKey, credentialId)

    setNavigatorForMigration(kihKey, credentialId, randomBytes(32))
    const publish = vi.fn().mockRejectedValue(new Error('relay down'))
    mockRelayReturning(oldEvent, publish)

    const { migrateFromKih } = await import('../src/migrate.js')
    const { RelayError } = await import('../src/errors.js')
    await expect(migrateFromKih({
      relays: ['wss://r.example'], userName: 'a', userDisplayName: 'A', signalOldCredential: false,
    })).rejects.toBeInstanceOf(RelayError)
    // only the new-event publish was attempted (rejected); deletion never built
    expect(publish).toHaveBeenCalledTimes(1)
  })

  it('reports deletionPublished:false when only the deletion fails', async () => {
    const { generateNsec } = await import('../src/index.js')
    const nsec = generateNsec()
    const kihKey = randomBytes(32)
    const credentialId = randomBytes(16)
    const oldEvent = await makeOldKihEvent(nsec, kihKey, credentialId)

    setNavigatorForMigration(kihKey, credentialId, randomBytes(32))
    const publish = vi.fn()
      .mockResolvedValueOnce(undefined)               // new event OK
      .mockRejectedValue(new Error('relay down'))     // deletion fails
    mockRelayReturning(oldEvent, publish)

    const { migrateFromKih } = await import('../src/migrate.js')
    const result = await migrateFromKih({
      relays: ['wss://r.example'], userName: 'a', userDisplayName: 'A', signalOldCredential: false,
    })
    expect(result.deletionPublished).toBe(false)
  })
})
