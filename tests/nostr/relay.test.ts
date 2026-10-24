import { describe, it, expect, vi, beforeEach } from 'vitest'
import { KEYTR_EVENT_KIND } from '../../src/types.js'
import type { Event } from 'nostr-tools/core'

// Mock nostr-tools/relay before importing our module
vi.mock('nostr-tools/relay', () => ({
  Relay: {
    connect: vi.fn(),
  },
}))

import { publishKeytrEvent, fetchKeytrEvents, fetchKeytrEventByDTag } from '../../src/nostr/relay.js'
import { Relay } from 'nostr-tools/relay'

const mockRelay = Relay as unknown as { connect: ReturnType<typeof vi.fn> }

function fakeEvent(overrides?: Partial<Event>): Event {
  return {
    id: 'abc123',
    pubkey: 'deadbeef'.repeat(8),
    created_at: 1700000000,
    kind: KEYTR_EVENT_KIND,
    tags: [['d', 'cred1'], ['rp', 'keytr.org']],
    content: 'encrypted-blob',
    sig: 'sig'.repeat(32),
    ...overrides,
  }
}

describe('publishKeytrEvent', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('publishes to a single relay successfully', async () => {
    const publish = vi.fn().mockResolvedValue(undefined)
    const close = vi.fn()
    mockRelay.connect.mockResolvedValue({ publish, close })

    await publishKeytrEvent(fakeEvent(), ['wss://relay1.example'])

    expect(mockRelay.connect).toHaveBeenCalledWith('wss://relay1.example')
    expect(publish).toHaveBeenCalledWith(expect.objectContaining({ kind: KEYTR_EVENT_KIND }))
    expect(close).toHaveBeenCalled()
  })

  it('succeeds if at least one relay works', async () => {
    const publish = vi.fn().mockResolvedValue(undefined)
    const close = vi.fn()
    mockRelay.connect
      .mockRejectedValueOnce(new Error('connection refused'))
      .mockResolvedValueOnce({ publish, close })

    await publishKeytrEvent(fakeEvent(), [
      'wss://dead-relay.example',
      'wss://good-relay.example',
    ])

    expect(publish).toHaveBeenCalledOnce()
  })

  it('throws RelayError when all relays fail', async () => {
    mockRelay.connect.mockRejectedValue(new Error('connection refused'))

    await expect(
      publishKeytrEvent(fakeEvent(), ['wss://relay1.example', 'wss://relay2.example'])
    ).rejects.toThrow('Failed to publish to any relay')
  })

  it('closes relay even when publish fails', async () => {
    const close = vi.fn()
    mockRelay.connect.mockResolvedValue({
      publish: vi.fn().mockRejectedValue(new Error('write failed')),
      close,
    })

    await expect(
      publishKeytrEvent(fakeEvent(), ['wss://relay.example'])
    ).rejects.toThrow()

    expect(close).toHaveBeenCalled()
  })

  it('respects custom timeout', async () => {
    const publish = vi.fn().mockImplementation(
      () => new Promise((resolve) => setTimeout(resolve, 200))
    )
    const close = vi.fn()
    mockRelay.connect.mockResolvedValue({ publish, close })

    // 50ms timeout should cause rejection
    await expect(
      publishKeytrEvent(fakeEvent(), ['wss://slow-relay.example'], { timeout: 50 })
    ).rejects.toThrow()
  })
})

describe('fetchKeytrEvents', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('fetches events from a relay', async () => {
    const event = fakeEvent()
    const close = vi.fn()
    const subClose = vi.fn()

    mockRelay.connect.mockResolvedValue({
      subscribe: vi.fn().mockImplementation((_filters, callbacks) => {
        // Defer to match real relay async behavior (sub must be assigned first)
        queueMicrotask(() => {
          callbacks.onevent(event)
          callbacks.oneose()
        })
        return { close: subClose }
      }),
      close,
    })

    const result = await fetchKeytrEvents('deadbeef'.repeat(8), ['wss://relay.example'])

    expect(result).toHaveLength(1)
    expect(result[0]).toEqual(event)
    expect(close).toHaveBeenCalled()
  })

  it('deduplicates events across relays', async () => {
    const event = fakeEvent()
    const subClose = vi.fn()

    mockRelay.connect.mockResolvedValue({
      subscribe: vi.fn().mockImplementation((_filters, callbacks) => {
        queueMicrotask(() => {
          callbacks.onevent(event)
          callbacks.oneose()
        })
        return { close: subClose }
      }),
      close: vi.fn(),
    })

    const result = await fetchKeytrEvents('deadbeef'.repeat(8), [
      'wss://relay1.example',
      'wss://relay2.example',
    ])

    // Same event.id from two relays — should be deduplicated
    expect(result).toHaveLength(1)
  })

  it('collects different events from multiple relays', async () => {
    const event1 = fakeEvent({ id: 'event-1' })
    const event2 = fakeEvent({ id: 'event-2' })
    let callCount = 0

    mockRelay.connect.mockImplementation(async () => ({
      subscribe: vi.fn().mockImplementation((_filters, callbacks) => {
        const evt = callCount === 0 ? event1 : event2
        callCount++
        queueMicrotask(() => {
          callbacks.onevent(evt)
          callbacks.oneose()
        })
        return { close: vi.fn() }
      }),
      close: vi.fn(),
    }))

    const result = await fetchKeytrEvents('deadbeef'.repeat(8), [
      'wss://relay1.example',
      'wss://relay2.example',
    ])

    expect(result).toHaveLength(2)
  })

  it('returns empty array when all relays fail', async () => {
    mockRelay.connect.mockRejectedValue(new Error('connection refused'))

    const result = await fetchKeytrEvents('deadbeef'.repeat(8), ['wss://dead.example'])

    expect(result).toEqual([])
  })

  it('skips failing relays and collects from working ones', async () => {
    const event = fakeEvent()

    mockRelay.connect
      .mockRejectedValueOnce(new Error('timeout'))
      .mockResolvedValueOnce({
        subscribe: vi.fn().mockImplementation((_filters, callbacks) => {
          queueMicrotask(() => {
            callbacks.onevent(event)
            callbacks.oneose()
          })
          return { close: vi.fn() }
        }),
        close: vi.fn(),
      })

    const result = await fetchKeytrEvents('deadbeef'.repeat(8), [
      'wss://dead.example',
      'wss://good.example',
    ])

    expect(result).toHaveLength(1)
  })

  it('resolves on timeout when relay never sends EOSE', async () => {
    mockRelay.connect.mockResolvedValue({
      subscribe: vi.fn().mockImplementation((_filters, callbacks) => {
        // Send event but never EOSE
        callbacks.onevent(fakeEvent())
        return { close: vi.fn() }
      }),
      close: vi.fn(),
    })

    const result = await fetchKeytrEvents(
      'deadbeef'.repeat(8),
      ['wss://slow.example'],
      { timeout: 100 }
    )

    // Should still get the event after timeout resolves
    expect(result).toHaveLength(1)
  })
})

describe('fetchKeytrEventByDTag', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('fetches an event by d tag', async () => {
    const event = fakeEvent({ tags: [['d', 'my-cred-id'], ['rp', 'keytr.org']] })
    const subClose = vi.fn()

    mockRelay.connect.mockResolvedValue({
      subscribe: vi.fn().mockImplementation((filters, callbacks) => {
        // Verify the filter uses #d
        expect(filters[0]['#d']).toEqual(['my-cred-id'])
        queueMicrotask(() => {
          callbacks.onevent(event)
          callbacks.oneose()
        })
        return { close: subClose }
      }),
      close: vi.fn(),
    })

    const result = await fetchKeytrEventByDTag('my-cred-id', ['wss://relay.example'])
    expect(result).toEqual(event)
  })

  it('returns null when no event matches', async () => {
    mockRelay.connect.mockResolvedValue({
      subscribe: vi.fn().mockImplementation((_filters, callbacks) => {
        queueMicrotask(() => callbacks.oneose())
        return { close: vi.fn() }
      }),
      close: vi.fn(),
    })

    const result = await fetchKeytrEventByDTag('nonexistent', ['wss://relay.example'])
    expect(result).toBeNull()
  })

  it('returns the most recent event across relays', async () => {
    const older = fakeEvent({ id: 'old', created_at: 1700000000 })
    const newer = fakeEvent({ id: 'new', created_at: 1700001000 })
    let callCount = 0

    mockRelay.connect.mockImplementation(async () => ({
      subscribe: vi.fn().mockImplementation((_filters, callbacks) => {
        const evt = callCount === 0 ? older : newer
        callCount++
        queueMicrotask(() => {
          callbacks.onevent(evt)
          callbacks.oneose()
        })
        return { close: vi.fn() }
      }),
      close: vi.fn(),
    }))

    const result = await fetchKeytrEventByDTag('cred', [
      'wss://relay1.example',
      'wss://relay2.example',
    ])

    expect(result?.id).toBe('new')
  })

  it('returns null when all relays fail', async () => {
    mockRelay.connect.mockRejectedValue(new Error('connection refused'))

    const result = await fetchKeytrEventByDTag('cred', ['wss://dead.example'])
    expect(result).toBeNull()
  })
})
