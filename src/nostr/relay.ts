import { base64urlnopad } from '@scure/base'
import type { Filter } from 'nostr-tools/filter'
import { Relay } from 'nostr-tools/relay'
import type { Event } from 'nostr-tools/core'
import { KEYTR_EVENT_KIND } from '../types.js'
import { RelayError } from '../errors.js'

/** Options for relay operations */
export interface RelayOptions {
  /** Connection/operation timeout in milliseconds. Defaults to 5000 (5 seconds). */
  timeout?: number
}

async function connectWithTimeout(url: string, timeout: number): Promise<Relay> {
  return Promise.race([
    Relay.connect(url),
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`Connect to ${url} timed out`)), timeout)
    ),
  ])
}

/** Publish a signed keytr event to one or more relays */
export async function publishKeytrEvent(
  event: Event,
  relayUrls: string[],
  options?: RelayOptions
): Promise<void> {
  const timeout = options?.timeout ?? 5000

  const results = await Promise.allSettled(
    relayUrls.map(async (url) => {
      const relay = await connectWithTimeout(url, timeout)
      try {
        await Promise.race([
          relay.publish(event),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error('Publish timed out')), timeout)
          ),
        ])
      } finally {
        relay.close()
      }
    })
  )

  const errors = results
    .map((r, i) => (r.status === 'rejected' ? `${relayUrls[i]}: ${r.reason.message}` : null))
    .filter((e): e is string => e !== null)

  if (errors.length === relayUrls.length) {
    throw new RelayError(`Failed to publish to any relay:\n${errors.join('\n')}`)
  }
}

/** Fetch all kind:31777 events for a given pubkey from relays */
export async function fetchKeytrEvents(pubkey: string, relayUrls: string[], options?: RelayOptions): Promise<Event[]> {
  return fetchEvents([{ kinds: [KEYTR_EVENT_KIND], authors: [pubkey] }], relayUrls, options)
}

export async function fetchStoredEvents(pubkey: string, credentialId: Uint8Array, relayUrls: string[], options?: RelayOptions): Promise<Event[]> {
  const id = base64urlnopad.encode(credentialId)
  return fetchEvents([
    { kinds: [31778], authors: [pubkey], '#d': [`${id}:key`, `${id}:vault`] },
    { kinds: [KEYTR_EVENT_KIND], authors: [pubkey], '#d': [`${id}:key`, `${id}:vault`, `${id}:seed`] },
  ], relayUrls, options)
}

async function fetchEvents(filters: Filter[], relayUrls: string[], options?: RelayOptions): Promise<Event[]> {
  const timeout = options?.timeout ?? 5000

  const results = await Promise.allSettled(
    relayUrls.map(async (url) => {
      const relay = await connectWithTimeout(url, timeout)
      try {
        return await new Promise<Event[]>((resolve) => {
          const collected: Event[] = []
          const sub = relay.subscribe(
            filters,
            {
              onevent(evt) {
                collected.push(evt)
              },
              oneose() {
                sub.close()
                resolve(collected)
              },
            }
          )
          setTimeout(() => {
            sub.close()
            resolve(collected)
          }, timeout)
        })
      } finally {
        relay.close()
      }
    })
  )

  const seen = new Set<string>()
  const events: Event[] = []
  for (const result of results) {
    if (result.status === 'fulfilled') {
      for (const event of result.value) {
        if (!seen.has(event.id)) {
          seen.add(event.id)
          events.push(event)
        }
      }
    }
  }

  return events
}

/**
 * Fetch a kind:31777 event by its #d tag (base64url credential ID).
 * Used for KiH mode where we don't have the pubkey upfront.
 * Returns the first matching event, or null if none found.
 */
export async function fetchKeytrEventByDTag(
  dTag: string,
  relayUrls: string[],
  options?: RelayOptions
): Promise<Event | null> {
  const timeout = options?.timeout ?? 5000

  const results = await Promise.allSettled(
    relayUrls.map(async (url) => {
      const relay = await connectWithTimeout(url, timeout)
      try {
        return await new Promise<Event | null>((resolve) => {
          let found: Event | null = null
          const sub = relay.subscribe(
            [{ kinds: [KEYTR_EVENT_KIND], '#d': [dTag] }],
            {
              onevent(evt) {
                // Take the most recent (replaceable events: last write wins)
                if (!found || evt.created_at > found.created_at) {
                  found = evt
                }
              },
              oneose() {
                sub.close()
                resolve(found)
              },
            }
          )
          setTimeout(() => {
            sub.close()
            resolve(found)
          }, timeout)
        })
      } finally {
        relay.close()
      }
    })
  )

  // Return the most recent event across all relays
  let best: Event | null = null
  for (const result of results) {
    if (result.status === 'fulfilled' && result.value) {
      if (!best || result.value.created_at > best.created_at) {
        best = result.value
      }
    }
  }

  return best
}
