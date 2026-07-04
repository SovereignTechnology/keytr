import { base64url } from '@scure/base'
import { KEYTR_EVENT_KIND, KEYTR_VERSION, DELETION_EVENT_KIND, type KeytrEventTemplate, type KeytrCredential } from '../types.js'
import { KeytrError } from '../errors.js'

interface BuildEventOptions {
  credential: KeytrCredential
  encryptedBlob: string
  clientName?: string
  /** AAD version byte. Defaults to KEYTR_VERSION. Strategies may override. */
  version?: number
}

/** Build an unsigned kind:31777 event template for a passkey-encrypted nsec */
export function buildKeytrEvent(options: BuildEventOptions): KeytrEventTemplate {
  const { credential, encryptedBlob, clientName } = options

  const tags: string[][] = [
    ['d', credential.credentialIdBase64url],
    ['rp', credential.rpId],
    ['algo', 'aes-256-gcm'],
    ['kdf', 'hkdf-sha256'],
    ['v', String(options.version ?? KEYTR_VERSION)],
  ]

  if (credential.transports.length > 0) {
    tags.push(['transports', ...credential.transports])
  }

  if (clientName) {
    tags.push(['client', clientName])
  }

  return {
    kind: KEYTR_EVENT_KIND,
    content: encryptedBlob,
    tags,
    created_at: Math.floor(Date.now() / 1000),
  }
}

/** A NIP-09 deletion request event template (before signing) */
export interface DeletionEventTemplate {
  kind: typeof DELETION_EVENT_KIND
  content: string
  tags: string[][]
  created_at: number
}

/**
 * Build an unsigned NIP-09 (kind:5) deletion request for a kind:31777 event.
 *
 * Addressable events are deleted by their coordinate `a` tag
 * (`31777:<pubkey>:<d-tag>`); relays remove all versions up to the deletion's
 * created_at. An optional `e` tag (the specific event id) is included as a
 * belt-and-braces hint for relays that don't index `a` tags.
 *
 * Used by migrateFromKih() to retire the old KiH event after the new PRF
 * event is published.
 */
export function buildKeytrDeletionEvent(options: {
  /** Hex-encoded author pubkey (owner of the event being deleted) */
  pubkey: string
  /** base64url credential ID (the `d` tag) of the event to delete */
  dTag: string
  /** Optional specific event id to also reference via an `e` tag */
  eventId?: string
  /** Optional human-readable reason (kind:5 content) */
  reason?: string
}): DeletionEventTemplate {
  const { pubkey, dTag, eventId, reason } = options

  const tags: string[][] = [
    ['a', `${KEYTR_EVENT_KIND}:${pubkey}:${dTag}`],
    ['k', String(KEYTR_EVENT_KIND)],
  ]
  if (eventId) {
    tags.push(['e', eventId])
  }

  return {
    kind: DELETION_EVENT_KIND,
    content: reason ?? '',
    tags,
    created_at: Math.floor(Date.now() / 1000),
  }
}

export interface ParsedKeytrEvent {
  credentialIdBase64url: string
  credentialId: Uint8Array
  rpId: string
  encryptedBlob: string
  version: number
  algorithm: string
  kdf: string
  transports: string[]
  clientName?: string
}

/** Parse a kind:31777 event to extract credential info and encrypted blob */
export function parseKeytrEvent(event: {
  kind: number
  content: string
  tags: string[][]
}): ParsedKeytrEvent {
  if (event.kind !== KEYTR_EVENT_KIND) {
    throw new KeytrError(`Expected kind ${KEYTR_EVENT_KIND}, got ${event.kind}`)
  }

  const getTag = (name: string): string | undefined =>
    event.tags.find(t => t[0] === name)?.[1]

  const credentialIdBase64url = getTag('d')
  if (!credentialIdBase64url) {
    throw new KeytrError('Missing "d" tag (credential ID)')
  }

  const rpId = getTag('rp')
  if (!rpId) {
    throw new KeytrError('Missing "rp" tag')
  }

  const version = parseInt(getTag('v') ?? String(KEYTR_VERSION), 10)
  const algorithm = getTag('algo') ?? 'aes-256-gcm'
  const kdf = getTag('kdf') ?? 'hkdf-sha256'

  const transportsTag = event.tags.find(t => t[0] === 'transports')
  const transports = transportsTag ? transportsTag.slice(1) : []

  const clientName = getTag('client')

  let credentialId: Uint8Array
  try {
    credentialId = base64url.decode(credentialIdBase64url)
  } catch {
    throw new KeytrError('Invalid credential ID encoding in "d" tag')
  }

  return {
    credentialIdBase64url,
    credentialId,
    rpId,
    encryptedBlob: event.content,
    version,
    algorithm,
    kdf,
    transports,
    clientName,
  }
}
