import { finalizeEvent } from 'nostr-tools/pure'
import type { Event } from 'nostr-tools/core'
import { base64url } from '@scure/base'
import type { DiscoverOptions, KeytrBundle } from './types.js'
import type { RelayOptions } from './nostr/relay.js'
import { DEFAULT_RP_ID, KEYTR_VERSION, KEYTR_KIH_VERSION } from './types.js'
import { KeytrError, PrfNotSupportedError } from './errors.js'
import { discoverPasskey } from './webauthn/authenticate.js'
import { registerPasskey } from './webauthn/register.js'
import { signalUnknownCredential } from './webauthn/signal.js'
import { encryptNsec } from './crypto/encrypt.js'
import { decryptNsec } from './crypto/decrypt.js'
import { buildKeytrEvent, buildKeytrDeletionEvent, parseKeytrEvent } from './nostr/event.js'
import { fetchKeytrEventByDTag, publishKeytrEvent } from './nostr/relay.js'
import { nsecToHexPubkey, nsecToNpub } from './nostr/keys.js'
import { safeZero } from './crypto/builtins.js'

/** Options for migrating a legacy KiH credential to PRF */
export interface MigrateOptions {
  /** Relays to fetch the old event from and publish the new event + deletion to */
  relays: string[]
  /** Gateway rpId of the old credential (and the new one). Defaults to keytr.org. */
  rpId?: string
  /** Relying Party display name for the new passkey. */
  rpName?: string
  /** Username metadata for the NEW PRF passkey */
  userName: string
  /** Display name metadata for the NEW PRF passkey */
  userDisplayName: string
  /** Optional client name tag on the new event */
  clientName?: string
  /** WebAuthn ceremony timeout in milliseconds */
  timeout?: number
  /** WebAuthn Level 3 hints */
  hints?: string[]
  /** Mediation for the discovery (login) ceremony */
  mediation?: DiscoverOptions['mediation']
  /** Relay operation options (timeout) */
  relayOptions?: RelayOptions
  /** kind:5 deletion reason (content). */
  deletionReason?: string
  /** Signal the old KiH credential as unknown after migrating. Defaults to true. */
  signalOldCredential?: boolean
}

/** Result of a successful KiH → PRF migration */
export interface MigrateResult {
  nsecBytes: Uint8Array
  npub: string
  pubkey: string
  /** The new PRF credential + unsigned template (for app bookkeeping) */
  newBundle: KeytrBundle
  /** The signed, published kind:31777 (v=1) event */
  newEvent: Event
  /** The signed kind:5 deletion event (publish attempted) */
  deletionEvent: Event
  /** false if the kind:5 deletion failed to publish to every relay (non-fatal) */
  deletionPublished: boolean
  /** Raw credential ID of the retired KiH credential */
  oldCredentialId: Uint8Array
  /** base64url d-tag of the retired KiH event */
  oldDTag: string
}

const DEFAULT_DELETION_REASON = 'Migrated keytr credential from KiH (v3) to PRF (v1)'

/**
 * Migrate an existing legacy KiH credential to PRF.
 *
 * Flow (with the two load-bearing invariants):
 *   1. Discoverable login with the existing KiH passkey → decrypt the nsec.
 *   2. Verify the decrypted pubkey matches the old event author (mandatory —
 *      d-tag lookups are cross-author).
 *   3. Register a NEW PRF passkey for the same nsec.
 *   4. Encrypt under PRF (v=1), sign, and publish the new event. This must
 *      succeed on at least one relay BEFORE anything is deleted.
 *   5. Publish a NIP-09 kind:5 deletion for the old KiH event (soft-failure:
 *      the new event is already live and KiH decrypt still works this release).
 *   6. Optionally signal the old credential as unknown.
 *
 * The returned nsecBytes is owned by the caller (zero it when done). Throws
 * PrfNotSupportedError (before any deletion) if the authenticator lacks PRF.
 */
export async function migrateFromKih(options: MigrateOptions): Promise<MigrateResult> {
  const rpId = options.rpId ?? DEFAULT_RP_ID
  const relayOptions = options.relayOptions

  // 1. Sign in with the existing (KiH) passkey.
  const discovered = await discoverPasskey({
    rpId,
    timeout: options.timeout,
    mediation: options.mediation,
    hints: options.hints,
  })

  if (discovered.mode === 'prf' || discovered.pubkey) {
    safeZero(discovered.keyMaterial)
    throw new KeytrError('Selected passkey is already a PRF credential — nothing to migrate')
  }

  const oldCredentialId = discovered.credentialId
  const oldDTag = base64url.encode(oldCredentialId)

  // 2. Fetch + decrypt the old KiH event.
  const oldEvent = await fetchKeytrEventByDTag(oldDTag, options.relays, relayOptions)
  if (!oldEvent) {
    safeZero(discovered.keyMaterial)
    throw new KeytrError(`No keytr event found for credential ${oldDTag}`)
  }

  const oldParsed = parseKeytrEvent(oldEvent)
  if (oldParsed.version !== KEYTR_KIH_VERSION) {
    safeZero(discovered.keyMaterial)
    throw new KeytrError(
      `Event ${oldDTag} is version ${oldParsed.version}, not a legacy KiH (v${KEYTR_KIH_VERSION}) event`
    )
  }

  let nsecBytes: Uint8Array
  try {
    nsecBytes = decryptNsec({
      encryptedBlob: oldParsed.encryptedBlob,
      keyMaterial: discovered.keyMaterial,
      credentialId: oldCredentialId,
      version: KEYTR_KIH_VERSION,
    })
  } finally {
    safeZero(discovered.keyMaterial)
  }

  const pubkey = nsecToHexPubkey(nsecBytes)
  const npub = nsecToNpub(nsecBytes)

  // Mandatory integrity check: the decrypted key must own the old event.
  if (oldEvent.pubkey && oldEvent.pubkey !== pubkey) {
    safeZero(nsecBytes)
    throw new KeytrError(
      'Decrypted nsec does not match event author pubkey — possible tampering; migration aborted'
    )
  }

  // 3. Register a new PRF passkey for the same nsec.
  let newBundle: KeytrBundle
  try {
    const { credential, keyMaterial: newKey } = await registerPasskey({
      rpId,
      rpName: options.rpName,
      userName: options.userName,
      userDisplayName: options.userDisplayName,
      pubkey,
      timeout: options.timeout,
      hints: options.hints,
    })

    try {
      // 4a. Encrypt under PRF + build the new event template.
      const encryptedBlob = encryptNsec({
        nsecBytes,
        keyMaterial: newKey,
        credentialId: credential.credentialId,
        version: KEYTR_VERSION,
      })
      const eventTemplate = buildKeytrEvent({
        credential,
        encryptedBlob,
        clientName: options.clientName,
        version: KEYTR_VERSION,
      })
      newBundle = { credential, encryptedBlob, eventTemplate }
    } finally {
      safeZero(newKey)
    }
  } catch (err) {
    // No PRF passkey was created / usable — abort without deleting anything.
    safeZero(nsecBytes)
    if (err instanceof PrfNotSupportedError) throw err
    throw err
  }

  // 4b. Sign + publish the NEW event FIRST. If it fails everywhere, abort
  // before touching the old event.
  const newEvent = finalizeEvent(newBundle.eventTemplate, nsecBytes)
  try {
    await publishKeytrEvent(newEvent, options.relays, relayOptions)
  } catch (err) {
    safeZero(nsecBytes)
    throw err
  }

  // 5. Publish a NIP-09 deletion for the old KiH event (soft failure).
  const deletionTemplate = buildKeytrDeletionEvent({
    pubkey,
    dTag: oldDTag,
    eventId: oldEvent.id,
    reason: options.deletionReason ?? DEFAULT_DELETION_REASON,
  })
  const deletionEvent = finalizeEvent(deletionTemplate, nsecBytes)
  let deletionPublished = true
  try {
    await publishKeytrEvent(deletionEvent, options.relays, relayOptions)
  } catch {
    deletionPublished = false
  }

  // 6. Optionally retire the old credential from the passkey picker.
  if (options.signalOldCredential !== false) {
    await signalUnknownCredential(oldParsed.rpId, oldCredentialId)
  }

  return {
    nsecBytes,
    npub,
    pubkey,
    newBundle,
    newEvent,
    deletionEvent,
    deletionPublished,
    oldCredentialId,
    oldDTag,
  }
}
