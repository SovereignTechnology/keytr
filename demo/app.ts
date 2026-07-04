import { finalizeEvent } from 'nostr-tools/pure'
import {
  checkPrfSupport,
  setup,
  discover,
  addBackupGateway,
  migrateFromKih,
  decodeNsec,
  encodeNsec,
  publishKeytrEvent,
  PrfNotSupportedError,
  KEYTR_GATEWAYS,
} from '../src/index.js'

// keytr is PRF-only: a PRF-capable authenticator is required to register.
// Legacy Key-in-Handle (KiH) credentials can still log in and be migrated,
// but there is NO password/local fallback.
const PRF_UNSUPPORTED_MSG =
  'This authenticator/browser does not support the WebAuthn PRF extension, ' +
  'which keytr requires. Try a different device or browser.'

// The rpId determines which clients can decrypt. On localhost we let the
// library fall back to its default gateway (keytr.org); on a real deployment
// we bind to the current hostname.
const rpId = location.hostname === 'localhost' ? undefined : location.hostname

// DOM helpers
const $ = (id: string) => document.getElementById(id)!
const supportCheck = $('support-check')
const setupSection = $('setup-section')
const loginSection = $('login-section')
const migrateSection = $('migrate-section')
const logEl = $('log')

function log(msg: string, type: 'info' | 'success' | 'error' = 'info') {
  const entry = document.createElement('div')
  entry.className = `entry ${type}`
  entry.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`
  logEl.prepend(entry)
}

function getRelays(): string[] {
  return ($('relays') as HTMLTextAreaElement).value
    .split('\n')
    .map((r) => r.trim())
    .filter(Boolean)
}

const val = (id: string) => ($(id) as HTMLInputElement).value.trim()

function disableRegistration(): void {
  ;($('btn-setup') as HTMLButtonElement).disabled = true
  ;($('btn-migrate') as HTMLButtonElement).disabled = true
  ;($('btn-backup') as HTMLButtonElement).disabled = true
}

function showUnsupported(msg: string): void {
  supportCheck.innerHTML = `
    <h2 class="support-no">PRF not available</h2>
    <p>${msg}</p>
  `
  disableRegistration()
}

// Check support on load
async function init() {
  log('Checking WebAuthn PRF support...')

  // Reveal the sections regardless — login (discover) works for legacy KiH
  // credentials even where PRF registration is unavailable.
  setupSection.classList.remove('hidden')
  loginSection.classList.remove('hidden')
  migrateSection.classList.remove('hidden')

  const support = await checkPrfSupport()

  if (support.supported) {
    supportCheck.innerHTML = `
      <h2 class="support-ok">Passkey PRF supported</h2>
      <p>Platform authenticator: ${support.platformAuthenticator ? 'Yes' : 'No'}</p>
    `
    log('PRF support detected', 'success')
  } else {
    showUnsupported(support.reason ? `${PRF_UNSUPPORTED_MSG} (${support.reason})` : PRF_UNSUPPORTED_MSG)
    log(`PRF not supported: ${support.reason ?? 'unknown'}`, 'error')
  }
}

// Setup: generate a new nsec, register a PRF passkey, publish the event
$('btn-setup').addEventListener('click', async () => {
  try {
    const userName = val('setup-username') || 'keytr-user'
    const userDisplayName = val('setup-displayname') || 'Nostr User'
    log('Starting passkey registration...')

    const result = await setup({
      rpId,
      rpName: 'keytr',
      userName,
      userDisplayName,
      clientName: 'keytr-demo',
    })
    log(`Passkey registered — ${result.npub}`, 'success')

    // Sign the event template with the freshly generated nsec, then publish.
    const signed = finalizeEvent(result.eventTemplate, result.nsecBytes)
    const relays = getRelays()
    log(`Publishing kind:31777 event to ${relays.length} relay(s)...`)
    await publishKeytrEvent(signed, relays)
    log('Event published to relays', 'success')

    $('result-npub').textContent = result.npub
    $('result-blob').textContent = result.encryptedBlob
    $('result-event').textContent = JSON.stringify(signed, null, 2)
    $('setup-result').classList.remove('hidden')

    // Pre-fill the backup nsec so a backup gateway can be added immediately.
    ;($('backup-nsec') as HTMLInputElement).value = encodeNsec(result.nsecBytes)

    $('btn-copy-event').onclick = () => {
      navigator.clipboard.writeText(JSON.stringify(signed, null, 2))
      log('Event JSON copied to clipboard', 'success')
    }
  } catch (err) {
    if (err instanceof PrfNotSupportedError) {
      log(PRF_UNSUPPORTED_MSG, 'error')
      showUnsupported(PRF_UNSUPPORTED_MSG)
    } else {
      log(`Setup failed: ${(err as Error).message}`, 'error')
    }
  }
})

// Backup gateway: register a second passkey on nostkey.org for an existing nsec
$('btn-backup').addEventListener('click', async () => {
  try {
    const nsecInput = val('backup-nsec')
    if (!nsecInput) {
      log('Enter an nsec to back up (run setup first, or paste your own)', 'error')
      return
    }

    const nsecBytes = decodeNsec(nsecInput)
    const backupRpId = KEYTR_GATEWAYS[1] // nostkey.org
    log(`Registering backup passkey on ${backupRpId}...`)

    const bundle = await addBackupGateway(nsecBytes, {
      rpId: backupRpId,
      rpName: backupRpId,
      userName: val('setup-username') || 'keytr-user',
      userDisplayName: val('setup-displayname') || 'Nostr User',
      clientName: 'keytr-demo',
    })

    const signed = finalizeEvent(bundle.eventTemplate, nsecBytes)
    nsecBytes.fill(0)

    const relays = getRelays()
    log(`Publishing backup event to ${relays.length} relay(s)...`)
    await publishKeytrEvent(signed, relays)

    $('backup-event').textContent = JSON.stringify(signed, null, 2)
    $('backup-result').classList.remove('hidden')
    log(`Backup passkey registered on ${backupRpId}`, 'success')
  } catch (err) {
    if (err instanceof PrfNotSupportedError) {
      log(PRF_UNSUPPORTED_MSG, 'error')
    } else {
      log(`Backup registration failed: ${(err as Error).message}`, 'error')
    }
  }
})

// Login: discoverable passkey — pick a passkey, fetch the event, decrypt
$('btn-login').addEventListener('click', async () => {
  try {
    const relays = getRelays()
    if (relays.length === 0) {
      log('Add at least one relay', 'error')
      return
    }

    log('Waiting for passkey selection...')
    const result = await discover(relays, rpId ? { rpId } : undefined)

    const nsec = encodeNsec(result.nsecBytes)
    result.nsecBytes.fill(0)

    $('login-npub').textContent = result.npub
    $('login-pubkey').textContent = result.pubkey
    $('login-nsec').textContent = nsec
    $('login-result').classList.remove('hidden')

    log(`Logged in as ${result.npub}`, 'success')
  } catch (err) {
    log(`Login failed: ${(err as Error).message}`, 'error')
  }
})

// Migrate: upgrade a legacy KiH credential to PRF
$('btn-migrate').addEventListener('click', async () => {
  try {
    const relays = getRelays()
    if (relays.length === 0) {
      log('Add at least one relay', 'error')
      return
    }

    log('Starting KiH → PRF migration... pick your legacy passkey when prompted')
    const result = await migrateFromKih({
      relays,
      rpId,
      userName: val('migrate-username') || 'keytr-user',
      userDisplayName: val('migrate-displayname') || 'Nostr User',
      clientName: 'keytr-demo',
    })
    result.nsecBytes.fill(0)

    $('migrate-npub').textContent = result.npub
    $('migrate-deletion').textContent = result.deletionPublished ? 'Yes' : 'No (non-fatal)'
    $('migrate-event').textContent = JSON.stringify(result.newEvent, null, 2)
    $('migrate-result').classList.remove('hidden')

    log(`Migrated to PRF — ${result.npub}`, 'success')
    if (!result.deletionPublished) {
      log('Old KiH event deletion did not publish to every relay (non-fatal)', 'info')
    }
  } catch (err) {
    if (err instanceof PrfNotSupportedError) {
      log(PRF_UNSUPPORTED_MSG, 'error')
    } else {
      log(`Migration failed: ${(err as Error).message}`, 'error')
    }
  }
})

init()
