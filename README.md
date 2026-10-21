# keytr

Passkey login for Nostr. Encrypt your nsec with a WebAuthn passkey, publish to relays, decrypt on any device. Implements [NIP-K1](NIP-K1.md).

## How it works

Register a passkey, encrypt your nsec, publish the ciphertext to Nostr relays. On any device with the synced passkey, tap to decrypt — no npub input needed, no localStorage, no manual key copying.

keytr derives the encryption key from the authenticator's **WebAuthn PRF extension** — a deterministic 32-byte secret that never leaves the hardware. The raw 32-byte Nostr public key is stored in the passkey's `user.id`, which enables discoverable login: the browser returns the pubkey via `userHandle` when the user picks a passkey, so keytr can fetch and decrypt the matching event with no prior state.

```
Passkey PRF → HKDF-SHA256 → AES-256-GCM → kind:31777 (v=1) → relay
```

**PRF is required — there is no fallback.** An authenticator without the PRF extension (Firefox on Android, some older security keys, and password-manager extensions that don't expose PRF to keytr) cannot register: `setup()` throws `PrfNotSupportedError`. keytr ships no password or local-only fallback, so this is a deliberate compatibility trade-off — see [Compatibility](#compatibility).

> **History — the withdrawn KiH mode.** keytr briefly experimented with a Key-in-Handle (KiH) mode that stored the AES key inside the passkey's `user.id`. It was **withdrawn in v0.8.0 as too risky**: that key material was returned to page JavaScript as `userHandle` on every login, where a compromised page (XSS, a malicious extension, or a compromised dependency) could read it and decrypt the published ciphertext offline. PRF keeps the key inside the authenticator, so it is never exposed to page scripts. Existing KiH credentials (`v=3` events) can still log in and should upgrade with [`migrateFromKih()`](#migration-legacy-kih--prf); KiH decryption is retained only for that migration and will be removed in a future release.

Cross-client login works via a [federated gateway model](docs/architecture.md#federated-gateway-model) — any domain can authorize a set of Nostr clients to share passkey access using WebAuthn [Related Origin Requests](https://w3c.github.io/webauthn/#sctn-related-origins). The two official gateways (`keytr.org` on Cloudflare, `nostkey.org` on Hostinger) trust each other bidirectionally, so a passkey registered under either rpId works on both sites and all authorized client origins.

## Documentation

- [Architecture & System Design](docs/architecture.md) — detailed walkthrough of every layer: crypto, WebAuthn, Nostr integration, federated gateways, security model
- [Integration Guide](docs/integration-guide.md) — how to wire keytr into a Nostr client's auth flow, session restore, and credential management
- [Roadmap](docs/roadmap.md) — current state and future direction
- [NIP-K1 Specification](NIP-K1.md) — the canonical protocol spec (PRF `v=1` is the only specified mode; legacy KiH `v=3` retained decrypt-only for migration)

## Typed recovery (draft)

Applications can use the proposed `setupPayload`, `unlockPayload` and `discoverPayload` APIs to transport an encrypted seed or multi-account vault. Existing private-key flows stay unchanged. Payload types and application schemas are authenticated; applications must agree on a schema to restore each other’s data. See the [wire format and integration examples](docs/typed-recovery.md).

## Passkey-held Nostr keys (draft)

`setupStored()` and `discoverStored()` read and write the stored-mode format of the [Passkey-held Nostr keys](<SPEC_URL>) proposal (`npk1`): tagged handles and records holding a key, a seed or a vault. Passkeys that derive their key directly, or that keytr cannot identify, are refused with `PasskeyModeError` instead of becoming a new empty identity. See [Passkey key modes](docs/passkey-key-modes.md).

## Install

```bash
npm install @sovit.xyz/keytr
```

## Quick start

### Setup (new user)

```typescript
import { setup, publishKeytrEvent } from '@sovit.xyz/keytr'
import { finalizeEvent } from 'nostr-tools/pure'

// Registers a PRF passkey. Throws PrfNotSupportedError if the authenticator
// lacks the PRF extension — there is no fallback.
const { credential, encryptedBlob, eventTemplate, nsecBytes, npub } = await setup({
  userName: 'alice',
  userDisplayName: 'Alice',
})

// Sign and publish
const signedEvent = finalizeEvent(eventTemplate, nsecBytes)
await publishKeytrEvent(signedEvent, ['wss://relay.damus.io'])
```

The `setup()` result has no `mode` field — PRF is the only registration mode.

### Login (discoverable — no npub needed)

```typescript
import { discover } from '@sovit.xyz/keytr'

// Browser shows passkeys, user picks one. keytr recovers the pubkey from the
// userHandle, fetches the event, and decrypts. On Safari a PRF login may show
// up to two prompts (discovery + a targeted PRF assertion); legacy KiH
// credentials are auto-detected and complete in one prompt.
const { nsecBytes, npub, pubkey } = await discover(
  ['wss://relay.damus.io'],
  { rpId: 'keytr.org' }
)
```

### Login (known pubkey)

```typescript
import { loginWithKeytr, fetchKeytrEvents } from '@sovit.xyz/keytr'

const events = await fetchKeytrEvents(pubkey, ['wss://relay.damus.io'])
const { nsecBytes, npub } = await loginWithKeytr(events)
```

`loginWithKeytr()` dispatches each event by its `v` tag — `v=1` authenticates with PRF, `v=3` with the legacy KiH path — so it can log in existing KiH credentials too.

### Migration (legacy KiH → PRF)

Users with an old KiH passkey (a `v=3` event) should upgrade to PRF:

```typescript
import { migrateFromKih } from '@sovit.xyz/keytr'

const { npub, pubkey, newEvent, deletionPublished } = await migrateFromKih({
  relays: ['wss://relay.damus.io'],
  userName: 'alice',
  userDisplayName: 'Alice',
})
```

`migrateFromKih()` logs in with the old KiH passkey, re-encrypts the nsec under a new PRF passkey, publishes the new `v=1` event, then publishes a NIP-09 `kind:5` deletion (`a` tag `31777:<pubkey>:<old-d-tag>`) to retire the old KiH event. The new event is published *before* anything is deleted; the deletion is best-effort (`deletionPublished` reports whether it landed).

The lower-level `setupKeytr()` and `addBackupGateway()` helpers are also available; both use the PRF strategy by default.

## Module exports

keytr provides four entry points for tree-shaking and selective imports:

| Export | Path | Contents |
|--------|------|----------|
| Main | `@sovit.xyz/keytr` | High-level API + re-exports from all modules |
| Crypto | `@sovit.xyz/keytr/crypto` | `encryptNsec`, `decryptNsec`, `deriveKey`, `serializeBlob`, `deserializeBlob`, `buildAad` |
| WebAuthn | `@sovit.xyz/keytr/webauthn` | `registerPasskey`, `authenticatePasskey`, `kihAuthenticatePasskey`, `discoverPasskey`, `checkPrfSupport`, `checkCapabilities`, `ensureBrowser`, PRF helpers, KiH decrypt helpers (`extractKey`, `detectMode`), Signal API, backup flags |
| Nostr | `@sovit.xyz/keytr/nostr` | Key utilities, event building/parsing, relay operations |

## Compatibility

keytr requires [discoverable credentials](https://w3c.github.io/webauthn/#client-side-discoverable-credential) **and** the [PRF extension](https://w3c.github.io/webauthn/#prf-extension). PRF is the only registration mode and there is **no fallback** — any browser or authenticator that can't provide PRF output to keytr simply cannot register (`setup()` throws `PrfNotSupportedError`). Rows below marked **Not supported** are the compatibility cost of dropping the old KiH fallback.

### Browsers

| Browser | Min Version | Registration (PRF) | Discoverable Login | Notes |
|---------|-------------|--------------------|--------------------|-------|
| Chrome (Desktop) | 116+ | Yes | Yes | |
| Chrome (Android) | 116+ | Yes | Yes | |
| Edge | 116+ | Yes | Yes | Chromium-based |
| Safari | 18+ | Yes | Yes | PRF login may show up to two prompts (discovery + targeted PRF assertion) |
| Firefox | 122+ | Yes | Yes | |
| Firefox (Android) | — | **Not supported** | — | No PRF extension; no fallback |

### Authenticators

| Authenticator | Registration (PRF) | Notes |
|---------------|--------------------|-------|
| iCloud Keychain | Yes | macOS 15+ / iOS 18+ |
| Google Password Manager | Yes | Android 14+ / Chrome 116+ |
| Windows Hello | Yes | Windows 11 25H2+ (Feb 2026 update) |
| YubiKey 5 (firmware 5.7+) | Yes | PRF via `hmac-secret` bridge |
| YubiKey 5 (firmware < 5.7) | **Not supported** | No PRF; no fallback |
| 1Password | Caveat | PRF supported in Chromium browsers, but the extension's WebAuthn interception can still block keytr's cross-origin gateway registration |
| Bitwarden | Caveat | PRF since 2026.1.1 (Chromium), same cross-origin interception caveat |
| Dashlane | **Not supported** | PRF still in beta; treat as unavailable |
| Older security keys (no PRF) | **Not supported** | No PRF; no fallback |

> **Password-manager browser extensions** (Bitwarden, 1Password, Dashlane) are the most common cause of registration failure. Even where they support PRF, they intercept `navigator.credentials.*` and frequently reject keytr's gateway `rpId` (Related Origin Requests) or don't expose PRF output — in which case registration is impossible with no fallback. See [Architecture: Password Manager Extensions](docs/architecture.md#password-manager-extensions-intercepting-webauthn).

### Federated gateways

Cross-client login via [Related Origin Requests](https://w3c.github.io/webauthn/#sctn-related-origins) requires additional browser support:

| Browser | Related Origins | Min Version |
|---------|-----------------|-------------|
| Chrome | Yes | 128+ |
| Edge | Yes | 128+ |
| Safari | Yes | 18+ |
| Firefox | No | Positive standards position (March 2026); no implementation timeline |

### Capability detection

Use `checkPrfSupport()` to gate the passkey UI before calling `setup()` (which throws `PrfNotSupportedError` when PRF is unavailable), or `checkCapabilities()` for a comprehensive report including PRF, conditional mediation, Related Origins, and Signal API support. Because there is no fallback, checking PRF support up front lets you show a clear "your device can't use passkey login" message instead of surfacing a thrown error.

```typescript
import { checkCapabilities } from '@sovit.xyz/keytr'

const caps = await checkCapabilities()
// caps.prf              — true/false/null (null = unknown, requires credential creation to confirm)
// caps.conditionalMediation — passkey autofill support
// caps.relatedOrigins   — cross-domain passkey use (federated gateways)
// caps.signalApi        — credential lifecycle management
```

Uses `PublicKeyCredential.getClientCapabilities()` (Chrome 132+) when available, falls back to feature detection.

### Conditional UI (passkey autofill)

Pass `mediation: 'conditional'` to `discover()` or `discoverPasskey()` for passkey autofill instead of the modal picker. Requires `<input autocomplete="webauthn">` in the DOM:

```typescript
const { nsecBytes, pubkey } = await discover(relays, {
  mediation: 'conditional',  // passkey suggestions appear in the input field
})
```

### Credential lifecycle (Signal API)

Tell authenticators to clean up revoked or stale passkeys (Chrome 132+). No-ops on unsupported browsers:

```typescript
import { signalUnknownCredential, signalAllAcceptedCredentialIds } from '@sovit.xyz/keytr'

// User deleted their passkey — tell authenticators to remove it
await signalUnknownCredential('keytr.org', credentialId)

// Sync the full set of valid credentials for a user
await signalAllAcceptedCredentialIds('keytr.org', userId, [credId1, credId2])
```

### Backup eligibility

After registration, `KeytrCredential` includes backup flags from `authenticatorData`:

```typescript
const { credential } = await setup({ ... })
if (credential.backupEligible === false) {
  console.warn('This passkey is device-bound and will not sync across devices')
}
```

### SSR safety

All WebAuthn functions throw `WebAuthnError` immediately in non-browser environments (Node.js, SSR). Use `ensureBrowser()` for explicit pre-checks in SSR frameworks:

```typescript
import { ensureBrowser } from '@sovit.xyz/keytr'

try { ensureBrowser() } catch { /* render fallback UI */ }
```

## Security properties

| Property | PRF (the only registration mode) |
|----------|----------------------------------|
| **Hardware-bound key** | PRF output requires the authenticator + user verification; the secret never leaves the hardware and is not stored in `user.id` |
| **Origin-bound** | Different domains get different PRF output; the passkey is bound to its `rpId` |
| **AAD-bound** | `"keytr" \|\| 0x01 \|\| credentialId` — binds ciphertext to the credential and version |
| **Version isolation** | The AAD version byte prevents a legacy KiH (`0x03`) blob decrypting as PRF and vice-versa |
| **No server trust** | The relay is a dumb store; encryption is end-to-end |
| **Memory hygiene** | Key material and derived keys are zeroed via `safeZero` in `finally` blocks after use |
| **Interception hardening** | All WebAuthn calls route through native references cached at import time (`natives.ts`), and buffer ops use cached prototype methods (`builtins.ts`), resisting monkey-patching / prototype-pollution attacks |

**Honest limitation.** PRF keeps the *encryption key* hardware-bound, but the decrypted nsec is still returned to your JavaScript so it can sign events. keytr zeros its own copies, but it cannot protect a key it has handed back: an attacker who has already compromised the app's runtime (malicious dependency, XSS, hostile extension) can read the nsec while it is in memory. PRF raises the bar over the removed KiH mode (the key is no longer sitting in `user.id`), but it is not a substitute for a hardware signer that never releases the private key.

The legacy KiH mode stored the encryption key as a random 256-bit value inside `user.id`, which was extractable in JS memory — that is why KiH registration was removed in v0.8.0. KiH decryption remains only so existing credentials can log in and migrate, and will be removed in a future release.

## License

AGPL-3.0-or-later
