# keytr Architecture

## The Problem

Nostr private key management is a major UX barrier. Users must manually copy their `nsec` between devices, risking exposure through clipboard, screenshots, or insecure storage. Hardware signers (NIP-46) add complexity. Browser extensions (NIP-07) don't sync across devices.

## The Solution

keytr uses **WebAuthn passkeys** — which already sync across devices via iCloud Keychain, Google Password Manager, etc. — to **encrypt your nsec** and publish the ciphertext to Nostr relays. Any device that has the synced passkey can decrypt it. No trusted server. No password to remember.

## Overview

```
User Device (nsec)
       │
       ▼
  Passkey PRF Extension ──► 32-byte deterministic output
       │
       ▼
  HKDF-SHA256 ──► 256-bit AES key
       │
       ▼
  AES-256-GCM ──► encrypted blob (93 bytes)
       │
       ▼
  kind:31777 Nostr event ──► published to relays
```

The system has four layers: **crypto**, **webauthn**, **nostr**, and **high-level flows**.

---

## Layer 1: Cryptography

### Key Derivation

The passkey's PRF extension outputs a raw 32-byte value. This is NOT used directly as an encryption key. Instead, it goes through HKDF-SHA256:

```
KEY = HKDF-SHA256(
  ikm    = PRF output       (32 bytes from authenticator)
  salt   = random(32)       (fresh per encryption, stored in blob)
  info   = "keytr nsec encryption v1"
  length = 32               (256-bit AES key)
)
```

The random salt means re-encrypting the same nsec with the same passkey produces **different ciphertext** every time. This prevents an observer from detecting re-encryption or key reuse.

Source: `src/crypto/kdf.ts`

### Encryption

Given the nsec bytes, PRF output, and credential ID:

1. Generate 12-byte random IV (AES-GCM nonce)
2. Generate 32-byte random HKDF salt
3. Derive AES-256 key via HKDF (above)
4. Build AAD: `"keytr" || version_byte || credentialId` — this binds the ciphertext to a specific credential and version (`0x01` for PRF; `0x03` is the reserved legacy KiH version, recognized only on the decrypt path), preventing substitution/downgrade/cross-version attacks
5. Encrypt: `AES-256-GCM(key, iv, nsec, aad)` → 48 bytes (32-byte nsec + 16-byte auth tag)
6. Serialize into a 93-byte blob, then base64-encode

Source: `src/crypto/encrypt.ts`

### Decryption

The reverse: base64-decode → deserialize → re-derive the same key using the stored HKDF salt → AES-GCM decrypt with reconstructed AAD → recover 32-byte nsec. If the wrong passkey or wrong credential ID is used, the AAD mismatch causes GCM to reject the ciphertext.

Source: `src/crypto/decrypt.ts`

### Blob Binary Format

```
Offset  Length  Field
0       1       Version byte (always 0x01 — blob format is identical for PRF and legacy KiH blobs)
1       12      IV (AES-GCM nonce)
13      32      HKDF salt
45      48      Ciphertext (32-byte nsec + 16-byte GCM auth tag)
────────────
Total: 93 bytes → ~124 base64 characters

Note: The blob version byte is always 0x01 (the binary format hasn't changed). PRF vs. legacy KiH is distinguished by the AAD version byte (0x01 vs 0x03) and the event's `v` tag — the 0x03 / `v=3` case only ever arises when decrypting an old KiH event.
```

`serializeBlob()` packs the `EncryptedNsecBlob` struct into this binary layout. `deserializeBlob()` unpacks it with validation (checks version, total length).

Source: `src/crypto/blob.ts`

---

## Layer 2: WebAuthn / Passkey Integration

### The PRF Extension

The critical piece. WebAuthn's PRF extension lets a passkey produce a **deterministic 32-byte output** given a fixed salt. keytr uses the salt `"keytr-v1"` (as an ArrayBuffer) for both registration and authentication. This salt is fixed by spec — it MUST NOT vary per user, because the PRF output must be reproducible on any device that has the synced passkey.

Key functions:

- `prfRegistrationExtension()` — builds the `extensions.prf` config for `navigator.credentials.create()`
- `prfAuthenticationExtension()` — builds it for `navigator.credentials.get()`
- `extractPrfOutput(extensionResults)` — pulls out `prf.results.first` (32 bytes)
- `isPrfEnabled(extensionResults)` — checks `prf.enabled === true`

Source: `src/webauthn/prf.ts`

### Legacy Key-in-Handle (KiH) — Decrypt-Only

KiH is a **removed** legacy scheme, not a current mode. It embedded a random 256-bit key directly in the passkey's `user.id` field:

```
user.id = [0x03 || random_key(32)]   — 33 bytes total
```

**KiH registration was removed in v0.8.0.** The encryption key stored in `user.id` is returned to the client as the `userHandle` during discoverable login, making it interceptable in JavaScript memory. `kihStrategy.register()` now throws `KihRegistrationDisabledError`. The remaining KiH code exists purely so existing credentials can still be **recognized and decrypted** during login and migration.

Mode detection is by `user.id` length:
- **32 bytes** → PRF (user.id is the raw 32-byte pubkey)
- **33 bytes, byte[0] === 0x03** → legacy KiH (user.id is mode byte + encryption key)

Decrypting a KiH event reuses the same pipeline (HKDF-SHA256 + AES-256-GCM); only the key source and AAD version byte (`0x03`) differ.

Key functions (decrypt/login only):
- `detectMode(userHandle)` — returns `'prf'` or `'kih'` based on length + prefix, and throws on a truncated `user.id`
- `extractKey(userHandle)` — returns the 32-byte key from bytes [1..33] of a legacy KiH `userHandle`

Source: `src/webauthn/kih.ts`

### Registration (PRF — the only registration path)

`registerPasskey(options)` does:

1. Validate the hex pubkey (64 hex chars), convert to bytes and set as `user.id` (32 bytes — enables discoverable login)
2. Generate random challenge
3. Build `CredentialCreationOptions`:
   - `rpId`: defaults to `"keytr.org"` (or custom domain)
   - Algorithms: ES256 (-7), RS256 (-257)
   - `authenticatorSelection`: resident key required, user verification required
   - `extensions`: PRF with salt `"keytr-v1"`
   - `hints`: optional authenticator routing (WebAuthn Level 3)
4. Call `navigator.credentials.create()` — via the native reference cached in `natives.ts`
5. Extract the 32-byte PRF output from `prf.results.first`. If not available (e.g., YubiKey reports `prf.enabled` but only returns output on assertion), perform an immediate follow-up assertion against the new credential to obtain it. If that *still* yields no PRF output, the credential is a PRF failure: the orphaned credential is cleaned up via `signalUnknownCredential()` (Signal API) and `PrfNotSupportedError` is thrown.
6. Extract credential ID (raw bytes + base64url), rpId, transports
7. Parse backup flags (BE/BS) from `authenticatorData` via `parseBackupFlags()`
8. Return `{ credential: KeytrCredential, keyMaterial: Uint8Array }` (`keyMaterial` = the 32-byte PRF output)

Source: `src/webauthn/register.ts`

### Registration (KiH) — removed

`kihStrategy.register()` throws `KihRegistrationDisabledError`. There is no KiH registration function and no `register-kih.ts` module. New passkeys are always PRF; KiH lives on only as a decrypt path (see above). There is no non-PRF fallback of any kind — if PRF is unavailable, registration fails.

### Authentication (Known Credential)

`authenticatePasskey(options)` does:

1. Build `CredentialRequestOptions`:
   - `rpId`: must match what was used at registration
   - Random challenge
   - `allowCredentials`: the specific credential ID from the event's `d` tag
   - `extensions`: PRF with salt `"keytr-v1"`
   - `hints`: optional authenticator routing
2. Call `navigator.credentials.get()` — triggers biometric/PIN
3. Extract 32-byte PRF output
4. Return the PRF output for decryption

Source: `src/webauthn/authenticate.ts`

### Authentication (Discoverable — unified PRF + legacy KiH)

`discoverPasskey(options?)` is the single unified discovery entry point (there is no separate `unifiedDiscover`). It auto-detects a PRF or a legacy KiH credential from the `userHandle`, and for PRF uses a **two-ceremony flow** to work around Safari iOS 18+ not returning PRF extension output on a discovery assertion (empty `allowCredentials`).

**Step 1 — Discovery (no PRF):**

1. Build `CredentialRequestOptions`:
   - `rpId`: defaults to `"keytr.org"`
   - Random challenge
   - `allowCredentials: []` — empty, so the browser shows all resident keys for this rpId
   - No PRF extension
   - Supports `mediation` option (`'conditional'` for passkey autofill)
2. Call the cached native `navigator.credentials.get()` — browser shows the passkey picker, user selects one
3. Read `userHandle` and `credentialId` (`rawId`), then `detectMode(userHandle)`:
   - `userHandle.length === 33 && userHandle[0] === 0x03` → **legacy KiH**: extract the key from bytes [1..33] and return immediately — **no step 2**. `pubkey` is not known yet (derived after decryption).
   - `userHandle.length === 32` → **PRF**: the userHandle *is* the pubkey (`hex(userHandle)`). Proceed to step 2.

**Step 2 — Targeted PRF assertion (PRF only):**

4. Build a second `CredentialRequestOptions` with the discovered credential ID in `allowCredentials` and the PRF extension (salt `"keytr-v1"`)
5. Call the cached native `get()`. Some browsers auto-approve without a second prompt; **Safari may show a second biometric prompt** (hence "up to two prompts").
6. Extract the 32-byte PRF output. If none is returned, throw `PrfNotSupportedError`.

Returns a `DiscoverResult`: `{ keyMaterial, credentialId, mode?, pubkey? }` — `mode` is `'prf'` or `'kih'`, and `pubkey` is set only for PRF. Note this internal `mode` field is on `DiscoverResult`; the high-level `discover()` result does **not** expose a `mode`.

Source: `src/webauthn/authenticate.ts`

### Support Detection

#### PRF detection

`checkPrfSupport()` checks:

- `window.PublicKeyCredential` exists
- Platform authenticator availability
- Uses `getClientCapabilities()` (Chrome 132+) for accurate PRF detection when available
- Falls back to optimistic reporting (full PRF detection is only possible at registration time)

Returns `{ supported: boolean, platformAuthenticator: boolean, reason?: string }`

Source: `src/webauthn/support.ts`

#### Comprehensive capability detection

`checkCapabilities()` returns a full `WebAuthnCapabilities` report:

- `webauthn` — whether WebAuthn is available
- `platformAuthenticator` — whether a platform authenticator exists
- `prf` — PRF support (`true`/`false`/`null` where null = requires credential creation to confirm)
- `conditionalMediation` — passkey autofill support
- `relatedOrigins` — cross-domain passkey use (federated gateways)
- `signalApi` — credential lifecycle management (Signal API)

Uses `PublicKeyCredential.getClientCapabilities()` (Chrome 132+) when available. Falls back to feature detection (`isConditionalMediationAvailable()`, `signalUnknownCredential` function presence).

Source: `src/webauthn/support.ts`

#### SSR guard

`ensureBrowser()` throws `WebAuthnError` immediately if `navigator.credentials.create` is not a function (Node.js, SSR environments). All WebAuthn functions call this internally.

Source: `src/webauthn/support.ts`

### Backup Flags

`parseBackupFlags(response)` extracts backup eligibility (BE) and backup state (BS) from `authenticatorData` byte 32:

- Bit 3 (0x08): **BE** — credential is eligible for multi-device sync
- Bit 4 (0x10): **BS** — credential is currently backed up

Returns `{ backupEligible: boolean, backupState: boolean }` or `undefined` if `getAuthenticatorData()` is unavailable.

Source: `src/webauthn/flags.ts`

### Signal API

WebAuthn Signal API wrappers (Chrome 132+) for credential lifecycle management. All are no-ops on unsupported browsers and return `boolean` indicating whether the signal was sent:

- `signalUnknownCredential(rpId, credentialId)` — tell authenticators a credential is unknown (may delete/deprioritize)
- `signalAllAcceptedCredentialIds(rpId, userId, credentialIds[])` — sync the full set of valid credentials for a user
- `signalCurrentUserDetails(rpId, userId, name, displayName)` — update user metadata shown in the passkey picker

Source: `src/webauthn/signal.ts`

---

## Layer 3: Nostr Integration

### Key Utilities

Wrappers around `nostr-tools/pure`:

- `generateNsec()` — random 32-byte private key
- `nsecToPublicKey()` / `nsecToHexPubkey()` — derive public key (bytes / hex)
- `encodeNsec()` / `decodeNsec()` — bech32 encode/decode with `nsec` prefix
- `encodeNpub()` / `decodeNpub()` — bech32 with `npub` prefix
- `nsecToNpub()` — convenience shortcut (nsec bytes → bech32 npub string)

Source: `src/nostr/keys.ts`

### Event Format

keytr uses **kind 31777** (parameterized replaceable event):

```json
{
  "kind": 31777,
  "pubkey": "<user's hex public key>",
  "content": "<base64-encoded encrypted blob>",
  "tags": [
    ["d", "<credential-id-base64url>"],
    ["rp", "<relying-party-id>"],
    ["algo", "aes-256-gcm"],
    ["kdf", "hkdf-sha256"],
    ["v", "1"],
    ["transports", "internal", "hybrid", "..."],
    ["client", "<client-name>"]
  ],
  "created_at": "<unix-timestamp>",
  "id": "...",
  "sig": "..."
}
```

### Tag Definitions

| Tag | Required | Description |
|-----|----------|-------------|
| `d` | Yes | Base64url-encoded WebAuthn credential ID. Makes this a parameterized replaceable event. |
| `rp` | Yes | WebAuthn Relying Party ID (domain). Clients need this to know which origin to use for decryption. |
| `algo` | Yes | Encryption algorithm. MUST be `aes-256-gcm`. |
| `kdf` | Yes | Key derivation function. MUST be `hkdf-sha256`. |
| `v` | Yes | Protocol version. `1` = PRF (current, the only specified mode). `3` = legacy KiH (decrypt-only, being removed). |
| `transports` | No | WebAuthn authenticator transports (e.g., `internal`, `hybrid`, `usb`, `ble`, `nfc`). |
| `client` | No | Name of the client that created this event. |

The `d` tag is the credential ID (base64url), making this a **parameterized replaceable event** — re-encrypting with the same passkey replaces the old event on relays.

Source: `src/nostr/event.ts`

### Relay Operations

- `publishKeytrEvent(signedEvent, relayUrls, options?)` — publishes to all relays in parallel via `Promise.allSettled()`; only throws if ALL relays fail
- `fetchKeytrEvents(pubkey, relayUrls, options?)` — queries all relays in parallel for kind:31777 events by author pubkey, deduplicates by event ID. Default 5-second timeout per relay.
- `fetchKeytrEventByDTag(dTag, relayUrls, options?)` — queries by `#d` tag (base64url credential ID). Used for KiH discoverable login where the pubkey isn't known upfront. Returns the most recent matching event.

All accept `RelayOptions` with a configurable `timeout` (milliseconds).

Source: `src/nostr/relay.ts`

---

## Layer 4: High-Level Flows

### Setup (PRF, no fallback)

```typescript
const result = await setup({
  userName: 'alice',
  userDisplayName: 'Alice',
  rpId: 'keytr.org',      // optional, defaults to keytr.org
  clientName: 'my-app',   // optional
  hints: ['client-device'],// optional, WebAuthn Level 3
})
// result: { credential, encryptedBlob, eventTemplate, nsecBytes, npub }
// NOTE: no `mode` field — PRF is the only registration mode.
```

`setup()` uses the default `prfStrategy` (pass `strategy` to override with a custom `KeyStrategy`). Internally:

1. Unless a custom `strategy` is supplied, `_assertPrfSupported()` runs `checkPrfSupport()` and throws `PrfNotSupportedError` early if PRF is unavailable — **there is no fallback**.
2. `generateNsec()` → 32-byte nsec; derive pubkey
3. `strategy.register({ pubkey, ... })` → `{ credential, keyMaterial }` (the PRF output)
4. `encryptNsec()` with AAD version `1`, then `buildKeytrEvent()` with the `v=1` tag
5. Zero `keyMaterial` via `safeZero()` (in a `finally` block)
6. Return `{ credential, encryptedBlob, eventTemplate, nsecBytes, npub }`

The caller is responsible for: signing the event with the nsec, publishing it to relays, and zeroing `nsecBytes` after use.

Source: `src/index.ts`

### `setupKeytr()` (lower-level PRF setup)

```typescript
const result = await setupKeytr({
  userName: 'alice',
  userDisplayName: 'Alice',
})
```

`setupKeytr()` is the same PRF setup with a slightly lower-level option shape (it accepts a `RegisterOptions & { clientName?, strategy? }`). It also defaults to `prfStrategy` and throws `PrfNotSupportedError` if PRF is unavailable. There is no separate "legacy PRF-only" path — PRF is now the only mode either helper uses.

Source: `src/index.ts`

### Backup Gateway Registration

```typescript
const bundle = await addBackupGateway(nsecBytes, {
  rpId: 'nostkey.org',
  rpName: 'nostkey.org',
  userName: npub,
  userDisplayName: 'Nostr User',
  clientName: 'my-app',
})
// bundle: { credential, encryptedBlob, eventTemplate }
```

Internally:

1. `nsecToHexPubkey(nsecBytes)` → hex pubkey
2. `strategy.register({ ...options, pubkey })` (default `prfStrategy`) → `{ credential, keyMaterial }` (triggers biometric)
3. `encryptNsec({ nsecBytes, keyMaterial, credentialId, version: 1 })` → base64 blob
4. Zero out `keyMaterial` via `safeZero()` (in `finally` block)
5. `buildKeytrEvent({ credential, encryptedBlob })` → unsigned event template
6. Return the bundle

Like `setup()`, it asserts PRF support up front (unless a custom `strategy` is passed). This is a separate action from setup — the user opts in when they want resilience against a gateway going down.

Source: `src/index.ts`

### Discoverable Login (No Prior State)

```typescript
const { nsecBytes, npub, pubkey } = await discover(
  ['wss://relay.damus.io'],
  { rpId: 'keytr.org' }
)
```

One call, no npub input needed. The result is `{ nsecBytes, npub, pubkey }` — **no `mode` field** (that lives only on the internal `DiscoverResult`). It handles both current PRF and legacy KiH credentials:

1. `strategy.discover({ rpId })` (default `prfStrategy` → `discoverPasskey`) → browser shows passkey picker, returns a `DiscoverResult`
   - Legacy KiH (33-byte userHandle): key extracted, done in 1 prompt, `pubkey` unset
   - PRF (32-byte userHandle): targeted PRF assertion (up to a 2nd Safari prompt), `pubkey` set
2. Fetch event:
   - PRF (has `pubkey`): `fetchKeytrEvents(pubkey, relays)` → match the event whose `d` tag equals the credential ID
   - KiH (no `pubkey`): `fetchKeytrEventByDTag(base64url(credentialId), relays)`
3. `decryptNsec({ encryptedBlob, keyMaterial, credentialId, version })` — `version` comes from the event's own `v` tag (`1` for PRF, `3` for KiH)
4. Derive pubkey from nsec; verify against the event author (integrity check — also guards the KiH `#d` path against cross-author d-tag collisions)
5. Zero out `keyMaterial` via `safeZero()` (in `finally` block)
6. Return `{ nsecBytes, npub, pubkey }`

There is no `discoverAndLogin()` export.

Source: `src/index.ts`

### Login with Known Pubkey

```typescript
const events = await fetchKeytrEvents(pubkey, relayUrls)
const { nsecBytes, npub } = await loginWithKeytr(events)
```

Accepts an **array** of kind:31777 events. Tries each event in order until a matching passkey succeeds. Each event is dispatched by its `v` tag, so this handles both PRF and legacy KiH credentials:

1. For each event:
   a. `parseKeytrEvent(event)` → extract credential ID, rpId, blob, `version`
   b. Pick the authenticate function by version: `authenticatePasskey` (PRF, `v=1`) or `kihAuthenticatePasskey` (legacy KiH, `v=3`). A custom `strategy` argument overrides this dispatch.
   c. Authenticate → 32-byte `keyMaterial` (triggers biometric)
   d. If the authenticator rejects (no matching credential), skip to the next event
   e. `decryptNsec({ encryptedBlob, keyMaterial, credentialId, version })` → 32-byte nsec
   f. Zero out `keyMaterial` via `safeZero()` (in `finally` block)
   g. Return `{ nsecBytes, npub }`
2. If no event succeeds, throw `WebAuthnError`

This flow is useful when the client already knows the pubkey (e.g., from localStorage or a URL parameter).

Source: `src/index.ts`

### Migration (legacy KiH → PRF)

```typescript
const { npub, pubkey, newEvent, deletionEvent, deletionPublished } =
  await migrateFromKih({
    relays: ['wss://relay.damus.io'],
    userName: 'alice',
    userDisplayName: 'Alice',
  })
```

`migrateFromKih(options: MigrateOptions)` upgrades an existing KiH credential to PRF. The ordering is load-bearing — nothing is deleted until the replacement is live:

1. `discoverPasskey()` with the old KiH passkey → decrypt the nsec. Throws if the selected passkey is already PRF (nothing to migrate).
2. Fetch the old `v=3` event by `#d`, and **verify** the decrypted pubkey matches the event author (mandatory — `#d` lookups are cross-author).
3. `registerPasskey()` a new PRF passkey for the same nsec (throws `PrfNotSupportedError` *before* any deletion if PRF is unavailable).
4. Encrypt under PRF (`v=1`), sign, and `publishKeytrEvent()` the new event. This must succeed on at least one relay before proceeding.
5. `buildKeytrDeletionEvent()` → a NIP-09 `kind:5` deletion (`a` tag `31777:<pubkey>:<old-d-tag>`, `k` tag `31777`, optional `e` tag), sign and publish. Soft-failure: `deletionPublished` is `false` if it landed on no relay (non-fatal — the new event is already live and KiH decrypt still works this release).
6. Unless `signalOldCredential === false`, `signalUnknownCredential()` retires the old credential from the passkey picker.

Returns a `MigrateResult` (`{ nsecBytes, npub, pubkey, newBundle, newEvent, deletionEvent, deletionPublished, oldCredentialId, oldDTag }`). The caller owns `nsecBytes` and must zero it.

Source: `src/migrate.ts`

---

## Federated Gateway Model

### The Problem

WebAuthn passkeys are bound to an **rpId** (a domain). A passkey created on `primal.net` won't produce a PRF output on `snort.social` — the domains don't match. Without a solution, every Nostr client would need its own passkey registration, defeating the purpose.

### The Solution: Related Origin Requests

WebAuthn's [Related Origin Requests](https://w3c.github.io/webauthn/#sctn-related-origins) spec lets a domain host a `/.well-known/webauthn` file declaring which origins are authorized:

```json
// https://keytr.org/.well-known/webauthn
{
  "origins": [
    "https://primal.net",
    "https://snort.social",
    "https://coracle.social"
  ]
}
```

A passkey registered with `rpId: "keytr.org"` on **any** listed origin produces the **same PRF output** on **every** listed origin. This means:

1. User registers a passkey on Primal → encrypted nsec event published
2. User opens Snort on a new device → Snort fetches the event, triggers the same passkey, gets the same PRF output → decrypts the nsec

### Federated, Not Centralized

There is no single gateway. Anyone can run one:

| Gateway | Operator | Authorized Origins |
|---------|----------|--------------------|
| `keytr.org` | sovIT | primal.net, coracle.social, ... |
| `passkey.nostr.com` | Community X | nostrudel.ninja, snort.social, ... |
| `keys.example.org` | Self-hosted | personal-client.example.org |

Users can register passkeys against **multiple gateways**, producing separate kind:31777 events for each. Losing access to one gateway doesn't affect events encrypted under other rpIds.

### Cross-Gateway Trust

The two official gateways — `keytr.org` (Cloudflare Pages) and `nostkey.org` (Hostinger) — trust each other via bidirectional Related Origin Requests. Each gateway's `/.well-known/webauthn` lists the other as an authorized origin:

```json
// https://keytr.org/.well-known/webauthn
{
  "origins": [
    "https://keytr.org",
    "https://nostkey.org",
    "https://bies.sovit.xyz",
    "https://gitvid.sovit.xyz",
    "https://nostrbook.net",
    "https://sovit.xyz"
  ]
}
```

```json
// https://nostkey.org/.well-known/webauthn
{
  "origins": [
    "https://nostkey.org",
    "https://keytr.org",
    "https://bies.sovit.xyz",
    "https://gitvid.sovit.xyz",
    "https://nostrbook.net",
    "https://sovit.xyz"
  ]
}
```

This means:

- A passkey registered with `rpId: "keytr.org"` can be used from `nostkey.org` (and vice versa)
- A passkey registered with either rpId can be used from any authorized client origin (bies, gitvid, nostrbook)
- The browser fetches the `.well-known/webauthn` file from the rpId domain and verifies the requesting origin is listed before allowing the WebAuthn ceremony

**Browser support**: Chrome 128+ (desktop and Android), Safari 18+ (iOS 18+, macOS Sequoia+).

### Adding a New Client Origin

To authorize a new Nostr client to use a gateway's passkeys:

1. Add the client's origin to the gateway's `/.well-known/webauthn` origins array
2. Deploy the updated file
3. The client can now call WebAuthn with the gateway's rpId

For the official gateways, submit a PR to [sovITxyz/keytr.org](https://github.com/sovITxyz/keytr.org) or [nostkey/nostkey.org](https://github.com/nostkey/nostkey.org).

### Standalone Mode

A client can skip gateways entirely and use its own domain as the rpId. Only that domain can decrypt. The `rp` tag in the event tells other clients which origin to visit if they want to attempt decryption.

### Recommended Strategy

1. Register against the primary gateway (`keytr.org`) during setup — **one biometric prompt**
2. Optionally register a backup gateway (`nostkey.org`) via `addBackupGateway()` — separate action, separate prompt
3. Support decryption of events under any rpId the client is authorized for

Related Origin Requests mean a single passkey on `keytr.org` already works from `nostkey.org` for day-to-day use. The backup gateway is for resilience — if `keytr.org` goes down, the browser can't fetch its `.well-known/webauthn`, so a separate credential on `nostkey.org` keeps the user's key accessible.

---

## Native & P2P Clients (No DNS)

### The Problem

The WebAuthn browser API requires HTTPS origins, DNS-resolvable rpIds, and `navigator.credentials`. Native runtimes like **Pear** (Holepunch's P2P application runtime) have none of these — apps are identified by public keys, distributed via Hypercore, and have no DNS or TLS.

### The Solution: CTAP2 Direct

Under the hood, browsers talk to authenticators via **CTAP2** (Client to Authenticator Protocol). The browser adds origin/DNS verification on top, but the authenticator itself doesn't enforce it. The rpId is just a string the authenticator hashes for credential scoping.

A native app can bypass the browser layer entirely:

```
Browser client:  navigator.credentials.get() → PRF extension  → PRF output
Native app:      libfido2 CTAP2 call         → hmac-secret    → same output
                                                                    │
                                              decrypt kind:31777 event
```

The authenticator doesn't know or care whether `"keytr.org"` resolves in DNS. It matches the rpId hash against stored credentials and returns the same HMAC output regardless of how the request arrived.

### What a Native Client Needs

1. **CTAP2 bindings** — `libfido2` (Yubico's C library) via N-API addon is the most proven path. For Pear/Bare runtime, this would be a native addon.
2. **Same rpId string** — use `"keytr.org"` (or whichever gateway) as a plain string parameter to the CTAP2 call.
3. **`hmac-secret` extension** — the CTAP2 wire-level equivalent of WebAuthn's PRF extension. Use the same salt (`"keytr-v1"`) to get byte-identical output.
4. **Everything else is the same** — the encrypted blob format, kind:31777 event structure, HKDF derivation, and AES-GCM decryption are all platform-agnostic. Only the authenticator communication layer differs.

### nostr-swarm Integration

[nostr-swarm](https://github.com/sovITxyz/nostr-swarm) is a fully P2P Nostr relay built on the Holepunch stack (Hyperswarm + Autobase + Hyperbee). It provides two access modes:

- **WebSocket**: Traditional Nostr clients connect via NIP-01 WebSocket
- **Hyperswarm direct**: Pear apps join the swarm topic and replicate the Autobase directly — no HTTP, no DNS, no WebSocket overhead

For keytr, this means a Pear app can:

1. **Fetch kind:31777 events** directly from the Hyperswarm-replicated event store — no relay URLs, no DNS lookups
2. **Authenticate via CTAP2** using `libfido2` with `rpId: "keytr.org"` + `hmac-secret` salt `"keytr-v1"`
3. **Decrypt the nsec** using the same blob format and crypto as browser clients
4. **Publish new events** (backup passkey registrations, re-encryptions) back to the swarm

The entire flow is DNS-free and server-free. Peers discover each other via DHT (`sha256("nostr-swarm:" + topic)`), and the Autobase ensures all peers converge on the same event set.

```
Pear app
  │
  ├── nostr-swarm (Hyperswarm) ── fetch/publish kind:31777 events
  │
  └── libfido2 (CTAP2) ── hmac-secret with rpId:"keytr.org"
        │
        └── decrypt nsec ── same blob format as browser clients
```

### Browser vs Native Comparison

| Concern | Browser (WebAuthn) | Native (CTAP2) |
|---------|--------------------|----------------|
| Authenticator API | `navigator.credentials` | `libfido2` / platform CTAP2 |
| PRF mechanism | `prf` extension | `hmac-secret` extension |
| rpId validation | Browser enforces DNS + origin | App passes string directly |
| Related Origins | `.well-known/webauthn` fetch | Not needed (no origin check) |
| Relay access | WebSocket to relay URLs | Hyperswarm direct or WebSocket |
| Event format | kind:31777 | kind:31777 (identical) |
| Crypto | Same (HKDF + AES-256-GCM) | Same |

### Security Considerations for Native Clients

Without the browser's origin enforcement, native clients take on responsibility for:

- **rpId integrity** — the app must use the correct rpId string. A malicious app could use any rpId to trigger credential lookup, but without the correct PRF salt and credential ID, decryption will fail (AAD mismatch).
- **User consent** — the authenticator still requires biometric/PIN for every operation. The user always approves.
- **Code trust** — users must trust the native app's code (same as any native key management tool). Pear apps are content-addressed by public key, providing a verifiable identity.

---

## Security Model

PRF (event/AAD version `v=1`) is the one and only current, specified encryption mode. The table below describes PRF; the last column notes how the retained **legacy KiH decrypt** path compares.

### Why not Key-in-Handle (KiH)?

keytr briefly experimented with a Key-in-Handle (KiH) mode that stored the AES key inside the passkey's `user.id`. It was withdrawn in v0.8.0 as too risky: that key material was returned to page JavaScript as `userHandle` on every login, where a compromised page (XSS, a malicious extension, or a compromised dependency) could read it and decrypt the published ciphertext offline. PRF keeps the key inside the authenticator, so it is never exposed to page scripts.

KiH now survives only as a decrypt-only path so existing `v=3` credentials can be recognized and migrated to PRF (see `migrateFromKih()` in Layer 4), and is being removed. See [SECURITY.md](../SECURITY.md) for the full advisory.

| Property | PRF (current) | Legacy KiH (decrypt-only, being removed) |
|----------|---------------|---------------------------|
| **Key source** | PRF output — hardware-bound, derived on-device, never stored in `user.id` | Random 256-bit key stored in `user.id`; returned as `userHandle` at login, so recoverable in JS memory |
| **Origin-bound** | PRF output tied to rpId | Passkey still bound to rpId; key only released on valid assertion |
| **AAD binding** | `"keytr" \|\| 0x01 \|\| credentialId` | `"keytr" \|\| 0x03 \|\| credentialId` — the version byte makes cross-version decryption impossible |
| **Unique ciphertexts** | Random IV + random HKDF salt | Same |
| **No server trust** | Relay is a dumb store, end-to-end encryption | Same |
| **Memory hygiene** | Key material + derived keys zeroed via `safeZero()` in `finally` blocks | Same |
| **Interception hardening** | WebAuthn calls use native refs cached at import (`natives.ts`); buffer ops use cached prototype methods (`builtins.ts`) — resists monkey-patching (POC-1) and prototype pollution (POC-3) | Same code path |
| **Passkey deletion** | Permanent loss if no backup | Same |
| **Registration** | Requires PRF extension (Chrome 116+, Safari 18+, etc.); **no fallback** | Disabled — `kihStrategy.register()` throws `KihRegistrationDisabledError` |

### Honest limitation: the decrypted nsec still lands in JS

PRF keeps the *encryption key* inside the authenticator, but the whole point of login is to hand the decrypted nsec back to the app so it can sign. keytr zeros its own copies via `safeZero()`, but it cannot protect a key it has returned: an attacker who has already compromised the app runtime (malicious dependency, XSS, hostile browser extension) can read the nsec while it is in memory. PRF is a meaningful improvement over KiH (the key is no longer sitting in `user.id`), and the `natives.ts`/`builtins.ts` hardening resists in-page interception of the *key material*, but neither makes keytr equivalent to a hardware signer that never releases the private key. Treat keytr as convenient, phishing-resistant, sync-friendly key storage — not as a signer isolation boundary.

### Password Fallback (Disabled)

The code exists in `src/fallback/password.ts` (scrypt + AES-256-GCM, NIP-49 compatible) but is **not exported** from the public API. Reason: password-encrypted blobs on relays can be brute-forced offline. Will be re-enabled only for local-only storage with entropy enforcement.

---

## Backup & Resilience

### The Problem

The passkey provides the **decryption key** (PRF output), but the **encrypted payload** (kind:31777 event) lives entirely on Nostr relays. If all relays purge the event, the user has a key with nothing to unlock — login fails permanently.

The encrypted event is **safe to store anywhere**. An attacker who obtains it cannot decrypt without the passkey's PRF output, which requires physical access to the authenticator plus biometric/PIN. This means backup options are wide open without compromising security.

### Backup Layers

Resilience comes from layering multiple independent backup strategies. No single layer is sufficient on its own.

| Layer | Where | User action | Protects against |
|-------|-------|-------------|------------------|
| Relay redundancy | Multiple Nostr relays | None (automatic) | Single relay failure |
| Multi-gateway | Separate rpId events | One biometric prompt per gateway | Gateway domain loss |
| Client-side cache | localStorage / IndexedDB | None (automatic) | Relay purge (same device) |
| Event export | JSON file or QR code | User saves file | Relay purge (any device) |
| HTTP fallback | Gateway well-known endpoint | None (automatic) | Complete relay network failure |

### Relay Redundancy (Existing)

`publishKeytrEvent()` already publishes to multiple relays in parallel. Only throws if **all** relays fail — partial success is acceptable. Clients should publish to at least 3-5 relays and fetch from all known relays during login.

This is the first line of defense but not a guarantee. Relays can purge data, go offline, or reject parameterized replaceable events they don't understand.

### Multi-Gateway Registration (Existing)

`addBackupGateway()` registers the same nsec under a different gateway (e.g., `nostkey.org` if primary is `keytr.org`). Each gateway produces a separate kind:31777 event with its own credential ID and rpId. If one gateway's domain becomes unreachable (breaking Related Origin Requests), events encrypted under the other gateway's rpId still work.

### Client-Side Event Cache (Recommended for Clients)

Clients should cache the kind:31777 event(s) in `localStorage` or `IndexedDB` after every successful login or registration. On subsequent logins, check the local cache **before** querying relays:

```
1. Check localStorage/IndexedDB for cached kind:31777 events
2. If found → attempt decryption with passkey
3. If not found or decryption fails → fetch from relays
4. After successful relay fetch → update local cache
```

### Event Export (Recommended for Clients)

Clients should offer an export function that lets users save their signed kind:31777 event(s) as a portable backup. The signed event is ~500-800 bytes of JSON — small enough for JSON file, QR code, or copy/paste.

On recovery, the client imports the event JSON and either decrypts directly using the passkey (no relay needed), or re-publishes to relays and proceeds with normal login.

### HTTP Fallback (Optional for Gateway Operators)

Gateway operators can serve kind:31777 events at a well-known HTTP endpoint:

```
GET https://keytr.org/.well-known/nostr/k1/<hex-pubkey>
```

Simple HTTP GET, no Nostr protocol. Clients that fail to find events on relays can try this endpoint before giving up.

### WebAuthn largeBlob (Roadmap)

The WebAuthn `largeBlob` extension allows storing auxiliary data directly inside a passkey credential. The ideal end-state: store the signed kind:31777 event inside the passkey itself — one passkey carries both the decryption key and the encrypted payload. No relay, no file, no external storage.

Currently blocked on ecosystem adoption — Google Password Manager and Windows Hello don't support largeBlob. See [roadmap.md](roadmap.md) for details.

### Recommended Client Implementation

Clients integrating keytr should implement backup in this priority order:

1. **Always**: Publish to multiple relays (already handled by `publishKeytrEvent()`)
2. **Always**: Cache events locally after successful login/registration
3. **Recommended**: Offer event export (JSON download or QR code)
4. **Optional**: Prompt users to register a backup gateway via `addBackupGateway()`
5. **Optional**: If gateway operator, serve events at a well-known HTTP endpoint

### What keytr Does NOT Do

- **No plaintext nsec export** — exporting the raw nsec defeats the purpose of passkey-based key management
- **No seed phrase / mnemonic** — the passkey IS the portable secret
- **No server-side key escrow** — the nsec never leaves the client unencrypted

---

## Known Issues

### Password Manager Extensions Intercepting WebAuthn

Browser extensions from password managers — **Bitwarden**, **1Password**, **Dashlane**, and others — can intercept `navigator.credentials.create()` and `navigator.credentials.get()` calls. These extensions register their own WebAuthn handler to offer passkey management through the password manager rather than the browser's native passkey UI.

**Note**: As of early 2026, 1Password and Bitwarden support PRF, and Dashlane has PRF in beta. However, these extensions may still not support Related Origin Requests, which is the issue described here.

The problem: most password manager extensions **do not support Related Origin Requests**. When keytr calls `navigator.credentials.get()` with `rpId: "keytr.org"` from an authorized client origin like `bies.sovit.xyz`, the browser would normally fetch `keytr.org/.well-known/webauthn` and verify the origin. But if a password manager extension intercepts the call first, it applies its own origin validation — which typically requires an exact match between the requesting origin and the rpId. Since `bies.sovit.xyz !== keytr.org`, the extension rejects the request.

This affects **all cross-origin flows** — any client using a gateway rpId different from its own domain will fail when these extensions are active.

#### Workarounds for Users

- **Disable the password manager's WebAuthn/passkey integration** in the extension settings. The browser's native passkey support will handle the ceremony correctly.
  - Bitwarden: Settings → Options → disable "Enable passkey management"
  - 1Password: Settings → Autofill and save → disable "Passkeys"
  - Dashlane: Settings → Autofill → disable "Passkey support"
- **Use the extension's allow-list** if available to exclude keytr gateway domains from interception.
- **Use a browser profile without password manager extensions** for Nostr clients that rely on keytr passkeys.

#### Recommendations for Client Developers

See [Integration Guide: Error Handling](integration-guide.md#error-handling) for detection patterns and user-facing error messages.

#### Long-Term Outlook

Password manager vendors are gradually adding PRF and Related Origin Request support. As adoption grows, this issue will diminish. In the meantime, client-side error detection and user guidance are the best mitigation.

---

## Error Hierarchy

All errors extend `KeytrError`:

```
KeytrError
├── PrfNotSupportedError          — authenticator doesn't support PRF (registration cannot proceed — no fallback)
├── KihRegistrationDisabledError  — KiH registration attempted (removed in v0.8.0)
├── EncryptionError               — AES-GCM encryption failed
├── DecryptionError               — wrong passkey or corrupted blob
├── BlobParseError                — invalid binary format
├── WebAuthnError                 — navigator.credentials call failed
└── RelayError                    — all relays failed to publish/fetch
```

Source: `src/errors.ts`

---

## Constants

```
KEYTR_VERSION      = 1          // AAD/event version for PRF (the default)
KEYTR_KIH_VERSION  = 3          // AAD/event version for legacy KiH (decrypt-only)
BLOB_VERSION       = 1          // binary blob format version (same for both)
KEYTR_EVENT_KIND   = 31777
DELETION_EVENT_KIND = 5         // NIP-09 kind:5 (retire migrated KiH events)
PRF_SALT           = UTF-8("keytr-v1")
HKDF_INFO          = "keytr nsec encryption v1"
DEFAULT_RP_ID      = "keytr.org"
DEFAULT_RP_NAME    = "keytr"
KEYTR_GATEWAYS     = ["keytr.org", "nostkey.org"]
PRF_USER_ID_SIZE   = 32         // Pubkey in PRF user.id
KIH_KEY_SIZE       = 32         // Legacy KiH random key size in bytes
KIH_USER_ID_SIZE   = 33         // Legacy KiH user.id: 0x03 + 32-byte key
KIH_MODE_BYTE      = 0x03       // Legacy KiH user.id prefix byte
```

Note: `KIH_KEY_SIZE` / `KIH_USER_ID_SIZE` / `KIH_MODE_BYTE` were renamed from the old `KEY_SIZE` / `USER_ID_SIZE` / `MODE_BYTE`.

Source: `src/types.ts`

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `@noble/ciphers` | AES-256-GCM |
| `@noble/hashes` | HKDF-SHA256, SHA256, CSPRNG |
| `@scure/base` | Base64, Base64url, Bech32 |
| `nostr-tools` | Key generation, relay connections |

All crypto libraries are from the `@noble`/`@scure` family (audited, pure JS, no native dependencies).

---

## Project Structure

```
src/
├── index.ts              — public API: prfStrategy/kihStrategy, setup/discover, setupKeytr, addBackupGateway, loginWithKeytr
├── migrate.ts            — migrateFromKih() (legacy KiH → PRF + kind:5 deletion)
├── types.ts              — interfaces, constants, KeyStrategy
├── errors.ts             — error classes (incl. KihRegistrationDisabledError)
├── crypto/
│   ├── encrypt.ts        — encryptNsec() + buildAad()
│   ├── decrypt.ts        — decryptNsec()
│   ├── kdf.ts            — deriveKey() via HKDF
│   ├── blob.ts           — serialize/deserialize 93-byte blob
│   └── builtins.ts       — cached Uint8Array methods: safeSlice/safeSet/safeZero (POC-3)
├── webauthn/
│   ├── register.ts       — registerPasskey() (PRF)
│   ├── authenticate.ts   — authenticatePasskey(), kihAuthenticatePasskey(), discoverPasskey() (unified)
│   ├── kih.ts            — detectMode(), extractKey() (legacy KiH decrypt-only)
│   ├── prf.ts            — PRF extension helpers
│   ├── natives.ts        — native navigator.credentials refs cached at import (POC-1)
│   ├── support.ts        — checkPrfSupport() + checkCapabilities() + ensureBrowser()
│   ├── flags.ts          — parseBackupFlags()
│   └── signal.ts         — Signal API wrappers
├── nostr/
│   ├── keys.ts           — nsec/npub encode/decode
│   ├── event.ts          — build/parse kind:31777 (v=1 PRF, v=3 KiH) + buildKeytrDeletionEvent()
│   └── relay.ts          — publish/fetch events + fetchKeytrEventByDTag()
└── fallback/
    └── password.ts       — disabled password encryption
```

(KiH registration was removed — there is no `register-kih.ts`.)
