# keytr Roadmap

## Current State: NIP-K1 (v0.8.0)

keytr implements NIP-K1 — passkey-encrypted private keys. A user's nsec is encrypted with a passkey and published to Nostr relays as a kind:31777 event. Any device with the synced passkey can decrypt it in one biometric tap.

**What's shipping today:**
- Full NIP-K1 implementation (encrypt, decrypt, event publish/fetch)
- **PRF-only registration**: `prfStrategy` (the default) is the one and only registration mode — the encryption key is the authenticator's PRF output, never stored in `user.id`; the raw pubkey goes in `user.id` for discoverable login (AAD/event `v=1`)
- **No fallback**: authenticators without PRF cannot register — `setup()` throws `PrfNotSupportedError`. There is no password or local fallback. This is a deliberate compatibility trade-off (Firefox Android, older security keys, and some password-manager extensions can no longer register)
- **KiH is a withdrawn experiment, now decrypt-only**: keytr briefly experimented with a Key-in-Handle (KiH) mode that stored the AES key in the passkey's `user.id`, but withdrew it in v0.8.0 as too risky — that key material was returned to page JavaScript as `userHandle` on every login, where a compromised page (XSS, a malicious extension, or a compromised dependency) could read it and decrypt the published ciphertext offline, whereas PRF keeps the key inside the authenticator so it is never exposed to page scripts. `kihStrategy.register()` throws `KihRegistrationDisabledError`; existing KiH (`v=3`) credentials can still log in via `discover()`/`loginWithKeytr()` and should migrate
- **Migration**: `migrateFromKih()` logs in with the old KiH passkey, re-encrypts under a new PRF passkey, publishes the new `v=1` event, then publishes a NIP-09 `kind:5` deletion to retire the old KiH event
- **Pluggable `KeyStrategy` interface**: `setup()`/`discover()`/`loginWithKeytr()` accept a custom `strategy`; `prfStrategy` and `kihStrategy` are the built-ins
- **Security hardening**: WebAuthn calls route through native references cached at import (`natives.ts`, resists monkey-patching); buffer ops use cached prototype methods and zero key material via `safeZero()` (`builtins.ts`, resists prototype pollution)
- **Discoverable login** (no prior pubkey needed); PRF login runs two ceremonies (up to two prompts on Safari), legacy KiH stays one
- Parallel relay operations
- Cross-gateway support via Related Origin Requests
- YubiKey compatibility (PRF assertion fallback on registration)
- Federated gateways: keytr.org + nostkey.org
- **Comprehensive capability detection** via `checkCapabilities()` (`getClientCapabilities()` on Chrome 132+, feature detection fallback); `checkPrfSupport()` restored for gating the passkey UI
- **Conditional UI** (passkey autofill) via `mediation: 'conditional'` option
- **WebAuthn Signal API** for credential lifecycle management (`signalUnknownCredential`, `signalAllAcceptedCredentialIds`, `signalCurrentUserDetails`)
- **Backup eligibility flags** (BE/BS from `authenticatorData`) on `KeytrCredential`
- **WebAuthn Level 3 hints** parameter for authenticator routing
- **SSR safety** — all WebAuthn functions throw early in non-browser environments
- **user.id truncation detection** — clear errors when authenticators truncate the userHandle

---

## Next Breaking Change: Remove KiH Decryption

**Status**: Planned

KiH registration was removed in v0.8.0; KiH decryption remains only as a migration on-ramp. The next planned breaking milestone removes the KiH decrypt path entirely:

- Delete `kihStrategy`, `kihAuthenticatePasskey`, the KiH helpers (`detectMode`/`extractKey`), and the `v=3` branch in `loginWithKeytr()`/`discover()`.
- Remove the KiH constants (`KIH_KEY_SIZE`, `KIH_USER_ID_SIZE`, `KIH_MODE_BYTE`) and the KiH decrypt spec from NIP-K1 (leaving only PRF `v=1`).
- After this release, unmigrated `v=3` events become unreadable by keytr.

**Before it lands:** clients should surface `migrateFromKih()` to any user still on a `v=3` credential (see the [integration guide](integration-guide.md#migrating-legacy-kih-users)). A deprecation window will run first so users can migrate; the exact release is TBD and will be called out in the changelog.

---

## Backup & Resilience Enhancements

### Problem

K1 stores the encrypted nsec on Nostr relays. If all relays purge the kind:31777 event, the user has a working passkey but nothing to decrypt — login fails permanently. The encrypted event is safe to store anywhere (can't be decrypted without the passkey's PRF output), so the mitigation is redundant storage across independent layers.

See [architecture.md — Backup & Resilience](architecture.md#backup--resilience) for the full design and current backup layers (relay redundancy, multi-gateway, client cache, event export, HTTP fallback).

### WebAuthn largeBlob — Self-Contained Passkey Recovery

**Status**: Blocked on ecosystem adoption

The ideal end-state: store the signed kind:31777 event inside the passkey itself via the WebAuthn `largeBlob` extension. One passkey carries both the decryption key (PRF) and the encrypted payload. No relay, no file, no external storage.

**Current compatibility (as of March 2026):**

| Authenticator | largeBlob | Notes |
|---|---|---|
| YubiKey 5 (firmware 5.7+) | Yes | CTAP 2.1, max 4096 bytes |
| iCloud Keychain | Yes | Since iOS 17 / macOS Sonoma / Safari 17 |
| Google Password Manager | **No** | Supports PRF but not largeBlob |
| Windows Hello | **No** | No largeBlob support |
| 1Password | **No** | Supports PRF but not largeBlob |
| Bitwarden | **No** | Supports PRF but not largeBlob |
| Dashlane | **No** | PRF in beta; no largeBlob support |

| Browser | largeBlob | Notes |
|---|---|---|
| Chrome | Yes | Depends on authenticator support |
| Safari 17+ | Yes | Only with iCloud Keychain |
| Firefox | Unclear | PRF support added in 122+, largeBlob not confirmed |

Google Password Manager + Windows Hello = majority of passkey users. Until they add largeBlob, this can't be a relied-upon layer.

**Implementation plan (when adoption is sufficient):**

1. At registration: detect `largeBlob` support via `getClientExtensionResults()`
2. If supported: write the signed kind:31777 event JSON into the credential's largeBlob
3. At login: if relay fetch returns no events, attempt `largeBlob` read before giving up
4. Never depend on it — treat as an opportunistic bonus layer alongside existing backups

### Client-Side Cache & Event Export

**Status**: Ready to implement

These don't require any new WebAuthn features — they're client-side patterns that any keytr integration can adopt today:

- **Local cache**: Store kind:31777 events in localStorage/IndexedDB after login; check before relay fetch
- **Event export**: Let users download the signed event as JSON or QR code for offline recovery

These should be documented as recommended patterns in the integration guide and optionally provided as helper utilities in the library.

### HTTP Fallback Endpoint

**Status**: Design phase

Gateway operators (keytr.org, nostkey.org) could serve events at:

```
GET https://keytr.org/.well-known/nostr/k1/<hex-pubkey>
```

Simple HTTP GET, no Nostr protocol. Clients try this after relay fetch fails. Requires gateway-side infrastructure to ingest and serve kind:31777 events.

---

## Exploratory: NIP-K2 — Passseeds

A draft spec exists at `nip/nip-k2.md` exploring **passseeds** — deterministic key derivation from passkeys. Instead of encrypting an existing nsec, the passkey PRF output would be the seed that derives the nsec. No relay needed for key material.

This is a potential direction we may explore in the future, not a planned feature. The draft spec is retained for reference only.

### Concept

K1 works well for users who already have a Nostr identity or need relay-backed recovery. K2 could simplify onboarding for new users by removing the need to generate, encrypt, and publish an nsec — register a passkey, derive an identity, done.

### Open Questions

Many fundamental design decisions remain unresolved:

- Should new users default to K2 or K1?
- Should K2 auto-create a K1 backup event (adding relay dependency)?
- Should marker events be published (metadata leak vs cross-client discovery)?
- How should clients handle users with both K1 and K2 credentials?
- Naming: the public API naming should communicate "your passkey becomes your key" without jargon

NIP-K1 is the focus. K2 would only be considered after K1 is mature and battle-tested.

## Draft: typed recovery

An opt-in [seed and vault payload proposal](typed-recovery.md) is available for protocol and API review. Wire version, schema interoperability and real-provider integration still need agreement and testing before treating this as a deployed ecosystem standard.
