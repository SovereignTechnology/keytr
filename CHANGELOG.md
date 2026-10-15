# Changelog

## Unreleased

- Add draft PRF-encrypted seed/vault payload APIs with authenticated type/schema metadata and separate event coordinates, preserving existing single-key recovery.

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## [0.8.0] - 2026-07-03

**PRF is now the only registration mode. Key-in-Handle (KiH) registration has been removed.**

### Security
- **KiH key material was interceptable in JavaScript.** In KiH mode the 32-byte AES key was stored in the passkey `user.id` and returned to the page as `userHandle` on every login. Any script running in the page's origin (via XSS, a malicious browser extension, or a compromised dependency) could read that key material during a login/registration and decrypt the user's public `kind:31777` (`v=3`) blob offline. This is **not** exploitable from relay data alone — a genuine build never publishes key material — and requires code execution on the victim's page. PRF mode keeps the key inside the authenticator, eliminating this interception vector (note: the decrypted nsec is still returned to the app, so a compromised page can always read the key once decrypted — see SECURITY.md).
- All WebAuthn calls route through native references captured at import time (`natives.ts`), and key buffers are zeroed via prototype-pollution-resistant helpers (`builtins.ts`).

### Breaking
- **KiH registration removed.** `kihStrategy.register()` throws `KihRegistrationDisabledError`. `generateUserId()` was removed. The PRF strategy (`prfStrategy`) is the default for `setup`, `setupKeytr`, `addBackupGateway`, `discover`, and `loginWithKeytr`.
- **PRF-only, no fallback.** Authenticators without PRF (password-manager extensions, Firefox Android, some older security keys) now fail registration with `PrfNotSupportedError`. There is no password/local fallback.
- `KEYTR_VERSION` is now `1` (PRF). Legacy KiH is `KEYTR_KIH_VERSION` (`3`). Bare `encryptNsec`/`decryptNsec`/`buildAad` calls that omit `version` now default to `1`; pass `version: KEYTR_KIH_VERSION` for legacy blobs.
- `RegisterOptions.pubkey` (hex, stored as `user.id`) is required again for the low-level `registerPasskey`. The high-level helpers derive and thread it for you.
- Constants `KEY_SIZE`/`USER_ID_SIZE`/`MODE_BYTE` renamed to `KIH_KEY_SIZE`/`KIH_USER_ID_SIZE`/`KIH_MODE_BYTE`.

### Added
- **`migrateFromKih()`** — logs in with an existing KiH passkey, re-encrypts the nsec under a new PRF passkey, publishes the new `v=1` event, then publishes a NIP-09 `kind:5` deletion (`a` tag `31777:<pubkey>:<d-tag>`) to retire the old KiH event.
- **`buildKeytrDeletionEvent()`** — NIP-09 deletion builder for `kind:31777` events. `DELETION_EVENT_KIND` constant.
- Restored PRF pipeline: `prfStrategy`, `checkPrfSupport()`, `PrfNotSupportedError`, `prfRegistrationExtension`/`prfAuthenticationExtension`/`extractPrfOutput`/`isPrfEnabled`, the two-ceremony Safari-safe discover, and the YubiKey create→get fallback with Signal-API orphan cleanup.
- `detectMode()`, `DiscoverResult.mode`, `KeytrCredential.prfSupported`, `PRF_USER_ID_SIZE`.

### Deprecated
- **KiH decryption** (`kihStrategy`, `kihAuthenticatePasskey`, `v=3` event support) — retained so existing users can log in and migrate; scheduled for removal in a future release. Migrate now with `migrateFromKih()`.

## [0.7.1] - 2026-04-06

### Security
- **Hardened KiH key material against JS-level interception** — cache `navigator.credentials.create/get` and `Uint8Array.prototype` methods at module load to resist monkey-patching (POC-1) and prototype pollution (POC-3).

## [0.7.0] - 2026-04-06

### Changed
- **Removed PRF mode; added the pluggable `KeyStrategy` interface.** KiH became the sole built-in strategy. (Superseded by 0.8.0, which restores PRF as the default and deprecates KiH.)

## [0.6.3] - 2026-04-06

### Fixed
- **Orphaned credential cleanup** — `registerPasskey()` now calls `signalUnknownCredential()` (WebAuthn Signal API) when PRF fails after credential creation. The browser removes the orphaned passkey from the picker so only the subsequent KiH credential remains. No-op on browsers without Signal API support.

## [0.6.2] - 2026-04-06

### Fixed
- **Single-credential registration** — `setup()` now pre-checks PRF support via `getClientCapabilities()` before creating any credential. On platforms that definitively report no PRF support (e.g. GrapheneOS), registration skips straight to KiH mode, avoiding the creation of an orphaned PRF credential followed by a second KiH credential. Previously, the PRF-first-with-KiH-fallback pattern could create two passkeys on the device when PRF failed after credential creation.

## [0.6.0] - 2026-04-01

### Added
- **Comprehensive capability detection** — `checkCapabilities()` returns a full `WebAuthnCapabilities` report (PRF, conditional mediation, Related Origins, Signal API). Uses `PublicKeyCredential.getClientCapabilities()` (Chrome 132+) when available, falls back to feature detection.
- **Conditional UI (passkey autofill)** — `mediation: 'conditional'` option on `discover()` and `discoverPasskey()` for inline passkey suggestions instead of the modal picker. Requires `<input autocomplete="webauthn">` in the DOM.
- **WebAuthn Signal API** — `signalUnknownCredential()`, `signalAllAcceptedCredentialIds()`, `signalCurrentUserDetails()` for credential lifecycle management (Chrome 132+). All are no-ops on unsupported browsers.
- **Backup eligibility flags** — `KeytrCredential` now includes `backupEligible` (BE) and `backupState` (BS) flags parsed from `authenticatorData` after registration. `parseBackupFlags()` exported from `./webauthn`.
- **WebAuthn Level 3 hints** — `hints` parameter on `SetupOptions`, `RegisterOptions`, `KihRegisterOptions`, `AuthenticateOptions`, and `DiscoverOptions` for authenticator routing (`'security-key'`, `'client-device'`, `'hybrid'`).
- **SSR safety** — `ensureBrowser()` guard throws `WebAuthnError` in non-browser environments. All WebAuthn functions call this internally.
- `WebAuthnCapabilities` type
- `checkCapabilities()` and `ensureBrowser()` exports

### Changed
- `checkPrfSupport()` now uses `getClientCapabilities()` for accurate PRF detection when available, falling back to optimistic reporting
- `discover()` and `discoverPasskey()` now accept `mediation` and `hints` options
- Registration functions (`registerPasskey`, `registerKihPasskey`) now parse backup flags and pass `hints` to WebAuthn ceremonies

## [0.5.0] - 2026-03-29

### Added
- **Key-in-Handle (KiH) mode** — PRF-free passwordless passkey encryption. A random 256-bit encryption key is stored in the passkey's `user.id` field (`[0x03 || key]`, 33 bytes). Works with **all** authenticators including password manager extensions (1Password, Bitwarden, Dashlane) that don't support PRF. Always 1 biometric prompt.
- **Unified `setup()` API** — tries PRF registration first, falls back to KiH if `PrfNotSupportedError` is thrown. Returns `mode: 'prf' | 'kih'`.
- **Unified `discover()` API** — auto-detects mode from `userHandle` length (32 bytes = PRF, 33 bytes with `0x03` prefix = KiH). KiH discovery completes in 1 prompt (no step-2 PRF assertion needed).
- `registerKihPasskey()` — KiH-specific registration (no PRF extension, single ceremony)
- `unifiedDiscover()` — low-level unified discoverable authentication
- `fetchKeytrEventByDTag()` — relay query by `#d` tag for KiH mode (no pubkey needed)
- `generateKihUserId()`, `detectMode()`, `extractKihKey()` — KiH user.id helpers
- `buildAad()` — now exported, accepts version parameter
- `KEYTR_KIH_VERSION`, `KIH_KEY_SIZE`, `KIH_USER_ID_SIZE`, `KIH_MODE_BYTE`, `PRF_USER_ID_SIZE` constants
- `KeytrMode`, `UnifiedDiscoverResult`, `KihRegisterOptions`, `KihRegisterResult`, `SetupOptions`, `SetupResult`, `DiscoverLoginResult` types
- `aadVersion` option on `EncryptOptions` and `DecryptOptions` — AAD version byte `0x03` for KiH prevents cross-mode decryption
- `version` option on `BuildEventOptions` — `v=3` tag for KiH events
- `mode` field on `ParsedKeytrEvent` — detected from `v` tag (`1` = PRF, `3` = KiH)

### Changed
- **Parallel relay operations** — `publishKeytrEvent` and `fetchKeytrEvents` now query all relays concurrently via `Promise.allSettled()` instead of sequentially, reducing worst-case latency from `N × timeout` to `1 × timeout`
- **Upgraded to noble/scure v2** — `@noble/ciphers` ^2.1.0, `@noble/hashes` ^2.0.0, `@scure/base` ^2.0.0
- `buildAad()` in `encrypt.ts` is now exported and parameterized by version (was private, hardcoded to `KEYTR_VERSION`)
- `decrypt.ts` imports shared `buildAad` from `encrypt.ts` instead of duplicating it

## [0.3.1] - 2026-03-28

### Fixed
- **Safari iOS 18+ discoverable login** — `discoverPasskey()` now uses a two-step flow: discovery without PRF, then a targeted assertion with PRF. Safari does not return PRF extension output during discoverable authentication (empty `allowCredentials`). The second assertion targets the discovered credential ID, which the browser auto-approves without an additional biometric prompt.

## [0.2.0] - 2026-03-27

### Added
- **Discoverable passkey login** — `discoverPasskey()` and `discoverAndLogin()` for zero-prior-knowledge login. The browser shows available passkeys, the user picks one, and the nsec is recovered without any npub input or localStorage state.
- `DiscoverOptions` and `DiscoverResult` types for the discoverable flow.
- Configurable timeouts for WebAuthn ceremonies (`timeout` option on `RegisterOptions` and `AuthenticateOptions`)
- Configurable timeouts for relay operations (`RelayOptions` with `timeout` parameter)
- Integration tests for relay publish/fetch roundtrips
- Integration tests for WebAuthn credential lifecycle (mocked)

### Changed
- **BREAKING:** `RegisterOptions.pubkey` is now a required field (hex-encoded 32-byte Nostr public key). The pubkey is stored as WebAuthn `user.id` to enable discoverable authentication.
- `setupKeytr()` and `addBackupGateway()` derive the pubkey automatically from the nsec — no change needed for callers of these high-level functions.
- Registration uses `hexToBytes(pubkey)` as `user.id` instead of `randomBytes(32)`.

### Migration
- New registrations work with discoverable login immediately.
- Old registrations (random `user.id`) still work with `loginWithKeytr(events)` but cannot use `discoverAndLogin()`. Users can re-register their passkey to upgrade.

## [0.1.0] - 2025-05-20

### Added
- NIP-K1 implementation: passkey-encrypted nsec keys for Nostr
- AES-256-GCM encryption with HKDF-SHA256 key derivation from WebAuthn PRF output
- `registerPasskey()` and `authenticatePasskey()` for WebAuthn credential management
- `encryptNsec()` / `decryptNsec()` with AAD binding to credential ID
- Binary blob serialization (93 bytes: version + IV + HKDF salt + ciphertext)
- Kind:31777 event building and parsing (`buildKeytrEvent` / `parseKeytrEvent`)
- Relay publish/fetch with multi-relay support and deduplication
- Nostr key utilities (nsec/npub encoding, key generation, hex conversion)
- High-level `setupKeytr()` and `loginWithKeytr()` convenience functions
- Federated gateway model for cross-client passkey compatibility
- Password fallback implementation (disabled from public API — unsafe for relay publication)
- Browser demo application
- NIP-K1 specification document

### Security
- PRF output and derived keys are zeroed after use
- AAD prevents credential/ciphertext substitution attacks
- Password fallback disabled pending safe UX design
