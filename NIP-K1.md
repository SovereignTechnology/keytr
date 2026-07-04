
NIP-K1
======

Passkey-Encrypted Private Keys
------------------------------

`draft` `optional`

This NIP defines a method for encrypting a Nostr private key with a WebAuthn passkey and storing the encrypted result in an addressable event. Users authenticate with biometrics (fingerprint, face, device PIN) to decrypt their key -- no passwords or seed phrases are involved.

## Motivation

Nostr private keys are difficult for most users to manage. Seed phrases and `ncryptsec` ([NIP-49](49.md)) require memorization or secure physical storage. Key delegation via remote signers ([NIP-46](46.md)) introduces a trusted third party.

Passkeys solve this differently. Modern devices ship with hardware-backed authenticators that can generate cryptographic secrets bound to a specific origin, protected by biometrics, and synced across devices by the platform (iCloud Keychain, Google Password Manager, etc.). The WebAuthn PRF extension exposes a deterministic secret from the authenticator that never leaves the hardware -- this secret can derive an encryption key for a Nostr private key.

The result: a user taps their fingerprint once to set up, and taps again on any device to log in. The encrypted private key is stored on Nostr relays as a replaceable event. No passwords, no seed phrases, no trusted servers.

## Terminology

- **passkey**: A WebAuthn discoverable credential, typically backed by a platform authenticator and synced across devices.
- **PRF**: The WebAuthn Pseudo-Random Function extension (`prf`). It evaluates an HMAC inside the authenticator, producing a deterministic 32-byte secret bound to the credential and input salt. The secret never leaves the authenticator hardware.
- **gateway**: A WebAuthn Relying Party (`rpId`) that multiple independent clients share via Related Origin Requests (`.well-known/webauthn`). Any client authorized by the same gateway can decrypt the same event.
- **KiH (Key-in-Handle)**: A **deprecated, decrypt-only** legacy mode. A random encryption key is embedded in the WebAuthn `user.id` field, which the authenticator stores and returns during discoverable login. Clients MUST NOT create new KiH credentials; the mode is retained in this spec only so existing `v=3` events remain readable and can be migrated to PRF.

## Overview

```
SETUP (one biometric prompt):
  1. Client creates a WebAuthn passkey with PRF extension
  2. Authenticator returns PRF output (32-byte secret)
  3. Client derives AES-256 key via HKDF-SHA256
  4. Client encrypts the Nostr private key (nsec)
  5. Client publishes encrypted blob as a kind:31777 event

LOGIN (one prompt; up to two on Safari):
  1. Browser presents passkey picker (discoverable credential)
  2. Discovery assertion returns userHandle (the 32-byte pubkey)
  3. Targeted assertion evaluates the PRF extension → 32-byte secret
     (a separate ceremony to work around Safari not returning PRF
      output on discovery; often auto-approved without a second prompt)
  4. Client fetches kind:31777 event for that pubkey
  5. Client derives the same AES-256 key and decrypts the nsec
```

## Encryption Modes

### PRF Mode (Version 1)

**The one and only mode for new registrations.** The authenticator's PRF extension produces a hardware-bound secret that serves as input key material for HKDF; it is never stored in `user.id`. The 32-byte Nostr public key is stored as `user.id` in the passkey, enabling discoverable login without any prior state. If the authenticator does not support PRF, registration fails — this spec defines no fallback.

AAD version byte: `0x01`

### Key-in-Handle Mode (Version 3) — DEPRECATED (decrypt-only)

> **Deprecated.** KiH registration was removed in keytr v0.8.0 because the encryption key stored in `user.id` is interceptable in JavaScript memory. Clients MUST NOT create new KiH credentials. This section is retained so implementations can decrypt existing `v=3` events for login and migration; KiH decryption will be removed from the reference implementation in a future release.

A random 32-byte encryption key is embedded in the WebAuthn `user.id` field, prefixed with a `0x03` mode byte (33 bytes total). The authenticator stored this as part of the credential and returns it during discoverable authentication.

KiH provides weaker security guarantees than PRF -- the key material is stored by the authenticator as opaque data rather than derived inside hardware, and it is recoverable in JS memory during login. Existing KiH credentials SHOULD be migrated to PRF (see [Migration (v3 → v1)](#migration-v3--v1)).

AAD version byte: `0x03`

### Mode Detection

During discoverable authentication, the mode is determined by the `userHandle` returned by the authenticator:

| `userHandle` length | First byte | Mode |
|---------------------|------------|------|
| 32 bytes            | any        | PRF  |
| 33 bytes            | `0x03`     | KiH  |

## Key Derivation

KEY\_MATERIAL = 32-byte secret from the authenticator (PRF output in PRF mode, or the embedded key in KiH mode)

HKDF\_SALT = 32 random bytes, generated fresh for each encryption

ENCRYPTION\_KEY = HKDF-SHA256(
    ikm=KEY\_MATERIAL,
    salt=HKDF\_SALT,
    info="keytr nsec encryption v1",
    length=32
)

The derived key MUST be 32 bytes. It MUST be zeroed from memory immediately after encryption or decryption.

## Encryption

PRIVATE\_KEY = The user's Nostr private key as 32 raw bytes

IV = 12 random bytes

HKDF\_SALT = 32 random bytes

ENCRYPTION\_KEY = HKDF-SHA256(KEY\_MATERIAL, HKDF\_SALT, "keytr nsec encryption v1", 32)

CREDENTIAL\_ID = The raw WebAuthn credential ID

AAD = concat("keytr", VERSION\_BYTE, CREDENTIAL\_ID)

Where VERSION\_BYTE is `0x01` for PRF mode or `0x03` for KiH mode. The AAD binds the ciphertext to the specific credential and mode, preventing cross-credential and cross-mode decryption.

CIPHERTEXT = AES-256-GCM(
    key=ENCRYPTION\_KEY,
    nonce=IV,
    plaintext=PRIVATE\_KEY,
    aad=AAD
)

The ciphertext is 48 bytes: 32 bytes of encrypted private key + 16 bytes of GCM authentication tag.

## Encrypted Blob Format

The encrypted output is serialized into a compact 93-byte binary blob:

| Offset | Length | Field      |
|--------|--------|------------|
| 0      | 1      | version    |
| 1      | 12     | iv         |
| 13     | 32     | hkdfSalt   |
| 45     | 48     | ciphertext |

Total: 93 bytes. The blob is base64-encoded for storage in the event `content` field (~124 characters).

Decryption operates in reverse: decode the base64 blob, extract the fields by offset, re-derive the key from stored HKDF\_SALT and the authenticator's key material, reconstruct the AAD, and decrypt.

## Event Format

Encrypted private keys are stored in addressable events of kind `31777`.

```jsonc
{
  "kind": 31777,
  "pubkey": "<32-byte-hex-pubkey>",
  "content": "<base64-encoded-93-byte-blob>",
  "tags": [
    ["d", "<credential-id-base64url>"],
    ["rp", "<relying-party-id>"],
    ["algo", "aes-256-gcm"],
    ["kdf", "hkdf-sha256"],
    ["v", "<version>"],
    ["transports", "<transport>", "<transport>", ...],
    ["client", "<client-name>"]
  ],
  "created_at": <unix-timestamp>
}
```

### Tags

- `d` (REQUIRED): The WebAuthn credential ID, base64url-encoded. This serves as the addressable event identifier -- each credential produces a unique event.
- `rp` (REQUIRED): The WebAuthn Relying Party ID used during registration (e.g., `"keytr.org"`). Clients need this to construct the authentication ceremony.
- `algo` (REQUIRED): The symmetric encryption algorithm. MUST be `"aes-256-gcm"`.
- `kdf` (REQUIRED): The key derivation function. MUST be `"hkdf-sha256"`.
- `v` (REQUIRED): The protocol version. `"1"` for PRF mode, `"3"` for KiH mode.
- `transports` (OPTIONAL): WebAuthn authenticator transports (e.g., `"internal"`, `"hybrid"`, `"usb"`, `"ble"`, `"nfc"`). Helps clients optimize the authentication ceremony.
- `client` (OPTIONAL): Name of the client that created the event.

### Content

The `content` field is the base64-encoded 93-byte encrypted blob as described above. It is NOT JSON -- it is a raw base64 string.

### Why kind:31777?

Kind 31777 falls in the 30000-39999 addressable event range defined by [NIP-01](01.md). Addressable events are identified by the combination of `pubkey`, `kind`, and `d` tag. This means:

- Each credential ID produces a distinct event (no collisions between passkeys).
- Re-encrypting with the same credential replaces the previous event (the relay keeps the latest).
- A user can have multiple kind:31777 events -- one per registered passkey.

## WebAuthn Ceremonies

### Registration (Setup)

The WebAuthn credential creation ceremony MUST use these parameters:

```
PublicKeyCredentialCreationOptions:
  challenge:       32 random bytes
  rp.id:           <relying-party-domain>
  rp.name:         <relying-party-display-name>
  user.id:         <see below>
  user.name:       <user-provided-identifier>
  user.displayName: <user-provided-display-name>
  pubKeyCredParams: [
    { type: "public-key", alg: -7 },    // ES256 (P-256)
    { type: "public-key", alg: -257 }   // RS256
  ]
  authenticatorSelection:
    residentKey:         "required"
    requireResidentKey:  true
    userVerification:    "required"
  extensions:
    prf:
      eval:
        first: UTF-8("keytr-v1")
```

**`user.id` encoding:**

- **PRF mode (the only mode for new registrations)**: `user.id` = 32-byte raw Nostr public key. This embeds the pubkey inside the passkey so it can be recovered during discoverable authentication without any relay lookup.
- **KiH mode (legacy, not created by new clients)**: `user.id` = `0x03` || 32 random bytes (33 bytes total). The random bytes serve as the encryption key and the `0x03` prefix enables mode detection. New registrations MUST NOT produce this layout; it is documented only so existing `v=3` credentials can still be recognized during discoverable authentication.

The `residentKey: "required"` parameter ensures the credential is stored on the authenticator as a discoverable credential, enabling login without the client knowing the credential ID in advance.

The PRF extension input salt `"keytr-v1"` is a fixed, well-known value. All clients MUST use this exact salt to produce the same PRF output for a given credential.

### Targeted Authentication (Decrypt a Known Event)

When a client already knows the credential ID (e.g., from a kind:31777 event's `d` tag):

```
PublicKeyCredentialRequestOptions:
  challenge:        32 random bytes
  rpId:             <from-event-rp-tag>
  allowCredentials: [{
    type: "public-key"
    id:   <credential-id-from-d-tag>
    transports: <from-event-transports-tag>
  }]
  userVerification: "required"
  extensions:
    prf:
      eval:
        first: UTF-8("keytr-v1")
```

### Discoverable Authentication (Login Without Prior State)

For login on a new device where the client has no stored credential IDs, a two-step discoverable flow is used:

**Step 1 -- Discovery assertion** (no PRF):

```
PublicKeyCredentialRequestOptions:
  challenge:        32 random bytes
  rpId:             <gateway-domain>
  allowCredentials: []
  userVerification: "required"
```

The empty `allowCredentials` array causes the browser to present a passkey picker. The authenticator returns `userHandle` (the `user.id` from registration).

The PRF extension is intentionally omitted from this step. Some platforms (notably Safari) ignore PRF when `allowCredentials` is empty.

**Step 2 -- Targeted PRF assertion**:

Using the credential ID from step 1, perform a targeted authentication (as described above) to obtain the PRF output. Some browsers auto-approve this second ceremony without an additional biometric prompt.

**Mode detection after step 1:**

If the returned `userHandle` is 32 bytes, this is a PRF-mode credential. The pubkey is `hex(userHandle)`. Proceed to step 2 to obtain PRF output, then fetch the kind:31777 event by `authors: [pubkey]`.

If the returned `userHandle` is 33 bytes with a `0x03` first byte, this is a KiH-mode credential. The encryption key is `userHandle[1..33]`. No step 2 is needed -- the key material is already available. Fetch the kind:31777 event by `#d` filter using the credential ID.

## Migration (v3 → v1)

Existing KiH (`v=3`) credentials SHOULD be migrated to PRF (`v=1`). Because the decrypted nsec is the same key, migration re-wraps it under a new PRF passkey and retires the old KiH event with a [NIP-09](09.md) deletion request.

The migration flow, in order (the ordering is load-bearing — nothing is deleted until the replacement is published):

1. **Log in** with the existing KiH passkey (discoverable authentication) and decrypt the nsec.
2. **Verify** the decrypted key's pubkey matches the old event's `pubkey` (mandatory, since `#d` lookups are cross-author).
3. **Register a new PRF passkey** for the same nsec (32-byte pubkey in `user.id`).
4. **Publish the new `v=1` event.** This MUST succeed on at least one relay before proceeding.
5. **Publish a `kind:5` deletion** for the old KiH event.
6. Optionally signal the old credential as unknown (WebAuthn Signal API) so it disappears from the passkey picker.

The deletion request is a NIP-09 `kind:5` event authored by the same pubkey:

```jsonc
{
  "kind": 5,
  "pubkey": "<hex-pubkey>",
  "content": "<optional human-readable reason>",
  "tags": [
    ["a", "31777:<hex-pubkey>:<old-credential-id-base64url>"],
    ["k", "31777"],
    ["e", "<optional old event id>"]
  ],
  "created_at": <unix-timestamp>
}
```

- `a` (REQUIRED): the addressable coordinate of the old KiH event (`31777:<pubkey>:<d-tag>`). Relays remove all versions of that coordinate up to the deletion's `created_at`.
- `k` (REQUIRED): the kind being deleted, `"31777"`.
- `e` (OPTIONAL): the specific old event id, as a belt-and-braces hint for relays that don't index `a` tags.

Deletion is best-effort: the new PRF event is already live, and KiH decryption still works this release, so a failed deletion is non-fatal (the old event will simply be superseded on migration-aware clients).

## Gateway Model

A gateway is a WebAuthn Relying Party domain that authorizes multiple independent origins via the Related Origin Requests mechanism (`.well-known/webauthn`). Any client listed in a gateway's `.well-known/webauthn` file can create and use passkeys scoped to that gateway's `rpId`.

This means:

- A user encrypts their nsec once per gateway, producing one kind:31777 event.
- Any client authorized by the same gateway can decrypt that event.
- Clients MAY also use their own domain as a standalone `rpId` for single-client mode.
- A user MAY register passkeys across multiple gateways for redundancy.

Gateways are federated and permissionless. Any domain can become a gateway by hosting the `.well-known/webauthn` file and listing authorized origins.

## Security Considerations

- **No password**: Unlike [NIP-49](49.md), there is no password to brute-force. The encryption key is derived from a hardware-backed secret (PRF mode) or a random key stored in the authenticator (KiH mode).
- **Origin binding**: The WebAuthn `rpId` enforcement by the browser prevents phishing -- a passkey created for `keytr.org` cannot be invoked by a different origin.
- **User verification**: All ceremonies require `userVerification: "required"`, meaning biometric or device PIN confirmation.
- **AAD binding**: The credential ID and version byte are included in the AES-GCM authenticated data. Attempting to decrypt with the wrong credential or the wrong mode fails with an authentication error.
- **Unique ciphertexts**: The IV and HKDF salt are generated fresh for each encryption. Re-encrypting the same nsec with the same passkey produces a different blob every time.
- **Memory hygiene**: Implementations SHOULD zero derived keys from memory after use.
- **Relay is untrusted storage**: All cryptographic operations happen client-side. The relay stores opaque ciphertext. Compromising a relay does not reveal private keys.
- **KiH limitations (deprecated mode)**: In KiH mode the encryption key is stored as opaque data in `user.id` rather than derived inside hardware. During discoverable login it is returned to the client as the `userHandle`, so it is recoverable in JavaScript memory — this is why KiH registration was removed in keytr v0.8.0. Clients MUST NOT create new KiH credentials and SHOULD migrate existing ones to PRF.
- **Decrypted key exposure (PRF mode)**: PRF keeps the *encryption* key inside the authenticator, but the decrypted nsec is returned to the client so it can sign events. An attacker who has already compromised the client runtime (malicious dependency, XSS, hostile extension) can read the nsec while it is in memory. PRF is not a substitute for a hardware signer that never releases the private key; it removes the KiH weakness (key sitting in `user.id`) but not this one.
- **Multi-device sync**: Platform authenticators (iCloud Keychain, Google Password Manager) sync passkeys across devices. This means the encryption capability follows the user to new devices, but also that the security boundary extends to the sync provider.

## Recommendations

Clients MUST register new credentials using PRF mode (`v=1`). KiH mode (`v=3`) is deprecated for registration and retained decrypt-only; there is no PRF fallback, so an authenticator without the PRF extension cannot register. Clients SHOULD migrate existing `v=3` credentials to `v=1` (see [Migration (v3 → v1)](#migration-v3--v1)).

Clients SHOULD publish events to multiple relays for availability.

Clients SHOULD support the gateway model for interoperability. Using a standalone `rpId` locks the user into a single client.

Clients MAY display backup eligibility and backup state flags from the authenticator to inform users whether their passkey is synced across devices.

Clients SHOULD NOT store the decrypted private key persistently. The intended flow is to decrypt on demand via a biometric prompt each time the key is needed (e.g., to sign events).
