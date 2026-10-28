NIP-K1
======

Passkey-Encrypted Private Keys
-------------------------------

`draft` `optional`

This NIP defines a method for encrypting Nostr private keys using the WebAuthn PRF extension, storing the ciphertext on Nostr relays, and recovering the private key on any device with the synced passkey. The user's public key is embedded in the credential's `user.id` field, enabling discoverable login without any prior knowledge of the user's identity.

## Motivation

Nostr private key management is a major UX barrier. Users must manually copy their `nsec` between devices, risking exposure through clipboard, screenshots, or insecure storage. Hardware signers (NIP-46) add complexity. Browser extensions (NIP-07) don't sync across devices.

WebAuthn passkeys solve the transport problem — they sync across devices automatically via iCloud Keychain, Google Password Manager, and similar platform credential managers. They require biometric or PIN verification and are phishing-resistant by design.

This NIP uses the WebAuthn **PRF extension** to derive a deterministic encryption key from the passkey, and stores the user's **public key** in the credential's `user.id` field. This approach:

- **Hardware-bound encryption** — the PRF secret never leaves the authenticator; the encryption key is computed on-device during each ceremony.
- **Discoverable login** — the authenticator returns the pubkey via `userHandle` during discoverable authentication, so the client can fetch the encrypted event without any prior state.
- **Single gesture** — one biometric tap to authenticate and recover the private key.

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        SETUP                                │
│                                                             │
│  Generate nsec ──► Derive pubkey                            │
│       │                 │                                   │
│       │           ┌─────▼──────┐                            │
│       │           │  user.id = │                            │
│       │           │  pubkey    │ (32 bytes, hex-decoded)     │
│       │           └─────┬──────┘                            │
│       │                 │                                   │
│       │           Register passkey with PRF extension       │
│       │                 │                                   │
│       │           PRF output (32 bytes)                     │
│       │                 │                                   │
│       ▼                 ▼                                   │
│  HKDF-SHA256(PRF output, random salt) ──► AES-256 key      │
│       │                                                     │
│       ▼                                                     │
│  AES-256-GCM encrypt nsec                                   │
│       │                                                     │
│       ▼                                                     │
│  kind:31777 event ──► publish to relays                     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   DISCOVERABLE LOGIN                        │
│                                                             │
│  Step 1: Discovery (no PRF, allowCredentials: [])           │
│  Browser shows passkey picker, user taps one                │
│       │                                                     │
│       ├── userHandle ──► pubkey (32 bytes)                   │
│       └── rawId      ──► credential ID                      │
│                                                             │
│  Step 2: Targeted assertion (allowCredentials: [credId])    │
│       └── PRF output  ──► 32 bytes                          │
│                                                             │
│  Fetch kind:31777 events for pubkey from relays             │
│       │                                                     │
│       ▼                                                     │
│  Match event by credential ID (d tag)                       │
│       │                                                     │
│       ▼                                                     │
│  HKDF-SHA256(PRF output, salt from blob) ──► AES-256 key   │
│       │                                                     │
│       ▼                                                     │
│  AES-256-GCM decrypt ──► recovered nsec                     │
└─────────────────────────────────────────────────────────────┘
```

## Specification

### User Handle Format

The WebAuthn credential's `user.id` field stores the user's **32-byte Nostr public key** (raw x-only pubkey, not bech32-encoded):

```
Offset  Length  Field
0       32      Nostr public key (raw 32-byte x-only pubkey)
────────────
Total: 32 bytes
```

This is well within the [WebAuthn specification's 64-byte maximum](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id) for `user.id`. The public key is naturally unique per user, satisfying WebAuthn's uniqueness requirement for `user.id` within a relying party.

The public key is stored in `user.id` to enable **discoverable authentication** — when the user authenticates with `allowCredentials: []`, the authenticator returns the `userHandle` containing the pubkey, allowing the client to fetch the correct kind:31777 event from relays without any prior knowledge of the user's identity.

### PRF Extension

The WebAuthn **PRF (Pseudo-Random Function) extension** provides a deterministic 32-byte output from the authenticator, derived from a fixed salt and the credential's internal secret. The PRF output serves as the input keying material for encryption key derivation.

Implementations MUST use the following PRF salt for all ceremonies:

```
PRF_SALT = UTF-8("keytr-v1")    // as ArrayBuffer
```

The salt is fixed by specification — it MUST NOT vary per user or per ceremony. The PRF output is deterministic: the same credential with the same salt always produces the same 32-byte output, on any device that has the synced passkey.

**Browser support**: Chrome 116+, Safari 18+, Edge 116+, Firefox 122+.

### Key Derivation

The raw PRF output is NOT used directly as an encryption key. It MUST be processed through HKDF-SHA256:

```
KEY = HKDF-SHA256(
  ikm    = PRF_OUTPUT,                      // 32 bytes from authenticator
  salt   = RANDOM(32),                      // fresh per encryption, stored in blob
  info   = UTF-8("keytr nsec encryption v1"),
  length = 32                               // 256-bit AES key
)
```

The random HKDF salt ensures that re-encrypting the same nsec with the same passkey produces different ciphertext each time.

### Registration (Setup)

1. Generate a random 32-byte Nostr private key (nsec).
2. Derive the 32-byte public key from the nsec.
3. Set `user.id` to the raw 32-byte public key.
4. Register a WebAuthn passkey with the following options:

```javascript
{
  challenge: randomBytes(32),
  rp: {
    name: "Relying Party Name",
    id: rpId                              // e.g., "keytr.org"
  },
  user: {
    id: pubkeyBytes,                      // 32 bytes: raw Nostr public key
    name: userIdentifier,                 // e.g., "npub1...@keytr.org"
    displayName: userDisplayName
  },
  pubKeyCredParams: [
    { type: "public-key", alg: -7 },     // ES256 (P-256 ECDSA)
    { type: "public-key", alg: -257 }    // RS256 (RSASSA-PKCS1-v1_5)
  ],
  authenticatorSelection: {
    userVerification: "required",
    residentKey: "required",
    requireResidentKey: true
  },
  attestation: "none",
  extensions: {
    prf: {
      eval: { first: PRF_SALT }           // ArrayBuffer of UTF-8("keytr-v1")
    }
  }
}
```

5. Verify that the PRF extension returned output (check `prf.results.first` in the extension results). If PRF output is not available during registration, perform a follow-up assertion against the newly created credential to obtain it — some authenticators (e.g., YubiKey) only return PRF output during authentication, not creation.
6. Encrypt the nsec using the PRF output (see [Encryption](#encryption)) to produce an encrypted blob.
7. Build a kind:31777 event containing the encrypted blob (see [Event Format](#event-format)).
8. Sign the event with the nsec and publish to Nostr relays.
9. Zero the PRF output, derived key, and nsec from memory.

Clients SHOULD support both ES256 (alg: -7) and RS256 (alg: -257) to maximize authenticator compatibility. Discoverable credentials (`residentKey: "required"`) and user verification (`userVerification: "required"`) are REQUIRED.

### Authentication (Discoverable Login)

This is the primary login flow. No prior knowledge of the user's pubkey or credential ID is needed. Implementations MUST use a **two-step flow** because Safari iOS 18+ does not return PRF extension output during discoverable authentication (empty `allowCredentials`).

**Step 1 — Discovery (no PRF):**

1. Call `navigator.credentials.get()`:

```javascript
{
  challenge: randomBytes(32),
  rpId: rpId,                             // e.g., "keytr.org"
  allowCredentials: [],                   // empty = browser shows passkey picker
  userVerification: "required"
  // No PRF extension — Safari iOS 18+ ignores it with empty allowCredentials
}
```

2. Extract `userHandle` from the `AuthenticatorAssertionResponse` — this is the 32-byte Nostr public key set during registration.
3. Extract the credential ID from `rawId`.

**Step 2 — Targeted assertion with PRF:**

4. Call `navigator.credentials.get()` again with the discovered credential:

```javascript
{
  challenge: randomBytes(32),
  rpId: rpId,
  allowCredentials: [{
    type: "public-key",
    id: credentialId                      // from step 1
  }],
  userVerification: "required",
  extensions: {
    prf: {
      eval: { first: PRF_SALT }
    }
  }
}
```

5. Extract the 32-byte PRF output from `prf.results.first` in the extension results.
6. Fetch kind:31777 events for the recovered public key from Nostr relays.
7. Select the event whose `d` tag matches the base64url-encoded credential ID from the authenticator response.
8. Parse the event and extract the encrypted blob from the `content` field.
9. Decrypt the nsec using the PRF output (see [Decryption](#decryption)).
10. Zero the PRF output and derived key from memory.

Step 1 uses `allowCredentials: []` to trigger the platform's passkey picker. Step 2 targets the specific credential for PRF evaluation. The browser typically auto-approves step 2 without an additional biometric prompt since it targets the same credential that was just authenticated. If step 2 fails to return PRF output, the authenticator does not support PRF.

### Authentication (Known Credential)

When the client already knows the user's pubkey (e.g., from localStorage or URL parameter), it can skip discovery and authenticate directly:

1. Fetch kind:31777 events for the known pubkey from relays.
2. For each event, attempt authentication with the specific credential:

```javascript
{
  challenge: randomBytes(32),
  rpId: rpId,                             // from event's "rp" tag
  allowCredentials: [{
    type: "public-key",
    id: credentialId,                     // from event's "d" tag (base64url-decoded)
    transports: transports               // from event's "transports" tag
  }],
  userVerification: "required",
  extensions: {
    prf: {
      eval: { first: PRF_SALT }
    }
  }
}
```

3. Extract the 32-byte PRF output and decrypt the nsec.
4. If the authenticator rejects (no matching credential), try the next event.

This flow is useful when clients maintain a credential index or when the user provides their npub manually.

### Encryption

```
IV       = RANDOM(12)                     // 12-byte AES-GCM nonce
HKDF_SALT = RANDOM(32)                   // 32-byte salt for HKDF
KEY      = HKDF-SHA256(PRF_OUTPUT, HKDF_SALT, "keytr nsec encryption v1", 32)
AAD      = UTF-8("keytr") || 0x01 || CREDENTIAL_ID_BYTES

CIPHERTEXT = AES-256-GCM(
  key       = KEY,
  iv        = IV,
  plaintext = NSEC_RAW_BYTES,            // 32 bytes
  aad       = AAD
)
// CIPHERTEXT is 48 bytes (32-byte plaintext + 16-byte GCM auth tag)
```

The AAD (Additional Authenticated Data) binds the ciphertext to the specific WebAuthn credential ID and version byte, preventing substitution and downgrade attacks.

### Decryption

```
1. Deserialize the blob to extract version, IV, HKDF salt, and ciphertext.
2. Derive the key: KEY = HKDF-SHA256(PRF_OUTPUT, HKDF_SALT, "keytr nsec encryption v1", 32)
3. Reconstruct AAD: UTF-8("keytr") || version || CREDENTIAL_ID_BYTES
4. Decrypt:

NSEC_RAW_BYTES = AES-256-GCM-DECRYPT(
  key        = KEY,
  iv         = IV,
  ciphertext = CIPHERTEXT,
  aad        = AAD
)
```

If the wrong passkey is used, the PRF output will differ, producing a wrong key, and AES-GCM decryption will fail with an authentication error. If the credential ID does not match, the AAD mismatch causes the same failure.

### Encrypted Blob Format

The `content` field of the Nostr event contains a base64-encoded binary blob:

```
Offset  Length  Field
0       1       Version (0x01)
1       12      IV (AES-GCM nonce)
13      32      HKDF salt
45      48      Ciphertext (32-byte nsec + 16-byte GCM auth tag)
────────────
Total: 93 bytes → ~124 base64 characters
```

Implementations MUST reject blobs where:
- The version byte is not `0x01`
- The total length is not exactly 93 bytes

### Event Kind

This NIP uses **kind `31777`** (parameterized replaceable event).

Each passkey credential produces a distinct event, identified by the credential ID in the `d` tag. Re-encrypting with the same passkey replaces the previous event.

### Event Format

```json
{
  "kind": 31777,
  "pubkey": "<user's hex public key>",
  "content": "<base64-encoded encrypted blob (93 bytes → ~124 chars)>",
  "tags": [
    ["d", "<credential-id-base64url>"],
    ["rp", "<relying-party-id>"],
    ["algo", "aes-256-gcm"],
    ["kdf", "hkdf-sha256"],
    ["v", "1"],
    ["transports", "internal", "hybrid", "..."],
    ["client", "<client-name>"]
  ],
  "created_at": <unix-timestamp>,
  "id": "...",
  "sig": "..."
}
```

### Tag Definitions

| Tag | Required | Description |
|-----|----------|-------------|
| `d` | Yes | Base64url-encoded WebAuthn credential ID. Makes this a parameterized replaceable event — re-encryption with the same passkey replaces the old event. |
| `rp` | Yes | WebAuthn Relying Party ID (domain). Clients need this to know which rpId to use for the authentication ceremony. |
| `algo` | Yes | Encryption algorithm. MUST be `aes-256-gcm`. |
| `kdf` | Yes | Key derivation function. MUST be `hkdf-sha256`. |
| `v` | Yes | Blob format version. Currently `1`. |
| `transports` | No | WebAuthn authenticator transports (e.g., `internal`, `hybrid`, `usb`, `ble`, `nfc`). Helps clients optimize the authentication UX. |
| `client` | No | Name of the client that created this event. Informational only. |

## Cross-Client Compatibility

### Federated Gateway Model

WebAuthn passkeys are bound to an **rpId** (a domain). A passkey created with `rpId: "app-a.com"` will not be usable on `app-b.com`. Without a solution, every Nostr client would need its own passkey registration, defeating the purpose.

WebAuthn's [Related Origin Requests](https://w3c.github.io/webauthn/#sctn-related-origins) specification solves this. A gateway domain hosts a `/.well-known/webauthn` file declaring which origins are authorized to use its passkeys:

```json
{
  "origins": [
    "https://client-a.example.com",
    "https://client-b.example.com"
  ]
}
```

A passkey registered with a gateway's rpId on **any** listed origin works on **every** listed origin. The authenticator returns the same credential, PRF output, and user handle regardless of which authorized origin triggers the ceremony.

The model is **federated**: there is no single canonical gateway. Multiple independent domains can each host their own `.well-known/webauthn` and authorize their own set of Nostr clients:

| Gateway | Operator | Hosting | Authorized Origins |
|---------|----------|---------|-------------------|
| `keytr.org` | Sovereign Technology | Cloudflare Pages | nostkey.org, bies.sovit.xyz, gitvid.sovit.xyz, nostrbook.net |
| `nostkey.org` | Sovereign Technology | Hostinger | keytr.org, bies.sovit.xyz, gitvid.sovit.xyz, nostrbook.net |
| `keys.example.org` | Self-hosted | Any | personal-client.example.org |

Users can register passkeys against **multiple gateways**, producing separate kind:31777 events for each. Losing access to one gateway does not affect events encrypted under other rpIds.

### Cross-Gateway Trust

Gateways MAY list each other as authorized origins, enabling passkeys registered under one gateway's rpId to be used from another gateway's domain. For example, if `keytr.org/.well-known/webauthn` includes `https://nostkey.org`, a user on `nostkey.org` can authenticate with a passkey bound to `rpId: "keytr.org"`.

The authentication flow for cross-gateway usage:

1. Client on origin B calls `navigator.credentials.get()` with `rpId` set to gateway A's domain
2. Browser fetches `https://gateway-a/.well-known/webauthn`
3. Browser verifies origin B is listed in the `origins` array
4. Authenticator runs the ceremony using gateway A's rpId — returns the same credential, PRF output, and user handle

This requires browser support for [Related Origin Requests](https://w3c.github.io/webauthn/#sctn-related-origins) (Chrome 128+, Safari 18+).

### Adding Client Origins to a Gateway

To authorize a new origin for an existing gateway, add the client's full origin (e.g., `https://client.example.com`) to the gateway's `/.well-known/webauthn` origins array. No changes are needed on the client side — the browser handles validation automatically.

### Standalone Mode

Clients MAY use their own domain as the rpId instead of (or in addition to) a gateway. In standalone mode:

- The `rp` tag in the event tells other clients which origin to visit for decryption.
- Only the client's own domain can decrypt the event.
- This requires no coordination with any gateway.

### Recommended Strategy

For maximum portability, clients SHOULD:

1. Register against at least one gateway (e.g., `keytr.org`) for cross-client access.
2. Optionally register a standalone credential under the client's own rpId as a backup.
3. Support decryption of events encrypted under any rpId the client is authorized for.

## Security Model

### PRF-Derived Keys

The encryption key is derived from the authenticator's PRF output, not stored directly in the credential. The PRF secret is internal to the authenticator — it never leaves the hardware. The key is computed during each WebAuthn ceremony and exists in client memory only for the duration of encryption/decryption.

When passkeys sync across devices (via iCloud Keychain, Google Password Manager, etc.), the PRF secret syncs as part of the credential material. The same PRF salt produces the same output on any device that holds the synced credential.

### Origin Binding

The passkey ceremony is bound to the rpId. A phishing site on a different domain cannot trigger the passkey — the browser enforces origin checks before the authenticator is contacted. Even if triggered, a different rpId would produce a different (useless) PRF output.

### User Verification

Every operation requires `userVerification: "required"`, meaning biometric (Face ID, Touch ID, fingerprint) or PIN verification. An attacker with physical access to the device still cannot extract the PRF output without passing user verification.

### AAD Binding

The AES-GCM ciphertext is authenticated against the credential ID and version byte. This prevents an attacker from:

- Substituting one encrypted blob for another (credential ID mismatch)
- Downgrading the blob format (version mismatch)

### Unique Ciphertexts

The random IV and random HKDF salt ensure that re-encrypting the same nsec with the same passkey produces different ciphertext each time. This prevents an observer from detecting re-encryption events.

### Relay Safety

The encrypted blob published to relays is meaningless without the PRF output. An attacker who obtains the event from a relay still needs:

1. Access to the user's synced passkey (or the physical authenticator)
2. The ability to pass biometric/PIN verification

Offline brute-force is infeasible — the PRF output is a 32-byte value derived from the authenticator's internal HMAC secret, and the HKDF step adds a per-encryption salt.

### Passkey Deletion = Permanent Key Loss

If a user deletes all passkeys that hold the credential, and has no other backup of their nsec, the encrypted data on relays becomes permanently irrecoverable. Clients MUST warn users about this and SHOULD encourage:

- Registering multiple passkeys (e.g., phone + laptop + hardware key)
- Registering across multiple gateways for redundancy
- Keeping a separate backup of the nsec (e.g., NIP-49 encrypted backup)

### Memory Hygiene

Implementations SHOULD zero the PRF output, derived AES key, and decrypted nsec from memory after use. In JavaScript, overwrite `Uint8Array` contents with zeros in a `finally` block.

### Server-Side Considerations

If an implementation uses a server-side component (e.g., for challenge generation), the `userHandle` is returned as part of the `AuthenticatorAssertionResponse`. The user handle contains the public key (which is already public information), so transmitting it to a server for account identification is acceptable. However, the PRF output MUST be extracted and used **client-side only** and MUST NOT be sent to any server.

## Multiple Passkeys

Users SHOULD register multiple passkeys for redundancy. Each passkey:

- Has its own credential ID
- Contains the same pubkey in its `user.id`
- Produces a different PRF output (different credential → different HMAC secret)
- Produces a separate kind:31777 event with a different `d` tag and different encrypted blob
- Can independently decrypt its corresponding event

To register an additional passkey for an existing identity:

1. Decrypt the nsec using any existing passkey
2. Register a new passkey with the same pubkey as `user.id`
3. Encrypt the nsec with the new passkey's PRF output
4. Publish the new kind:31777 event

## Constants

```
KEYTR_VERSION    = 1
KEYTR_EVENT_KIND = 31777
PRF_SALT         = UTF-8("keytr-v1")
HKDF_INFO        = "keytr nsec encryption v1"
```

## Acknowledgments

The passkey-based key management approach described in this NIP was inspired by [BitTasker](https://bittasker.com), who pioneered the concept of using the WebAuthn `user.id` field for Nostr private key security. NIP-K1 evolves this design to use the PRF extension for key derivation, storing only the public key in `user.id` for discoverable authentication.

## Relation to Other NIPs

| NIP | Relation |
|-----|----------|
| NIP-01 | Standard event structure used for kind:31777 events |
| NIP-07 | Browser extension signers can integrate NIP-K1 for key import/export |
| NIP-46 | Alternative approach: NIP-46 delegates signing to a remote signer; NIP-K1 stores keys locally |
| NIP-49 | Can be used as a complementary backup method (password-encrypted nsec for offline storage) |

## Proposed typed recovery extension

An opt-in [typed seed and vault recovery proposal](../docs/typed-recovery.md) adds PRF payload version 4, explicit type/schema metadata and bounded variable-length ciphertext. It leaves the existing v1 private-key format unchanged. Typed payloads use separate addressable coordinates and dedicated APIs; clients that only implement v1 must not interpret them as private keys. This is a draft extension, not a claim of deployed cross-client support.
