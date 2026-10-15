# Typed seed and vault recovery (draft)

This is an opt-in proposal for PRF-encrypted application payloads. Existing single-key `setup()`, `discover()`, `encryptNsec()` and v1 events keep their behavior. Typed payloads use explicit APIs and protocol version 4; version 3 remains reserved for legacy KiH. This draft does not claim interoperability with deployed clients that only understand nsec events.

## Why a separate payload type

A wallet may need to restore a seed with derivation paths, or an entire multi-account vault, rather than a single private key. These are different recovery scopes. The library transports bounded opaque bytes and authenticates their type and schema; the consuming application owns serialization, schema validation and account import. A `vault` label alone does not make two applications' vault schemas compatible. Never infer a seed or private key from byte length.

## Wire format

The event remains kind 31777, with these mandatory tags exactly once:

| Tag | Value |
|---|---|
| `d` | `<credential-base64url>:<type>:<schema>` |
| `credential` | Canonical base64url credential ID |
| `rp` | Credential's relying party ID |
| `algo` | `aes-256-gcm` |
| `kdf` | `hkdf-sha256` |
| `v` | `4` |
| `type` | `seed` or `vault` |
| `schema` | Application-owned versioned identifier, e.g. `org.example.vault.v1` |

The schema is 1–128 ASCII characters matching `[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}`. The optional `client` tag identifies the writer. Separate `d` coordinates prevent typed payloads from replacing a v1 private-key event, or another type/schema, registered under the same credential. The event author is the public key stored in the discoverable credential's user handle. The application must retain that author's signing key to update the snapshot.

Content is canonical standard base64 encoding of `0x04 || IV(12) || HKDF salt(32) || ciphertext(N+16)`. Plaintext length N is 1–65,536 bytes. No compression is applied. HKDF-SHA256 uses the 32-byte PRF output, a fresh 32-byte random salt and the UTF-8 context `keytr payload encryption v4` to derive a 32-byte AES key. AES-256-GCM uses a fresh 12-byte IV and a 16-byte authentication tag.

Authenticated additional data is the UTF-8 encoding of the exact compact JSON array `['keytr', 4, type, schema, rpId, authorPubkeyHex, credentialIdBase64url]`, serialized with double quotes, no whitespace and lowercase author hex. This binds the type, schema, RP, author and credential independently of the outer event signature. Old nsec decoders reject this variable-length/version-4 blob.

Registration and authentication retain the PRF input `keytr-v1` and the 32-byte author public key in `user.id`. Domain separation happens in the HKDF context and AAD, not by silently changing the existing credential's PRF input. KiH and password encryption are not supported for typed payloads.

## Creating a recovery event

```typescript
import { setupPayload, publishKeytrEvent } from '@sovit.xyz/keytr'
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure'

// Application-provided: authorSecret (32-byte Nostr key) and a validated,
// serialized vault. Do not log either value or return them to untrusted code.
const payload = new TextEncoder().encode(JSON.stringify(myVault))
try {
  const { eventTemplate } = await setupPayload(payload, {
    pubkey: getPublicKey(authorSecret),
    userName: 'alice',
    userDisplayName: 'Alice',
    rpId: 'example.com', // must be usable from this client's origin
    payloadType: 'vault',
    schema: 'org.example.vault.v1',
  })
  const event = finalizeEvent(eventTemplate, authorSecret)
  await publishKeytrEvent(event, recoveryRelays)
} finally {
  payload.fill(0)
  // Clear authorSecret when the application no longer needs it.
}
```

`setupPayload` registers a passkey and returns an unsigned template. It does not sign, publish or persist application state. Reuse `encryptPayload` and `buildPayloadEvent` with an existing credential and a fresh PRF assertion to update its snapshot. A new setup call creates a new credential. Validate application data before prompting, and handle publication failure without deleting local keys or claiming that recovery was saved.

## Recovering on another device

```typescript
import { discoverPayload } from '@sovit.xyz/keytr'

const result = await discoverPayload(recoveryRelays, {
  rpId: 'example.com',
  payloadType: 'vault',
  schema: 'org.example.vault.v1',
})
try {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(result.payload)
  const vault = validateMyVaultSchema(JSON.parse(text))
  // Verify the recovered signing identity belongs to result.pubkey, obtain
  // user consent, and use the application's normal import/merge protections.
  await importMyVault(vault)
} finally {
  result.payload.fill(0)
}
```

The browser returns the author public key through `userHandle`, so users do not need to enter an npub. The application must still know the RP, schema and recovery relays. A synchronized passkey does not guarantee that a relay retains its event, that another application recognizes its schema, or that an unrelated origin may request its PRF. Changing the RP requires a new credential. Related Origin Requests and gateway policy remain separate from payload support.

`unlockPayload(signedEvent, expectedContext)` handles an already-fetched event; the caller supplies the expected author, RP, type and schema. Signature and context are checked before opening WebAuthn. `discoverPayload` selects the newest matching event by timestamp, breaking ties with the lowest event ID, checks the signature and selected credential, and authenticates the ciphertext. It does not silently fall back to an older snapshot on decryption failure. A withholding relay can still serve stale data; fresh installations have no independently trusted latest revision.

## Security and limits

Only the authenticator's internal secret stays inside it: PRF output and decrypted payload bytes reach trusted client JavaScript. Application compromise can expose them. Derived-key buffers are cleared on success and failure; callers own returned plaintext buffers and source objects/strings, which cannot be reliably erased in JavaScript. Do not parse or import data until authentication succeeds, and do not claim that encryption validates an application's schema or derivation rules.

Events expose author, credential identifier, type, schema, RP, size and timing. A full-vault compromise can expose multiple identities and other stored credentials. Updating or deleting an addressable event cannot erase older copies from relays. Snapshot freshness, rotation, revocation and recovery availability remain application responsibilities. Reject oversize data rather than truncating it. The library's 64 KiB plaintext bound does not imply every relay accepts that event size; keep file export or another explicit recovery route available.

The demo remains a single-account login UI. This proposal adds library APIs and a wire-format draft, not automatic vault import into that UI. Real authenticator synchronization and external-client schema compatibility require separate integration testing.
