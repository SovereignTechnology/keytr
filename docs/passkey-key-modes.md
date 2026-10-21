# Passkey-held Nostr keys (npk1)

keytr can read and write the stored-mode format of the draft [Passkey-held Nostr keys](<SPEC_URL>) proposal, next to its own formats. Nothing here changes `setup()`, `discover()`, `loginWithKeytr()`, v1 events, the `keytr-v1` PRF input or the v4 [typed recovery](typed-recovery.md) payloads.

The proposal names two ways a passkey can hold a Nostr identity. In derived mode the PRF output is the private key. In stored mode a separately created secret is encrypted with the PRF output. keytr has always been stored mode and never derives a key. New passkeys say which mode they use in their handle (`user.id`), so a client can refuse the other kind instead of creating an empty identity.

## Format

| | |
|---|---|
| Handle | `"NPK" 01 02` + 32-byte author public key (37 bytes) |
| PRF input | `SHA-256("nostr-passkey:store:v1")`, unrelated to the `keytr-v1` output |
| Record | `"NPK" 01 type iv(12) hkdf_salt(32) ciphertext`, HKDF info `nostr-passkey:store:v1`, AAD binds type, RP ID, author and credential ID |
| Types | `key` (32 bytes), `seed` (JSON entropy and passphrase), `vault` (JSON seed and accounts) |
| Event | kind 31777, `d` = `<credential>:<type>`, `credential`, `v` = `npk1`, `rp`, `type`; credential IDs unpadded base64url |

The proposal defines the seed and vault JSON. keytr keeps unknown fields, unknown account kinds and `ext` namespaces as they are, and checks after decrypting that the event author is one of the secret's keys.

## Handles

| Handle | `classifyHandle()` | `discoverStored()` |
|---|---|---|
| 32 bytes | `stored`, `legacy: 'raw-pubkey'` | keytr v1 record of that public key, else `unknown` |
| 33 bytes starting `03` | `stored`, `legacy: 'key-in-handle'` | refused, use `discover()` and `migrateFromKih()` |
| `"NPK" 01 02`, 37 bytes | `stored` | newest valid npk1 record of the author |
| `"NPK" 01 01`, 22 bytes | `derived` | refused |
| other `"NPK"` handles | `unsupported` | refused |
| anything else, or none | `unknown` | refused |

Refusals are `PasskeyModeError` with a `reason` of `derived`, `unsupported`, `unknown` or `record-not-found`, and happen before any relay query. Derived parameter sets and the handles of other deployments are listed in the proposal's [registry](<REGISTRY_URL>). The v1 `detectMode()` also throws `PasskeyModeError` for tagged handles; 32 and 33-byte handles behave as before.

## Usage

```typescript
import { setupStored, discoverStored, npkSecretKeys, publishKeytrEvent } from '@sovit.xyz/keytr'

// Create: registers a tagged passkey, returns the record bytes and a signed event.
const { event, record } = await setupStored(
  { type: 'vault', vault: { seed: { entropy }, accounts: [{ kind: 'derived', path: "m/44'/1237'/0'/0/0" }] } },
  { userName: 'alice', userDisplayName: 'Alice' },
)
await publishKeytrEvent(event, relays)

// Log in: npk1 or keytr v1, one sign-in action.
const { secret } = await discoverStored(relays)
const keys = npkSecretKeys(secret) // importable keys; zero each secretKey when done
```

The author is the key, the seed's `m/44'/1237'/0'/0/0` account, or the vault's `default` account (else its first). `record` can also go into a file or a `largeBlob`; `decryptStoredSecret()` opens it with the PRF output for `NPK_STORE_PRF_INPUT`. If the newest record does not decrypt, `discoverStored()` fails instead of restoring an older one.

Not implemented: derived mode, reading or writing `largeBlob`, discovery of untagged handles by credential ID (keytr refuses them), and migrating v1 or v4 records to npk1.

## Gateways

The proposal's default is for each application to use its own RP ID and import an identity once. Shared gateways such as keytr's are optional, have at most 5 member domains (the browser minimum for Related Origin Requests), and are listed in the registry. Every member can obtain the PRF output of any passkey for the gateway's RP ID, so adding one is a trust decision. The proposal recommends stored mode on gateways, which is what keytr does.
