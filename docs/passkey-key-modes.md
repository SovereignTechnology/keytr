# Passkey-held Nostr keys (npk1)

keytr can read and write the stored-mode format of the draft [Passkey-held Nostr keys](<SPEC_URL>) proposal, next to its own formats. The legacy login reader skips unsupported kinds and versions before parsing their credential coordinates. This does not migrate `setup()`, `discover()`, v1 events, the `keytr-v1` PRF input or the v4 [typed recovery](typed-recovery.md) payloads.

The proposal names two ways a passkey can hold a Nostr identity. In derived mode the PRF output is the private key. In stored mode a separately created secret is encrypted with the PRF output. keytr has always been stored mode and never derives a key. New passkeys say which mode they use in their handle (`user.id`), so a client can refuse the other kind instead of creating an empty identity.

## Format

| | |
|---|---|
| Handle | `"NPK" 01 02` + 32-byte author public key (37 bytes) |
| PRF input | `SHA-256("nostr-passkey:store:v1")`, unrelated to the `keytr-v1` output |
| Record | `"NPK" 01 type iv(12) hkdf_salt(32) ciphertext`, HKDF info `nostr-passkey:store:v1`, AAD binds type, RP ID, author and credential ID |
| Types | `key` (32 bytes), `vault` (JSON seed and accounts); legacy `seed` remains readable only |
| Event | provisional kind 31778, `d` = `<credential>:<type>` and `rp`, no `v`; credential IDs unpadded base64url |

The companion vault proposal defines the vault JSON. New seed-only writes use a vault containing the seed and its main derived account; type 02 is reserved. keytr keeps unknown fields, unknown account kinds and `ext` namespaces as they are, and checks after decrypting that the event author is one of the secret's keys.

## Handles

| Handle | `classifyHandle()` | `discoverStored()` |
|---|---|---|
| 32 bytes | `stored`, `legacy: 'raw-pubkey'` | keytr v1 record of that public key, else `unknown` |
| 33 bytes starting `03` | `stored`, `legacy: 'key-in-handle'` | refused, use `discover()` and `migrateFromKih()` |
| `"NPK" 01 02`, 37 bytes | `stored` | newest eligible vault, else a usable immutable key |
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

The author is the key, the seed's `m/44'/1237'/0'/0/0` account, or the vault's `default` account (else its first). `record` can also go into a file or a `largeBlob`; `decryptStoredSecret()` opens it with the PRF output for `NPK_STORE_PRF_INPUT`. Discovery selects the newest signed vault coordinate before decoding and never restores an older relay vault if that copy fails. It may use a usable immutable key; hosts must display any returned `warnings`. Kind 31777 is queried separately for legacy reads. Kind 31778 is provisional pending upstream acceptance.

Not implemented: derived mode, reading or writing `largeBlob`, discovery of untagged handles by credential ID (keytr refuses them), and migrating v1 or v4 records to npk1.

## Gateways

The proposal's default is for each application to use its own RP ID and import an identity once. Shared gateways such as keytr's are optional, have at most 5 member domains (the browser minimum for Related Origin Requests), and are listed in the registry. Every member can obtain the PRF output of any passkey for the gateway's RP ID, so adding one is a trust decision. The proposal recommends stored mode on gateways, which is what keytr does.

## Vault validation and integration boundary

The decoder rejects duplicate JSON member names, invalid UTF-8, malformed top-level fields and non-digit or out-of-range `updated_at` values. It retains unknown fields, skips unusable accounts, derives only the exact specified BIP-32 path, and chooses the first usable default account. The authenticated author must belong to a usable account.

`discoverStored()` is relay-only. A host that adds provider storage must compare its authenticated vault against the newest eligible relay vault using `updated_at`, prefer usable vaults over immutable key records, and report failed copies without rolling back to older relay vaults. These changes do not establish cross-device provider synchronization or migrate existing deployments.
