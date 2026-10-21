import { type NpkType } from './npk.js';
/**
 * The three secrets a stored record can hold:
 *
 * - key:   exactly 32 raw bytes
 * - seed:  UTF-8 JSON { entropy, passphrase? }
 * - vault: UTF-8 JSON { seed?, accounts: [...], ext? }
 *
 * Unknown fields, unknown account kinds and every `ext` namespace are kept
 * as they are, so decoding and encoding again keeps other applications' data.
 */
export interface NpkSeed {
    /** 16, 20, 24, 28 or 32 bytes of BIP-39 entropy, lowercase hex */
    entropy: string;
    passphrase?: string;
    [field: string]: unknown;
}
/**
 * `derived` carries a full BIP-32 `path` starting m/44'/1237'/, `key` a 32-byte
 * lowercase hex `secret`. Accounts of any other kind are skipped on import.
 */
export interface NpkAccount {
    kind: 'derived' | 'key' | (string & {});
    path?: string;
    secret?: string;
    label?: string;
    /** The account the user normally uses. At most one per vault. */
    default?: boolean;
    [field: string]: unknown;
}
export interface NpkVault {
    seed?: NpkSeed;
    accounts: NpkAccount[];
    /** Application data keyed by reverse-DNS identifier */
    ext?: Record<string, Record<string, unknown>>;
    [field: string]: unknown;
}
export type NpkSecret = {
    type: 'key';
    secretKey: Uint8Array;
} | {
    type: 'seed';
    seed: NpkSeed;
} | {
    type: 'vault';
    vault: NpkVault;
};
/** One importable Nostr key of a stored secret. The caller zeroes `secretKey`. */
export interface NpkSecretKey {
    pubkey: string;
    secretKey: Uint8Array;
    path?: string;
    label?: string;
    default?: true;
}
export declare function validateNpkSecret(secret: NpkSecret): void;
/** Encode a secret as record plaintext. The caller zeroes it. */
export declare function encodeNpkSecret(secret: NpkSecret): Uint8Array;
/** Decode record plaintext of a known type. Does not zero `plaintext`. */
export declare function decodeNpkSecret(type: NpkType, plaintext: Uint8Array): NpkSecret;
/** Derive the key at `path` from a seed. The caller zeroes `secretKey`. */
export declare function deriveSeedKey(seed: NpkSeed, path?: string): NpkSecretKey;
/**
 * Every importable Nostr key of a secret, in order: the key, a seed's main
 * account, or each `derived` and `key` account of a vault (other kinds are
 * skipped). The caller zeroes each `secretKey`.
 */
export declare function npkSecretKeys(secret: NpkSecret): NpkSecretKey[];
//# sourceMappingURL=npk-secret.d.ts.map