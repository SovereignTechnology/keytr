import { strictJson } from './strict-json.js';
import { getPublicKey } from 'nostr-tools/pure';
import { HDKey } from '@scure/bip32';
import { entropyToMnemonic, mnemonicToSeedSync } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { hexToBytes } from '@noble/hashes/utils.js';
import { KeytrError } from '../errors.js';
import { NPK_MAX_PLAINTEXT_BYTES } from './npk.js';
import { safeZero } from './builtins.js';
/** A seed's main account, the only key a `seed` record promises. */
const MAIN_PATH = "m/44'/1237'/0'/0/0";
const isObject = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);
const isPath = (path) => typeof path === 'string' && /^m\/44'\/1237'(\/(0|[1-9][0-9]{0,9})'?)+$/.test(path) &&
    path.split('/').length <= 256 && path.split('/').slice(1).every(level => parseInt(level, 10) < 0x80000000);
function isSecretHex(value) {
    if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value))
        return false;
    const bytes = hexToBytes(value);
    try {
        getPublicKey(bytes);
        return true;
    }
    catch {
        return false;
    }
    finally {
        safeZero(bytes);
    }
}
function validateSeed(seed, where) {
    if (!isObject(seed) || typeof seed.entropy !== 'string' || !/^([0-9a-f]{8}){4,8}$/.test(seed.entropy)) {
        throw new KeytrError(`${where}.entropy must be 16, 20, 24, 28 or 32 bytes of lowercase hex`);
    }
    if (seed.passphrase !== undefined && typeof seed.passphrase !== 'string')
        throw new KeytrError(`${where}.passphrase must be a string`);
}
function validateVault(vault) {
    if (!isObject(vault))
        throw new KeytrError('vault must be an object');
    if (vault.seed !== undefined)
        validateSeed(vault.seed, 'vault.seed');
    if (!Array.isArray(vault.accounts) || vault.accounts.length === 0)
        throw new KeytrError('vault.accounts must hold at least one account');
    if (vault.updated_at !== undefined && (!Number.isSafeInteger(vault.updated_at) || vault.updated_at < 0))
        throw new KeytrError('Invalid updated_at');
    if (vault.ext !== undefined && !isObject(vault.ext))
        throw new KeytrError('vault.ext must be an object');
}
export function validateNpkSecret(secret) {
    if (!isObject(secret))
        throw new KeytrError('Invalid stored secret');
    if (secret.type === 'key') {
        if (!(secret.secretKey instanceof Uint8Array) || secret.secretKey.length !== 32)
            throw new KeytrError('A key secret is exactly 32 bytes');
        try {
            getPublicKey(secret.secretKey);
        }
        catch {
            throw new KeytrError('Invalid secp256k1 private key');
        }
    }
    else if (secret.type === 'seed')
        validateSeed(secret.seed, 'seed');
    else if (secret.type === 'vault')
        validateVault(secret.vault);
    else
        throw new KeytrError('Unknown stored secret type');
}
/** Encode a secret as record plaintext. The caller zeroes it. */
export function encodeNpkSecret(secret) {
    validateNpkSecret(secret);
    const plaintext = secret.type === 'key'
        ? secret.secretKey.slice()
        : new TextEncoder().encode(JSON.stringify(secret.type === 'seed' ? secret.seed : secret.vault));
    if (plaintext.length > NPK_MAX_PLAINTEXT_BYTES) {
        safeZero(plaintext);
        throw new KeytrError(`Stored record plaintext exceeds ${NPK_MAX_PLAINTEXT_BYTES} bytes`);
    }
    if (secret.type !== 'key') {
        try {
            strictJson(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext));
        }
        catch {
            safeZero(plaintext);
            throw new KeytrError('Stored record plaintext is not strict JSON');
        }
    }
    return plaintext;
}
/** Decode record plaintext of a known type. Does not zero `plaintext`. */
export function decodeNpkSecret(type, plaintext) {
    let secret;
    if (type === 'key') {
        secret = { type, secretKey: plaintext.slice() };
    }
    else {
        let value;
        try {
            value = strictJson(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext));
        }
        catch {
            throw new KeytrError('Stored record plaintext is not valid UTF-8 JSON');
        }
        secret = type === 'seed' ? { type, seed: value } : { type, vault: value };
    }
    validateNpkSecret(secret);
    return secret;
}
/** Derive the key at `path` from a seed. The caller zeroes `secretKey`. */
export function deriveSeedKey(seed, path = MAIN_PATH) {
    const entropy = hexToBytes(seed.entropy);
    const bip39Seed = mnemonicToSeedSync(entropyToMnemonic(entropy, wordlist), seed.passphrase);
    safeZero(entropy);
    const root = HDKey.fromMasterSeed(bip39Seed);
    safeZero(bip39Seed);
    let node = root;
    try {
        for (const level of path.split('/').slice(1)) {
            const index = parseInt(level, 10) + (level.endsWith("'") ? 0x80000000 : 0);
            const child = node.deriveChild(index);
            node.wipePrivateData();
            node = child;
            if (child.index !== index)
                throw new KeytrError('The exact BIP-32 path is not usable');
        }
        const secretKey = node.privateKey.slice();
        return { pubkey: getPublicKey(secretKey), secretKey, path };
    }
    finally {
        node.wipePrivateData();
    }
}
/**
 * Every importable Nostr key of a secret, in order: the key, a seed's main
 * account, or each `derived` and `key` account of a vault (other kinds are
 * skipped). The caller zeroes each `secretKey`.
 */
export function npkSecretKeys(secret) {
    validateNpkSecret(secret);
    if (secret.type === 'key')
        return [{ pubkey: getPublicKey(secret.secretKey), secretKey: secret.secretKey.slice() }];
    if (secret.type === 'seed')
        return [deriveSeedKey(secret.seed)];
    const { seed, accounts } = secret.vault;
    return accounts.flatMap(account => {
        if (!isObject(account) || typeof account.kind !== 'string' ||
            (account.label !== undefined && typeof account.label !== 'string') ||
            (account.default !== undefined && typeof account.default !== 'boolean'))
            return [];
        if (account.kind === 'derived' && (!seed || !isPath(account.path)))
            return [];
        if (account.kind === 'key' && !isSecretHex(account.secret))
            return [];
        let key;
        if (account.kind === 'derived') {
            try {
                key = deriveSeedKey(seed, account.path);
            }
            catch {
                return [];
            }
        }
        else if (account.kind === 'key') {
            const secretKey = hexToBytes(account.secret);
            key = { pubkey: getPublicKey(secretKey), secretKey };
        }
        else
            return [];
        if (typeof account.label === 'string')
            key.label = account.label;
        if (account.default === true)
            key.default = true;
        return [key];
    });
}
//# sourceMappingURL=npk-secret.js.map