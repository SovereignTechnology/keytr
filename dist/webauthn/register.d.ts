import type { RegisterOptions, RegisterResult } from '../types.js';
/**
 * Register a new discoverable passkey with the WebAuthn PRF extension enabled.
 *
 * The 32-byte encryption key is derived by the authenticator (PRF output) and
 * never leaves it except as key material returned to this call — it is not
 * stored in user.id. The raw Nostr pubkey is stored as user.id so discoverable
 * login can recover it from the userHandle.
 *
 * Some authenticators (e.g. YubiKey) report prf.enabled=true during
 * registration but only return the PRF output during an assertion; a follow-up
 * get() covers that case. If no PRF output can be obtained, the orphaned
 * credential is cleaned up via the Signal API and PrfNotSupportedError is thrown.
 *
 * All WebAuthn calls route through the cached native references (natives.ts) to
 * resist monkey-patching (POC-1).
 */
export declare function registerPasskey(options: RegisterOptions): Promise<RegisterResult>;
/**
 * Register a passkey with a tagged stored handle ("NPK" || 0x01 || 0x02 || author)
 * and evaluate the PRF with the stored-mode input SHA-256("nostr-passkey:store:v1").
 * The output is for an npk1 record and unrelated to the "keytr-v1" output.
 */
export declare function registerStoredPasskey(options: Omit<RegisterOptions, 'pubkey'> & {
    author: string;
}): Promise<RegisterResult>;
//# sourceMappingURL=register.d.ts.map