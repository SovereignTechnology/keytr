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
//# sourceMappingURL=register.d.ts.map