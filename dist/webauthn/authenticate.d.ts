import type { AuthenticateOptions, DiscoverOptions, DiscoverResult } from '../types.js';
/**
 * Authenticate with an existing PRF passkey and obtain the PRF output
 * for decrypting the nsec.
 *
 * @returns 32-byte PRF output for key derivation
 */
export declare function authenticatePasskey(options: AuthenticateOptions): Promise<Uint8Array>;
/**
 * Targeted assertion that evaluates the PRF with a chosen input. keytr v1
 * uses "keytr-v1" (authenticatePasskey); stored npk1 records use
 * NPK_STORE_PRF_INPUT.
 *
 * @returns 32-byte PRF output
 */
export declare function authenticatePrf(options: AuthenticateOptions, prfInput: Uint8Array): Promise<Uint8Array>;
/**
 * Legacy KiH targeted authentication (decrypt-only).
 *
 * Used for existing Key-in-Handle credentials during login and migration.
 * Extracts the 32-byte encryption key from the userHandle. No PRF extension.
 *
 * @returns 32-byte encryption key from userHandle
 */
export declare function kihAuthenticatePasskey(options: AuthenticateOptions): Promise<Uint8Array>;
/**
 * Unified discoverable passkey authentication — no prior pubkey or credential
 * ID needed. Auto-detects PRF (current) vs legacy KiH credentials.
 *
 * Step 1 — Discovery (no PRF): empty allowCredentials, browser shows the
 *   passkey picker. Reads the userHandle.
 *     • 33 bytes, 0x03 prefix → legacy KiH: the key is in the userHandle,
 *       done in a single ceremony (no PRF step).
 *     • 32 bytes → PRF: the userHandle is the pubkey; proceed to step 2.
 *
 * Step 2 (PRF only) — Targeted assertion WITH PRF: the discovered credentialId
 *   goes into allowCredentials so the browser can evaluate the PRF extension.
 *   This works around Safari iOS 18+ not returning PRF output on discovery
 *   (empty allowCredentials) assertions.
 *
 * All WebAuthn calls route through the cached native get (natives.ts).
 *
 * @returns key material, credential ID, detected mode, and (PRF) the pubkey
 */
export declare function discoverPasskey(options?: DiscoverOptions): Promise<DiscoverResult>;
/**
 * Discoverable assertion for stored npk1 passkeys: asks for the stored-mode
 * PRF output in the same ceremony and returns the raw handle without
 * interpreting it. `prfOutput` is null when the platform did not evaluate the
 * PRF here (many do not with empty allowCredentials); use authenticatePrf().
 */
export declare function discoverStoredPasskey(options?: DiscoverOptions): Promise<{
    credentialId: Uint8Array;
    userHandle: Uint8Array | null;
    prfOutput: Uint8Array | null;
}>;
//# sourceMappingURL=authenticate.d.ts.map