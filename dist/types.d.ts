/** Blob binary format version (layout: version(1) | iv(12) | salt(32) | ct(48)) */
export declare const BLOB_VERSION = 1;
/** Protocol / AAD version for PRF mode (the default/primary mode) */
export declare const KEYTR_VERSION = 1;
/** Protocol / AAD version for legacy Key-in-Handle (KiH) mode — decrypt-only */
export declare const KEYTR_KIH_VERSION = 3;
/** Size of the random encryption key embedded in a legacy KiH user.id */
export declare const KIH_KEY_SIZE = 32;
/** Total size of a legacy KiH user.id: mode byte (0x03) + 32-byte key */
export declare const KIH_USER_ID_SIZE = 33;
/** Mode prefix byte written as user.id[0] in legacy KiH mode */
export declare const KIH_MODE_BYTE = 3;
/** PRF mode user.id size — the raw 32-byte Nostr pubkey */
export declare const PRF_USER_ID_SIZE = 32;
/** PRF salt used during WebAuthn ceremonies (prf.eval.first input) */
export declare const PRF_SALT: Uint8Array<ArrayBuffer>;
/** Nostr event kind for passkey-encrypted private keys */
export declare const KEYTR_EVENT_KIND = 31777;
/** NIP-09 deletion request event kind (used to retire migrated KiH events) */
export declare const DELETION_EVENT_KIND = 5;
/** HKDF info string for key derivation */
export declare const HKDF_INFO = "keytr nsec encryption v1";
/**
 * Well-known passkey gateways for cross-client compatibility.
 * Any domain can host a .well-known/webauthn file and become a gateway.
 * Clients can also use their own domain as a standalone rpId.
 *
 * The gateway model is federated: multiple independent domains can each
 * authorize their own set of origins. Users encrypt their nsec once per
 * gateway (or standalone rpId), producing separate kind:31777 events.
 * Any client sharing the same rpId can decrypt the matching event.
 */
export declare const DEFAULT_RP_ID = "keytr.org";
export declare const DEFAULT_RP_NAME = "keytr";
/**
 * Well-known passkey gateways.
 * The primary gateway is used during initial setup (1 biometric prompt).
 * Additional gateways can be registered later via addBackupGateway().
 */
export declare const KEYTR_GATEWAYS: readonly ["keytr.org", "nostkey.org"];
/** Result of passkey registration */
export interface KeytrCredential {
    credentialId: Uint8Array;
    credentialIdBase64url: string;
    rpId: string;
    transports: AuthenticatorTransport[];
    /** Whether the credential's PRF extension is confirmed working (set by PRF registration) */
    prfSupported?: boolean;
    /** Whether the credential is eligible for multi-device sync (BE flag from authenticatorData) */
    backupEligible?: boolean;
    /** Whether the credential is currently backed up / synced (BS flag from authenticatorData) */
    backupState?: boolean;
}
/** The encrypted nsec blob (parsed binary structure) */
export interface EncryptedNsecBlob {
    version: number;
    iv: Uint8Array;
    hkdfSalt: Uint8Array;
    ciphertext: Uint8Array;
}
/** A kind:31777 event payload (before signing) */
export interface KeytrEventTemplate {
    kind: typeof KEYTR_EVENT_KIND;
    content: string;
    tags: string[][];
    created_at: number;
}
/** Options for encrypting an nsec */
export interface EncryptOptions {
    nsecBytes: Uint8Array;
    keyMaterial: Uint8Array;
    credentialId: Uint8Array;
    /** AAD version byte. Defaults to KEYTR_VERSION (1, PRF). Use KEYTR_KIH_VERSION (3) for legacy KiH blobs. */
    version?: number;
}
/** Options for decrypting an nsec */
export interface DecryptOptions {
    encryptedBlob: string;
    keyMaterial: Uint8Array;
    credentialId: Uint8Array;
    /** AAD version byte. Defaults to KEYTR_VERSION (1, PRF). Must match the version used during encryption. */
    version?: number;
}
/** PRF support detection result */
export interface PrfSupportInfo {
    supported: boolean;
    platformAuthenticator: boolean;
    reason?: string;
}
/** Passkey registration options */
export interface RegisterOptions {
    /**
     * Relying Party ID. This determines which clients can decrypt.
     *
     * - Use a gateway domain (e.g. "keytr.org") for cross-client compatibility
     *   with all clients authorized by that gateway.
     * - Use your own domain for standalone mode (only your client can decrypt).
     * - Register multiple rpIds for maximum portability.
     *
     * Defaults to "keytr.org".
     */
    rpId?: string;
    /** Relying Party display name. Defaults to "keytr". */
    rpName?: string;
    userName: string;
    userDisplayName: string;
    /**
     * Hex-encoded 32-byte Nostr public key, stored as the WebAuthn user.id.
     * This enables discoverable credential login — the browser returns the
     * pubkey via userHandle when the user picks a passkey. The high-level
     * setup()/addBackupGateway()/migrateFromKih() helpers fill this in for you.
     */
    pubkey: string;
    /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
    timeout?: number;
    /** WebAuthn Level 3 hints to guide authenticator selection: 'security-key', 'client-device', 'hybrid' */
    hints?: string[];
}
/** Result of passkey registration */
export interface RegisterResult {
    credential: KeytrCredential;
    /** 32-byte key material (PRF output) for encryption */
    keyMaterial: Uint8Array;
}
/** Options for discoverable passkey authentication (no prior credential needed) */
export interface DiscoverOptions {
    rpId?: string;
    /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
    timeout?: number;
    /**
     * Credential mediation requirement. Set to 'conditional' for passkey autofill
     * (requires <input autocomplete="webauthn"> in the DOM). Defaults to 'optional' (modal picker).
     */
    mediation?: 'silent' | 'optional' | 'conditional' | 'required';
    /** WebAuthn Level 3 hints to guide authenticator selection: 'security-key', 'client-device', 'hybrid' */
    hints?: string[];
}
/** Encryption mode: PRF (authenticator-derived key) or legacy KiH (key-in-handle) */
export type KeytrMode = 'prf' | 'kih';
/** Result of discoverable passkey authentication */
export interface DiscoverResult {
    /** 32-byte key material (PRF output, or the key extracted from a legacy KiH userHandle) */
    keyMaterial: Uint8Array;
    /** Raw credential ID */
    credentialId: Uint8Array;
    /** Detected mode: 'prf' for the current strategy, 'kih' for a legacy credential */
    mode?: KeytrMode;
    /** Hex public key — set in PRF mode (recovered from the userHandle) */
    pubkey?: string;
}
/** Passkey authentication options for decryption */
export interface AuthenticateOptions {
    credentialId: Uint8Array;
    rpId: string;
    transports?: AuthenticatorTransport[];
    /** WebAuthn ceremony timeout in milliseconds. Defaults to 120000 (2 minutes). */
    timeout?: number;
    /** WebAuthn Level 3 hints to guide authenticator selection: 'security-key', 'client-device', 'hybrid' */
    hints?: string[];
}
/** Full encrypt-and-wrap result */
export interface KeytrBundle {
    credential: KeytrCredential;
    encryptedBlob: string;
    eventTemplate: KeytrEventTemplate;
}
/** Pluggable key derivation strategy */
export interface KeyStrategy {
    /** AAD version byte (1 for PRF, 3 for legacy KiH) */
    readonly version: number;
    /** Register a passkey, return credential + 32-byte key material */
    register(options: RegisterOptions): Promise<{
        credential: KeytrCredential;
        keyMaterial: Uint8Array;
    }>;
    /** Targeted auth with known credential, return 32-byte key material */
    authenticate(options: AuthenticateOptions): Promise<Uint8Array>;
    /** Discoverable auth, return key material + credential ID + optional pubkey */
    discover(options: DiscoverOptions): Promise<DiscoverResult>;
}
/** Browser WebAuthn capability report from getClientCapabilities() */
export interface WebAuthnCapabilities {
    /** Whether WebAuthn is available in this environment */
    webauthn: boolean;
    /** Whether a platform authenticator is available */
    platformAuthenticator: boolean;
    /** PRF extension support (null = unknown, requires credential creation to confirm) */
    prf: boolean | null;
    /** Whether conditional mediation (passkey autofill) is supported */
    conditionalMediation: boolean;
    /** Whether Related Origin Requests are supported (cross-domain passkey use; null = unknown) */
    relatedOrigins: boolean | null;
    /** Whether the WebAuthn Signal API is supported (credential lifecycle management) */
    signalApi: boolean;
}
//# sourceMappingURL=types.d.ts.map