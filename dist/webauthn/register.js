import { randomBytes, hexToBytes } from '@noble/hashes/utils.js';
import { base64url } from '@scure/base';
import { DEFAULT_RP_ID, DEFAULT_RP_NAME, PRF_USER_ID_SIZE } from '../types.js';
import { WebAuthnError, PrfNotSupportedError } from '../errors.js';
import { prfRegistrationExtension, prfAuthenticationExtension, extractPrfOutput } from './prf.js';
import { signalUnknownCredential } from './signal.js';
import { ensureBrowser } from './support.js';
import { parseBackupFlags } from './flags.js';
import { nativeCreate, nativeGet } from './natives.js';
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
export async function registerPasskey(options) {
    ensureBrowser();
    const rpId = options.rpId ?? DEFAULT_RP_ID;
    const rpName = options.rpName ?? DEFAULT_RP_NAME;
    const { userName, userDisplayName, pubkey } = options;
    if (typeof pubkey !== 'string' || !/^[0-9a-fA-F]{64}$/.test(pubkey)) {
        throw new WebAuthnError('registerPasskey requires a 32-byte hex-encoded pubkey (64 hex chars) for user.id');
    }
    const userId = hexToBytes(pubkey);
    if (userId.length !== PRF_USER_ID_SIZE) {
        throw new WebAuthnError(`pubkey must be ${PRF_USER_ID_SIZE} bytes, got ${userId.length}`);
    }
    const create = nativeCreate ?? navigator.credentials.create.bind(navigator.credentials);
    const get = nativeGet ?? navigator.credentials.get.bind(navigator.credentials);
    const pubKeyOptions = {
        rp: {
            id: rpId,
            name: rpName,
        },
        user: {
            id: userId.buffer.slice(0),
            name: userName,
            displayName: userDisplayName,
        },
        challenge: randomBytes(32).buffer.slice(0),
        pubKeyCredParams: [
            { type: 'public-key', alg: -7 }, // ES256
            { type: 'public-key', alg: -257 }, // RS256
        ],
        authenticatorSelection: {
            residentKey: 'required',
            requireResidentKey: true,
            userVerification: 'required',
        },
        timeout: options.timeout ?? 120000,
        extensions: prfRegistrationExtension(),
    };
    // WebAuthn Level 3 hints for authenticator routing
    if (options.hints?.length) {
        ;
        pubKeyOptions.hints = options.hints;
    }
    const createOptions = { publicKey: pubKeyOptions };
    let cred;
    try {
        const result = await create(createOptions);
        if (!result)
            throw new WebAuthnError('Credential creation returned null');
        cred = result;
    }
    catch (err) {
        if (err instanceof WebAuthnError)
            throw err;
        throw new WebAuthnError(`Passkey registration failed: ${err.message}`);
    }
    const response = cred.response;
    const extensionResults = cred.getClientExtensionResults();
    let keyMaterial = extractPrfOutput(extensionResults);
    // Some authenticators (e.g. YubiKey) report prf.enabled=true during
    // registration but only return PRF output during authentication.
    // Fall back to an immediate assertion to obtain the PRF output.
    if (!keyMaterial || keyMaterial.length !== 32) {
        const credId = new Uint8Array(cred.rawId);
        const getOptions = {
            publicKey: {
                rpId,
                challenge: randomBytes(32).buffer.slice(0),
                allowCredentials: [
                    {
                        type: 'public-key',
                        id: credId.buffer.slice(0),
                        transports: response.getTransports?.() ?? [],
                    },
                ],
                userVerification: 'required',
                timeout: options.timeout ?? 120000,
                extensions: prfAuthenticationExtension(),
            },
        };
        let assertion;
        try {
            const result = await get(getOptions);
            if (!result)
                throw new WebAuthnError('Follow-up authentication returned null');
            assertion = result;
        }
        catch (err) {
            if (err instanceof WebAuthnError)
                throw err;
            throw new WebAuthnError(`Follow-up PRF authentication failed: ${err.message}`);
        }
        const assertionExtensions = assertion.getClientExtensionResults();
        keyMaterial = extractPrfOutput(assertionExtensions);
        if (!keyMaterial || keyMaterial.length !== 32) {
            // Credential was created but PRF is not supported — clean up the
            // orphaned credential via the Signal API so it doesn't appear in the
            // passkey picker. No-op on browsers without Signal API support.
            await signalUnknownCredential(rpId, new Uint8Array(cred.rawId));
            throw new PrfNotSupportedError('PRF output not available from this authenticator');
        }
    }
    const credentialId = new Uint8Array(cred.rawId);
    const transports = response.getTransports?.() ?? [];
    const backup = parseBackupFlags(response);
    const credential = {
        credentialId,
        credentialIdBase64url: base64url.encode(credentialId),
        rpId,
        transports,
        prfSupported: true,
        ...backup && { backupEligible: backup.backupEligible, backupState: backup.backupState },
    };
    return { credential, keyMaterial };
}
//# sourceMappingURL=register.js.map