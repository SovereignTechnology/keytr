import { randomBytes, hexToBytes } from '@noble/hashes/utils.js'
import { base64url } from '@scure/base'
import type { KeytrCredential, RegisterOptions, RegisterResult } from '../types.js'
import { DEFAULT_RP_ID, DEFAULT_RP_NAME, PRF_SALT, PRF_USER_ID_SIZE } from '../types.js'
import { NPK_STORE_PRF_INPUT } from '../crypto/npk.js'
import { buildStoredHandle } from './handle.js'
import { WebAuthnError, PrfNotSupportedError } from '../errors.js'
import { prfRegistrationExtension, prfAuthenticationExtension, extractPrfOutput } from './prf.js'
import { signalUnknownCredential } from './signal.js'
import { ensureBrowser } from './support.js'
import { parseBackupFlags } from './flags.js'
import { nativeCreate, nativeGet } from './natives.js'

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
export async function registerPasskey(
  options: RegisterOptions
): Promise<RegisterResult> {
  ensureBrowser()

  const { pubkey } = options

  if (typeof pubkey !== 'string' || !/^[0-9a-fA-F]{64}$/.test(pubkey)) {
    throw new WebAuthnError(
      'registerPasskey requires a 32-byte hex-encoded pubkey (64 hex chars) for user.id'
    )
  }
  const userId = hexToBytes(pubkey)
  if (userId.length !== PRF_USER_ID_SIZE) {
    throw new WebAuthnError(`pubkey must be ${PRF_USER_ID_SIZE} bytes, got ${userId.length}`)
  }

  return createPrfPasskey(options, userId, PRF_SALT)
}

/**
 * Register a passkey with a tagged stored handle ("NPK" || 0x01 || 0x02 || author)
 * and evaluate the PRF with the stored-mode input SHA-256("nostr-passkey:store:v1").
 * The output is for an npk1 record and unrelated to the "keytr-v1" output.
 */
export async function registerStoredPasskey(options: Omit<RegisterOptions, 'pubkey'> & { author: string }): Promise<RegisterResult> {
  ensureBrowser()
  const userId = buildStoredHandle(options.author)
  return createPrfPasskey(options, userId, NPK_STORE_PRF_INPUT)
}

async function createPrfPasskey(
  options: Omit<RegisterOptions, 'pubkey'>,
  userId: Uint8Array,
  prfInput: Uint8Array
): Promise<RegisterResult> {
  const rpId = options.rpId ?? DEFAULT_RP_ID
  const rpName = options.rpName ?? DEFAULT_RP_NAME
  const { userName, userDisplayName } = options

  const create = nativeCreate ?? navigator.credentials.create.bind(navigator.credentials)
  const get = nativeGet ?? navigator.credentials.get.bind(navigator.credentials)

  const pubKeyOptions: PublicKeyCredentialCreationOptions = {
    rp: {
      id: rpId,
      name: rpName,
    },
    user: {
      id: userId.buffer.slice(0) as ArrayBuffer,
      name: userName,
      displayName: userDisplayName,
    },
    challenge: randomBytes(32).buffer.slice(0) as ArrayBuffer,
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },    // ES256
      { type: 'public-key', alg: -257 },  // RS256
    ],
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'required',
    },
    timeout: options.timeout ?? 120000,
    extensions: prfRegistrationExtension(prfInput),
  }

  // WebAuthn Level 3 hints for authenticator routing
  if (options.hints?.length) {
    ;(pubKeyOptions as any).hints = options.hints
  }

  const createOptions: CredentialCreationOptions = { publicKey: pubKeyOptions }

  let cred: PublicKeyCredential
  try {
    const result = await create(createOptions)
    if (!result) throw new WebAuthnError('Credential creation returned null')
    cred = result as PublicKeyCredential
  } catch (err) {
    if (err instanceof WebAuthnError) throw err
    throw new WebAuthnError(`Passkey registration failed: ${(err as Error).message}`)
  }

  const response = cred.response as AuthenticatorAttestationResponse
  const extensionResults = cred.getClientExtensionResults()

  let keyMaterial = extractPrfOutput(extensionResults)

  // Some authenticators (e.g. YubiKey) report prf.enabled=true during
  // registration but only return PRF output during authentication.
  // Fall back to an immediate assertion to obtain the PRF output.
  if (!keyMaterial || keyMaterial.length !== 32) {
    const credId = new Uint8Array(cred.rawId)
    const getOptions: CredentialRequestOptions = {
      publicKey: {
        rpId,
        challenge: randomBytes(32).buffer.slice(0) as ArrayBuffer,
        allowCredentials: [
          {
            type: 'public-key',
            id: credId.buffer.slice(0) as ArrayBuffer,
            transports: response.getTransports?.() as AuthenticatorTransport[] ?? [],
          },
        ],
        userVerification: 'required',
        timeout: options.timeout ?? 120000,
        extensions: prfAuthenticationExtension(prfInput),
      },
    }

    let assertion: PublicKeyCredential
    try {
      const result = await get(getOptions)
      if (!result) throw new WebAuthnError('Follow-up authentication returned null')
      assertion = result as PublicKeyCredential
    } catch (err) {
      if (err instanceof WebAuthnError) throw err
      throw new WebAuthnError(`Follow-up PRF authentication failed: ${(err as Error).message}`)
    }

    const assertionExtensions = assertion.getClientExtensionResults()
    keyMaterial = extractPrfOutput(assertionExtensions)
    if (!keyMaterial || keyMaterial.length !== 32) {
      // Credential was created but PRF is not supported — clean up the
      // orphaned credential via the Signal API so it doesn't appear in the
      // passkey picker. No-op on browsers without Signal API support.
      await signalUnknownCredential(rpId, new Uint8Array(cred.rawId))
      throw new PrfNotSupportedError('PRF output not available from this authenticator')
    }
  }

  const credentialId = new Uint8Array(cred.rawId)
  const transports = response.getTransports?.() as AuthenticatorTransport[] ?? []
  const backup = parseBackupFlags(response)

  const credential: KeytrCredential = {
    credentialId,
    credentialIdBase64url: base64url.encode(credentialId),
    rpId,
    transports,
    prfSupported: true,
    ...backup && { backupEligible: backup.backupEligible, backupState: backup.backupState },
  }

  return { credential, keyMaterial }
}
