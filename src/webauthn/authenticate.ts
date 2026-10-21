import { bytesToHex } from '@noble/hashes/utils.js'
import type { AuthenticateOptions, DiscoverOptions, DiscoverResult } from '../types.js'
import { DEFAULT_RP_ID, PRF_SALT } from '../types.js'
import { WebAuthnError, PrfNotSupportedError } from '../errors.js'
import { prfAuthenticationExtension, extractPrfOutput } from './prf.js'
import { detectMode, extractKey } from './kih.js'
import { NPK_STORE_PRF_INPUT } from '../crypto/npk.js'
import { ensureBrowser } from './support.js'
import { nativeGet } from './natives.js'

function getNative(): typeof navigator.credentials.get {
  return nativeGet ?? navigator.credentials.get.bind(navigator.credentials)
}

/**
 * Authenticate with an existing PRF passkey and obtain the PRF output
 * for decrypting the nsec.
 *
 * @returns 32-byte PRF output for key derivation
 */
export async function authenticatePasskey(
  options: AuthenticateOptions
): Promise<Uint8Array> {
  return authenticatePrf(options, PRF_SALT)
}

/**
 * Targeted assertion that evaluates the PRF with a chosen input. keytr v1
 * uses "keytr-v1" (authenticatePasskey); stored npk1 records use
 * NPK_STORE_PRF_INPUT.
 *
 * @returns 32-byte PRF output
 */
export async function authenticatePrf(
  options: AuthenticateOptions,
  prfInput: Uint8Array
): Promise<Uint8Array> {
  ensureBrowser()

  const { credentialId, rpId, transports } = options

  const pubKeyOptions: PublicKeyCredentialRequestOptions = {
    rpId,
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: [
      {
        type: 'public-key',
        id: credentialId.buffer as ArrayBuffer,
        transports: transports ?? [],
      },
    ],
    userVerification: 'required',
    timeout: options.timeout ?? 120000,
    extensions: prfAuthenticationExtension(prfInput),
  }

  if (options.hints?.length) {
    ;(pubKeyOptions as any).hints = options.hints
  }

  const getOptions: CredentialRequestOptions = { publicKey: pubKeyOptions }
  const get = getNative()

  let assertion: PublicKeyCredential
  try {
    const result = await get(getOptions)
    if (!result) throw new WebAuthnError('Authentication returned null')
    assertion = result as PublicKeyCredential
  } catch (err) {
    if (err instanceof WebAuthnError) throw err
    throw new WebAuthnError(`Passkey authentication failed: ${(err as Error).message}`)
  }

  const extensionResults = assertion.getClientExtensionResults()
  const prfOutput = extractPrfOutput(extensionResults)

  if (!prfOutput || prfOutput.length !== 32) {
    throw new PrfNotSupportedError(
      'PRF output not available during authentication. ' +
      'The authenticator may not support PRF.'
    )
  }

  return prfOutput
}

/**
 * Legacy KiH targeted authentication (decrypt-only).
 *
 * Used for existing Key-in-Handle credentials during login and migration.
 * Extracts the 32-byte encryption key from the userHandle. No PRF extension.
 *
 * @returns 32-byte encryption key from userHandle
 */
export async function kihAuthenticatePasskey(
  options: AuthenticateOptions
): Promise<Uint8Array> {
  ensureBrowser()

  const { credentialId, rpId, transports } = options

  const pubKeyOptions: PublicKeyCredentialRequestOptions = {
    rpId,
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: [
      {
        type: 'public-key',
        id: credentialId.buffer as ArrayBuffer,
        transports: transports ?? [],
      },
    ],
    userVerification: 'required',
    timeout: options.timeout ?? 120000,
  }

  if (options.hints?.length) {
    ;(pubKeyOptions as any).hints = options.hints
  }

  const getOptions: CredentialRequestOptions = { publicKey: pubKeyOptions }
  const get = getNative()

  let assertion: PublicKeyCredential
  try {
    const result = await get(getOptions)
    if (!result) throw new WebAuthnError('Authentication returned null')
    assertion = result as PublicKeyCredential
  } catch (err) {
    if (err instanceof WebAuthnError) throw err
    throw new WebAuthnError(`Passkey authentication failed: ${(err as Error).message}`)
  }

  const response = assertion.response as AuthenticatorAssertionResponse
  if (!response.userHandle || response.userHandle.byteLength === 0) {
    throw new WebAuthnError(
      'Authenticator did not return a userHandle — cannot extract encryption key'
    )
  }

  return extractKey(new Uint8Array(response.userHandle))
}

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
export async function discoverPasskey(
  options?: DiscoverOptions
): Promise<DiscoverResult> {
  ensureBrowser()

  const rpId = options?.rpId ?? DEFAULT_RP_ID
  const timeout = options?.timeout ?? 120000
  const get = getNative()

  // Step 1: Discovery — no PRF, empty allowCredentials
  const assertion = await discoveryAssertion(options)

  const response = assertion.response as AuthenticatorAssertionResponse
  if (!response.userHandle || response.userHandle.byteLength === 0) {
    throw new WebAuthnError('Authenticator did not return a userHandle')
  }

  const userHandle = new Uint8Array(response.userHandle)
  const credentialId = new Uint8Array(assertion.rawId)
  const mode = detectMode(userHandle)

  if (mode === 'kih') {
    // Legacy KiH: key is in the userHandle, no step 2 needed
    const keyMaterial = extractKey(userHandle)
    return { keyMaterial, credentialId, mode: 'kih' }
  }

  // PRF mode: userHandle is the pubkey, need step 2 for the PRF output
  const pubkey = bytesToHex(userHandle)

  const prfOptions: CredentialRequestOptions = {
    publicKey: {
      rpId,
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [
        {
          type: 'public-key',
          id: credentialId.buffer as ArrayBuffer,
        },
      ],
      userVerification: 'required',
      timeout,
      extensions: prfAuthenticationExtension(),
    },
  }

  let prfAssertion: PublicKeyCredential
  try {
    const result = await get(prfOptions)
    if (!result) throw new WebAuthnError('PRF follow-up authentication returned null')
    prfAssertion = result as PublicKeyCredential
  } catch (err) {
    if (err instanceof WebAuthnError) throw err
    throw new WebAuthnError(`PRF follow-up authentication failed: ${(err as Error).message}`)
  }

  const extensionResults = prfAssertion.getClientExtensionResults()
  const prfOutput = extractPrfOutput(extensionResults)

  if (!prfOutput || prfOutput.length !== 32) {
    throw new PrfNotSupportedError(
      'PRF output not available during discoverable authentication. ' +
      'The authenticator may not support PRF.'
    )
  }

  return { keyMaterial: prfOutput, credentialId, mode: 'prf', pubkey }
}

/** Discoverable assertion with empty allowCredentials, optionally asking for the PRF in the same ceremony. */
async function discoveryAssertion(options?: DiscoverOptions, prfInput?: Uint8Array): Promise<PublicKeyCredential> {
  const pubKeyOptions: PublicKeyCredentialRequestOptions = {
    rpId: options?.rpId ?? DEFAULT_RP_ID,
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: [],
    userVerification: 'required',
    timeout: options?.timeout ?? 120000,
  }
  if (prfInput) pubKeyOptions.extensions = prfAuthenticationExtension(prfInput)

  if (options?.hints?.length) {
    ;(pubKeyOptions as any).hints = options.hints
  }

  const discoveryOptions: CredentialRequestOptions = { publicKey: pubKeyOptions }
  if (options?.mediation) discoveryOptions.mediation = options.mediation

  try {
    const result = await getNative()(discoveryOptions)
    if (!result) throw new WebAuthnError('Discoverable authentication returned null')
    return result as PublicKeyCredential
  } catch (err) {
    if (err instanceof WebAuthnError) throw err
    throw new WebAuthnError(`Discoverable passkey authentication failed: ${(err as Error).message}`)
  }
}

/**
 * Discoverable assertion for stored npk1 passkeys: asks for the stored-mode
 * PRF output in the same ceremony and returns the raw handle without
 * interpreting it. `prfOutput` is null when the platform did not evaluate the
 * PRF here (many do not with empty allowCredentials); use authenticatePrf().
 */
export async function discoverStoredPasskey(options?: DiscoverOptions): Promise<{
  credentialId: Uint8Array
  userHandle: Uint8Array | null
  prfOutput: Uint8Array | null
}> {
  ensureBrowser()
  const assertion = await discoveryAssertion(options, NPK_STORE_PRF_INPUT)
  const handle = (assertion.response as AuthenticatorAssertionResponse).userHandle
  const output = extractPrfOutput(assertion.getClientExtensionResults())
  return {
    credentialId: new Uint8Array(assertion.rawId),
    userHandle: handle && handle.byteLength > 0 ? new Uint8Array(handle) : null,
    prfOutput: output && output.length === 32 ? output : null,
  }
}
