import { PRF_SALT } from '../types.js'

/**
 * Build the PRF extension input for credential creation (registration).
 * During registration, we use `eval` to test if PRF is supported
 * and get the first PRF output.
 */
export function prfRegistrationExtension(): AuthenticationExtensionsClientInputs {
  return {
    prf: {
      eval: {
        first: PRF_SALT.buffer as ArrayBuffer,
      },
    },
  } as AuthenticationExtensionsClientInputs
}

/**
 * Build the PRF extension input for credential assertion (authentication).
 * During authentication, we use `eval` to get the PRF output
 * for deriving the encryption/decryption key.
 */
export function prfAuthenticationExtension(): AuthenticationExtensionsClientInputs {
  return {
    prf: {
      eval: {
        first: PRF_SALT.buffer as ArrayBuffer,
      },
    },
  } as AuthenticationExtensionsClientInputs
}

/**
 * Extract the 32-byte PRF output from a WebAuthn extension result.
 * Returns null if PRF was not supported/returned by the authenticator.
 */
export function extractPrfOutput(
  extensionResults: AuthenticationExtensionsClientOutputs
): Uint8Array | null {
  const prf = (extensionResults as any)?.prf
  if (!prf?.results?.first) return null
  return new Uint8Array(prf.results.first)
}

/**
 * Check if PRF was enabled during registration from extension outputs.
 */
export function isPrfEnabled(
  extensionResults: AuthenticationExtensionsClientOutputs
): boolean {
  const prf = (extensionResults as any)?.prf
  // During registration, PRF support is indicated by `enabled: true`
  if (prf?.enabled === true) return true
  // Or by successfully returning results
  if (prf?.results?.first) return true
  return false
}
