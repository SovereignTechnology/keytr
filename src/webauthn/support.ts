import type { PrfSupportInfo, WebAuthnCapabilities } from '../types.js'
import { WebAuthnError } from '../errors.js'

/**
 * Throw if WebAuthn is not available (SSR / Node.js / non-browser environment).
 * Call at the top of any function that touches navigator.credentials.
 */
export function ensureBrowser(): void {
  if (typeof navigator === 'undefined' || typeof navigator.credentials?.create !== 'function') {
    throw new WebAuthnError('WebAuthn is not available in this environment (SSR/Node.js)')
  }
}

/**
 * Check whether the browser/authenticator supports the WebAuthn PRF extension,
 * which keytr requires for registration.
 *
 * Uses getClientCapabilities() for an accurate answer when available (Chrome
 * 132+); otherwise reports optimistically and defers the real check to
 * registration time (where a create→get fallback confirms PRF output).
 */
export async function checkPrfSupport(): Promise<PrfSupportInfo> {
  if (typeof window === 'undefined' || !window.PublicKeyCredential) {
    return { supported: false, platformAuthenticator: false, reason: 'WebAuthn not available' }
  }

  let platformAuthenticator = false
  try {
    platformAuthenticator = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
  } catch {
    // Not critical, continue
  }

  const hasCredentialsApi = typeof navigator.credentials?.create === 'function'
  if (!hasCredentialsApi) {
    return { supported: false, platformAuthenticator, reason: 'Credentials API not available' }
  }

  // Use getClientCapabilities() for accurate PRF detection when available (Chrome 132+)
  const caps = await _getRawCapabilities()
  if (caps && typeof caps['extensions.prf'] === 'boolean') {
    return {
      supported: caps['extensions.prf'],
      platformAuthenticator,
      reason: caps['extensions.prf'] ? undefined : 'Browser reports PRF extension not supported',
    }
  }

  // Fallback: report optimistically and confirm at registration time
  return { supported: true, platformAuthenticator }
}

/**
 * Comprehensive capability check using getClientCapabilities() (Chrome 132+).
 * Falls back to feature detection for browsers without getClientCapabilities().
 */
export async function checkCapabilities(): Promise<WebAuthnCapabilities> {
  if (typeof window === 'undefined' || !window.PublicKeyCredential) {
    return {
      webauthn: false,
      platformAuthenticator: false,
      prf: null,
      conditionalMediation: false,
      relatedOrigins: false,
      signalApi: false,
    }
  }

  let platformAuthenticator = false
  try {
    platformAuthenticator = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
  } catch {
    // ignore
  }

  // Try getClientCapabilities() for accurate browser-reported capabilities
  const caps = await _getRawCapabilities()
  if (caps) {
    return {
      webauthn: true,
      platformAuthenticator,
      prf: typeof caps['extensions.prf'] === 'boolean' ? caps['extensions.prf'] : null,
      conditionalMediation: caps['conditionalGet'] === true,
      relatedOrigins: caps['relatedOrigins'] === true,
      signalApi: caps['signalAllAcceptedCredentialIds'] === true
        || caps['signalUnknownCredential'] === true,
    }
  }

  // Fallback: feature-detect what we can
  let conditionalMediation = false
  try {
    if (typeof (PublicKeyCredential as any).isConditionalMediationAvailable === 'function') {
      conditionalMediation = await (PublicKeyCredential as any).isConditionalMediationAvailable()
    }
  } catch {
    // ignore
  }

  return {
    webauthn: true,
    platformAuthenticator,
    prf: null, // Can't detect without creating a credential
    conditionalMediation,
    relatedOrigins: null, // Can't detect without getClientCapabilities
    signalApi: typeof (PublicKeyCredential as any).signalUnknownCredential === 'function',
  }
}

/** Internal: call getClientCapabilities() if available */
async function _getRawCapabilities(): Promise<Record<string, boolean> | null> {
  try {
    if (typeof (PublicKeyCredential as any).getClientCapabilities === 'function') {
      return await (PublicKeyCredential as any).getClientCapabilities()
    }
  } catch {
    // ignore
  }
  return null
}
