import type { PrfSupportInfo, WebAuthnCapabilities } from '../types.js';
/**
 * Throw if WebAuthn is not available (SSR / Node.js / non-browser environment).
 * Call at the top of any function that touches navigator.credentials.
 */
export declare function ensureBrowser(): void;
/**
 * Check whether the browser/authenticator supports the WebAuthn PRF extension,
 * which keytr requires for registration.
 *
 * Uses getClientCapabilities() for an accurate answer when available (Chrome
 * 132+); otherwise reports optimistically and defers the real check to
 * registration time (where a create→get fallback confirms PRF output).
 */
export declare function checkPrfSupport(): Promise<PrfSupportInfo>;
/**
 * Comprehensive capability check using getClientCapabilities() (Chrome 132+).
 * Falls back to feature detection for browsers without getClientCapabilities().
 */
export declare function checkCapabilities(): Promise<WebAuthnCapabilities>;
//# sourceMappingURL=support.d.ts.map