export class KeytrError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'KeytrError'
  }
}

/** Thrown when the authenticator does not support the WebAuthn PRF extension */
export class PrfNotSupportedError extends KeytrError {
  constructor(reason?: string) {
    super(reason ?? 'WebAuthn PRF extension is not supported by this authenticator')
    this.name = 'PrfNotSupportedError'
  }
}

/**
 * Thrown when KiH (Key-in-Handle) registration is attempted.
 *
 * KiH registration was removed in keytr v0.8.0 because the encryption key,
 * stored in the passkey user.id, is interceptable in JavaScript memory.
 * New passkeys use the PRF strategy (the default). Existing KiH users can
 * still log in and should call migrateFromKih() to upgrade; KiH decryption
 * will be removed in a future release.
 */
export class KihRegistrationDisabledError extends KeytrError {
  constructor() {
    super(
      'KiH registration was removed in keytr v0.8.0 (the encryption key was interceptable in JS memory). ' +
      'New passkeys use PRF (the default strategy). Existing KiH users can still log in and should call ' +
      'migrateFromKih() to upgrade. KiH decryption will be removed in a future release.'
    )
    this.name = 'KihRegistrationDisabledError'
  }
}

export class EncryptionError extends KeytrError {
  constructor(message: string) {
    super(message)
    this.name = 'EncryptionError'
  }
}

export class DecryptionError extends KeytrError {
  constructor(message: string) {
    super(message)
    this.name = 'DecryptionError'
  }
}

export class BlobParseError extends KeytrError {
  constructor(message: string) {
    super(message)
    this.name = 'BlobParseError'
  }
}

export class WebAuthnError extends KeytrError {
  constructor(message: string) {
    super(message)
    this.name = 'WebAuthnError'
  }
}

export class RelayError extends KeytrError {
  constructor(message: string) {
    super(message)
    this.name = 'RelayError'
  }
}

/**
 * A passkey keytr refuses after classifying its handle (passkey-held Nostr
 * keys proposal). keytr only reads and writes stored mode, so it never
 * computes a key from these passkeys or turns them into a new identity.
 */
export class PasskeyModeError extends KeytrError {
  constructor(
    readonly reason: 'derived' | 'unsupported' | 'unknown' | 'record-not-found',
    detail?: string
  ) {
    super({
      derived: 'This passkey derives its Nostr key directly and was made by a different app. Log in with the app that created it',
      unsupported: 'This passkey was made by a newer or different app and cannot be used here',
      unknown: 'No keytr record was found for this passkey, and its handle does not say how it holds its key',
      'record-not-found': 'This passkey stores an encrypted key, but its record could not be found on the given relays',
    }[reason] + (detail ? ` (${detail}).` : '.'))
    this.name = 'PasskeyModeError'
  }
}
