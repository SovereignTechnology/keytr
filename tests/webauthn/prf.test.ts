import { describe, it, expect } from 'vitest'
import {
  prfRegistrationExtension,
  prfAuthenticationExtension,
  extractPrfOutput,
  isPrfEnabled,
} from '../../src/webauthn/prf.js'
import { PRF_SALT } from '../../src/types.js'
import { randomBytes } from '@noble/hashes/utils.js'

describe('prf extension builders', () => {
  it('registration extension carries the PRF salt as prf.eval.first', () => {
    const ext = prfRegistrationExtension() as any
    expect(new Uint8Array(ext.prf.eval.first)).toEqual(PRF_SALT)
  })

  it('authentication extension carries the same PRF salt', () => {
    const ext = prfAuthenticationExtension() as any
    expect(new Uint8Array(ext.prf.eval.first)).toEqual(PRF_SALT)
  })

  it('PRF_SALT is utf8("keytr-v1")', () => {
    expect(PRF_SALT).toEqual(new TextEncoder().encode('keytr-v1'))
  })
})

describe('extractPrfOutput', () => {
  it('refuses output when PRF is explicitly disabled', () => {
    const result = { prf: { enabled: false, results: { first: new ArrayBuffer(32) } } } as any
    expect(extractPrfOutput(result)).toBeNull()
    expect(isPrfEnabled(result)).toBe(false)
  })

  it('returns null when there is no prf extension result', () => {
    expect(extractPrfOutput({} as any)).toBeNull()
  })

  it('returns null when prf is enabled but has no results (registration-only)', () => {
    expect(extractPrfOutput({ prf: { enabled: true } } as any)).toBeNull()
  })

  it('returns a 32-byte Uint8Array from prf.results.first', () => {
    const out = randomBytes(32)
    const result = extractPrfOutput({ prf: { results: { first: out.buffer.slice(0) } } } as any)
    expect(result).toBeInstanceOf(Uint8Array)
    expect(result).toEqual(out)
  })
})

describe('isPrfEnabled', () => {
  it('true when prf.enabled === true', () => {
    expect(isPrfEnabled({ prf: { enabled: true } } as any)).toBe(true)
  })

  it('true when prf.results.first is present', () => {
    expect(isPrfEnabled({ prf: { results: { first: new ArrayBuffer(32) } } } as any)).toBe(true)
  })

  it('false when there is no prf output', () => {
    expect(isPrfEnabled({} as any)).toBe(false)
    expect(isPrfEnabled({ prf: { enabled: false } } as any)).toBe(false)
  })
})
