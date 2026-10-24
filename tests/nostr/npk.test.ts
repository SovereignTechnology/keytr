import { describe, it, expect } from 'vitest'
import { hexToBytes } from '@noble/hashes/utils.js'
import { base64 } from '@scure/base'
import { finalizeEvent } from 'nostr-tools/pure'
import vectors from '../fixtures/passkey-key-mode-vectors.json'
import { buildNpkEvent, verifyNpkEvent } from '../../src/nostr/npk.js'
import { parseKeytrEvent } from '../../src/nostr/event.js'

const v = vectors.stored.records[0]
const secret = hexToBytes(v.plaintext) // private key 1, author 79be...
const credentialId = hexToBytes(v.credential_id)
const record = hexToBytes(v.record)
const expected = { author: v.author, rpId: v.rp_id, credentialId }

function signed(tags?: (t: string[][]) => string[][], content?: string) {
  const template = buildNpkEvent({ record, credentialId, rpId: v.rp_id })
  return finalizeEvent({ ...template, tags: tags ? tags(template.tags) : template.tags, content: content ?? template.content }, secret)
}

describe('npk1 events', () => {
  it('builds kind 31778 with the spec tags and base64 content', () => {
    const event = buildNpkEvent({ record, credentialId, rpId: v.rp_id })
    expect(event.kind).toBe(31778)
    expect(event.content).toBe(v.record_base64)
    expect(event.tags).toEqual([
      ['d', 'qqqqqqqqqqqqqqqqqqqqqg:key'],
      ['rp', 'example.com'],
    ])
  })

  it('verifies a signed event and returns its record', () => {
    const event = signed()
    expect(event.pubkey).toBe(v.author)
    expect(verifyNpkEvent(event, expected)).toEqual({ type: 'key', record })
  })

  it.each([
    ['padded credential', (t: string[][]) => t.map(x => x[0] === 'credential' ? ['credential', 'qqqqqqqqqqqqqqqqqqqqqg=='] : x[0] === 'd' ? ['d', 'qqqqqqqqqqqqqqqqqqqqqg==:key'] : x)],
    ['v', (t: string[][]) => [...t, ['v', '1']]],
    ['d mismatch', (t: string[][]) => t.map(x => x[0] === 'd' ? ['d', 'qqqqqqqqqqqqqqqqqqqqqg:seed'] : x)],
    ['type mismatch with record', (t: string[][]) => t.map(x => x[0] === 'type' ? ['type', 'seed'] : x[0] === 'd' ? ['d', 'qqqqqqqqqqqqqqqqqqqqqg:seed'] : x)],
  ])('rejects %s', (_name, mutate) => {
    expect(() => verifyNpkEvent(signed(mutate), expected)).toThrow()
  })

  it('rejects bad content, wrong context and a bad signature', () => {
    expect(() => verifyNpkEvent(signed(undefined, '!!'), expected)).toThrow()
    expect(() => verifyNpkEvent(signed(undefined, base64.encode(record.subarray(0, 60))), expected)).toThrow()
    const event = signed()
    expect(() => verifyNpkEvent(event, { ...expected, author: 'ab'.repeat(32) })).toThrow(/context/)
    expect(() => verifyNpkEvent(event, { ...expected, rpId: 'example.org' })).toThrow(/context/)
    expect(() => verifyNpkEvent(event, { ...expected, credentialId: new Uint8Array(16) })).toThrow(/credential/)
    expect(() => verifyNpkEvent({ ...event, sig: '0'.repeat(128) }, expected)).toThrow(/signature/)
  })

  it('is rejected by the v1 event parser, so v1 clients never read it as an nsec event', () => {
    expect(() => parseKeytrEvent(signed())).toThrow(/kind 31777/)
  })
})
