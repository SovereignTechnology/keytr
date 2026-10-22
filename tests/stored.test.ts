import { it, expect, vi } from 'vitest'
import { finalizeEvent } from 'nostr-tools/pure'
import { hexToBytes } from '@noble/hashes/utils.js'
import { encryptNpkRecord } from '../src/crypto/npk.js'
import vectors from './passkey-conformance-vectors.json'
const state = vi.hoisted(() => ({ events: [] as any[] }))
vi.mock('../src/nostr/relay.js', () => ({ fetchKeytrEvents: vi.fn(async () => state.events), fetchStoredEvents: vi.fn(async () => state.events) }))
vi.mock('../src/webauthn/authenticate.js', () => ({ discoverStoredPasskey: vi.fn(), authenticatePrf: vi.fn() }))
import { discoverStoredPasskey } from '../src/webauthn/authenticate.js'
import { discoverStored } from '../src/stored.js'

it('does not restore an older vault when the newest signed coordinate is malformed', async () => {
  const v = vectors.stored.records[0]
  const sk = hexToBytes(vectors.relay.signed_event.secret_key)
  const credentialId = hexToBytes(v.credential_id)
  const userHandle = new Uint8Array([0x4e,0x50,0x4b,1,2,...hexToBytes(v.author)])
  vi.mocked(discoverStoredPasskey).mockResolvedValue({ credentialId, userHandle, prfOutput: hexToBytes(v.prf_output) } as any)
  const tags = [['d', `${Buffer.from(credentialId).toString('base64url')}:vault`], ['rp', v.rp_id]]
  const old = encryptNpkRecord({ type:'vault', plaintext:new TextEncoder().encode(JSON.stringify({ accounts:[{kind:'key',secret:vectors.relay.signed_event.secret_key}] })), keyMaterial:hexToBytes(v.prf_output), rpId:v.rp_id, author:v.author, credentialId })
  state.events = [finalizeEvent({ kind:31778, created_at:1, tags, content:Buffer.from(old).toString('base64') }, sk), finalizeEvent({ kind:31778, created_at:2, tags, content:'broken-newest' }, sk)]
  await expect(discoverStored([], { rpId:v.rp_id })).rejects.toThrow(/base64|stored-record/)
})

it('prefers an eligible vault over a newer immutable key record', async () => {
  const v = vectors.stored.records[0]
  const sk = hexToBytes(vectors.relay.signed_event.secret_key)
  const credentialId = hexToBytes(v.credential_id)
  vi.mocked(discoverStoredPasskey).mockResolvedValue({ credentialId, userHandle:new Uint8Array([0x4e,0x50,0x4b,1,2,...hexToBytes(v.author)]), prfOutput:hexToBytes(v.prf_output) } as any)
  const old = encryptNpkRecord({ type:'vault', plaintext:new TextEncoder().encode(JSON.stringify({ accounts:[{kind:'key',secret:vectors.relay.signed_event.secret_key}] })), keyMaterial:hexToBytes(v.prf_output), rpId:v.rp_id, author:v.author, credentialId })
  const id = Buffer.from(credentialId).toString('base64url')
  state.events = [finalizeEvent({ kind:31778, created_at:1, tags:[['d',`${id}:vault`]], content:Buffer.from(old).toString('base64') },sk), finalizeEvent({ kind:31778, created_at:2, tags:[['d',`${id}:key`]], content:v.record_base64 },sk)]
  expect((await discoverStored([], {rpId:v.rp_id})).secret.type).toBe('vault')
})
