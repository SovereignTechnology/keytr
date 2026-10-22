import { base64, base64urlnopad } from '@scure/base';
import { verifyEvent } from 'nostr-tools/pure';
import { KEYTR_EVENT_KIND } from '../types.js';
import { KeytrError } from '../errors.js';
import { NPK_MAX_RECORD_BYTES, npkRecordType } from '../crypto/npk.js';
/** `v` tag value of a stored-record event */
export const NPK_EVENT_VERSION = 'npk1';
/** Provisional new kind, pending upstream assignment. */
export const NPK_EVENT_KIND = 31778;
/**
 * Unsigned kind:31777 template for a stored record, signed by its author.
 * Credential IDs in `d` and `credential` are unpadded base64url, as WebAuthn writes them.
 */
export function buildNpkEvent(options) {
    const type = npkRecordType(options.record);
    if (type === 'seed')
        throw new KeytrError('Seed-only identities must be written as vaults');
    const credential = base64urlnopad.encode(options.credentialId);
    return {
        kind: NPK_EVENT_KIND,
        content: base64.encode(options.record),
        tags: [['d', `${credential}:${type}`], ['rp', options.rpId]],
        created_at: Math.floor(Date.now() / 1000),
    };
}
/**
 * Check a stored-record event against the author, RP and credential the
 * caller expects, then its signature. Returns the record bytes and type.
 */
/** Validate signed coordinates before looking at the payload, so a corrupt latest vault cannot roll back. */
export function eligibleNpkEvent(event, expected) {
    if ((event.kind !== NPK_EVENT_KIND && event.kind !== KEYTR_EVENT_KIND) || !Array.isArray(event.tags))
        throw new KeytrError('Invalid stored-record event');
    const ds = event.tags.filter(t => t[0] === 'd');
    const credential = base64urlnopad.encode(expected.credentialId);
    const type = ds[0]?.[1]?.slice(credential.length + 1);
    if (ds.length !== 1 || ds[0][1] !== `${credential}:${type}` || !['key', 'vault', ...(event.kind === KEYTR_EVENT_KIND ? ['seed'] : [])].includes(type))
        throw new KeytrError('Unexpected stored-record credential');
    const versions = event.tags.filter(t => t[0] === 'v');
    if (event.kind === NPK_EVENT_KIND ? versions.length !== 0 : versions.length !== 1 || versions[0][1] !== NPK_EVENT_VERSION)
        throw new KeytrError('Not a stored-record event');
    if (event.pubkey !== expected.author || event.tags.some(t => t[0] === 'rp' && t[1] !== expected.rpId))
        throw new KeytrError('Unexpected stored-record context');
    const signed = { id: event.id, sig: event.sig, pubkey: event.pubkey, created_at: event.created_at, kind: event.kind, tags: event.tags.map(t => [...t]), content: event.content };
    if (!verifyEvent(signed))
        throw new KeytrError('Invalid stored-record event signature');
    return type;
}
export function verifyNpkEvent(event, expected) {
    const type = eligibleNpkEvent(event, expected);
    if (typeof event.content !== 'string' || event.content.length > 4 * Math.ceil(NPK_MAX_RECORD_BYTES / 3))
        throw new KeytrError('Stored-record content too large');
    let record;
    try {
        record = base64.decode(event.content);
    }
    catch {
        throw new KeytrError('Stored-record content is not base64');
    }
    if (base64.encode(record) !== event.content || npkRecordType(record) !== type)
        throw new KeytrError('Invalid stored-record content or type');
    return { type, record };
}
//# sourceMappingURL=npk.js.map