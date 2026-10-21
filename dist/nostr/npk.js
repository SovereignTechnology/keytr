import { base64, base64urlnopad } from '@scure/base';
import { verifyEvent } from 'nostr-tools/pure';
import { KEYTR_EVENT_KIND } from '../types.js';
import { KeytrError } from '../errors.js';
import { NPK_MAX_RECORD_BYTES, npkRecordType } from '../crypto/npk.js';
/** `v` tag value of a stored-record event */
export const NPK_EVENT_VERSION = 'npk1';
/**
 * Unsigned kind:31777 template for a stored record, signed by its author.
 * Credential IDs in `d` and `credential` are unpadded base64url, as WebAuthn writes them.
 */
export function buildNpkEvent(options) {
    const type = npkRecordType(options.record);
    const credential = base64urlnopad.encode(options.credentialId);
    return {
        kind: KEYTR_EVENT_KIND,
        content: base64.encode(options.record),
        tags: [['d', `${credential}:${type}`], ['credential', credential], ['v', NPK_EVENT_VERSION], ['rp', options.rpId], ['type', type]],
        created_at: Math.floor(Date.now() / 1000),
    };
}
/**
 * Check a stored-record event against the author, RP and credential the
 * caller expects, then its signature. Returns the record bytes and type.
 */
export function verifyNpkEvent(event, expected) {
    if (event.kind !== KEYTR_EVENT_KIND || !Array.isArray(event.tags) || event.tags.length > 32)
        throw new KeytrError('Invalid stored-record event');
    const tag = (name) => {
        const found = event.tags.filter(t => Array.isArray(t) && t[0] === name);
        if (found.length !== 1 || typeof found[0][1] !== 'string')
            throw new KeytrError(`Missing or duplicate "${name}" tag`);
        return found[0][1];
    };
    const credential = base64urlnopad.encode(expected.credentialId);
    const type = tag('type');
    if (tag('v') !== NPK_EVENT_VERSION)
        throw new KeytrError('Not a stored-record event');
    if (event.pubkey !== expected.author)
        throw new KeytrError('Unexpected stored-record author');
    if (tag('rp') !== expected.rpId)
        throw new KeytrError('Unexpected stored-record relying party');
    if (tag('credential') !== credential || tag('d') !== `${credential}:${type}`)
        throw new KeytrError('Unexpected stored-record credential');
    if (typeof event.content !== 'string' || event.content.length > 4 * Math.ceil(NPK_MAX_RECORD_BYTES / 3)) {
        throw new KeytrError('Stored-record content too large');
    }
    let record;
    try {
        record = base64.decode(event.content);
    }
    catch {
        throw new KeytrError('Stored-record content is not base64');
    }
    if (npkRecordType(record) !== type)
        throw new KeytrError('Stored-record "type" tag does not match the record');
    // Copy only NIP-01 fields so a cached verification marker cannot skip the check.
    const signed = {
        id: event.id, sig: event.sig, pubkey: event.pubkey, created_at: event.created_at,
        kind: event.kind, tags: event.tags.map(t => [...t]), content: event.content,
    };
    if (!verifyEvent(signed))
        throw new KeytrError('Invalid stored-record event signature');
    return { type, record };
}
//# sourceMappingURL=npk.js.map