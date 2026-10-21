import { type Event } from 'nostr-tools/pure';
import { type KeytrEventTemplate } from '../types.js';
import { type NpkType } from '../crypto/npk.js';
/** `v` tag value of a stored-record event */
export declare const NPK_EVENT_VERSION = "npk1";
/**
 * Unsigned kind:31777 template for a stored record, signed by its author.
 * Credential IDs in `d` and `credential` are unpadded base64url, as WebAuthn writes them.
 */
export declare function buildNpkEvent(options: {
    record: Uint8Array;
    credentialId: Uint8Array;
    rpId: string;
}): KeytrEventTemplate;
/**
 * Check a stored-record event against the author, RP and credential the
 * caller expects, then its signature. Returns the record bytes and type.
 */
export declare function verifyNpkEvent(event: Event, expected: {
    author: string;
    rpId: string;
    credentialId: Uint8Array;
}): {
    type: NpkType;
    record: Uint8Array;
};
//# sourceMappingURL=npk.d.ts.map