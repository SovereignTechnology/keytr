import { type Event } from 'nostr-tools/pure';
import { type KeytrCredential, type KeytrEventTemplate } from '../types.js';
import { type PayloadContext } from '../crypto/payload.js';
/** Separate coordinates keep a vault from replacing the same credential's nsec. */
export declare function payloadDTag(context: Pick<PayloadContext, 'credentialId' | 'payloadType' | 'schema'>): string;
export declare function buildPayloadEvent(options: {
    credential: KeytrCredential;
    pubkey: string;
    payloadType: PayloadContext['payloadType'];
    schema: string;
    encryptedBlob: string;
    clientName?: string;
}): KeytrEventTemplate;
/** Parse public metadata; this does not authenticate an unsigned template. */
export declare function parsePayloadEvent(event: {
    kind: number;
    content: string;
    tags: string[][];
    pubkey: string;
}): PayloadContext & {
    encryptedBlob: string;
};
/** The expected author/RP/type/schema come from the application or discovered credential. */
export declare function verifyPayloadEvent(event: Event, expected: Omit<PayloadContext, 'credentialId'> & {
    credentialId?: Uint8Array;
}): ReturnType<typeof parsePayloadEvent>;
//# sourceMappingURL=payload.d.ts.map