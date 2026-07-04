# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.8.x   | ✅ (PRF mode) |
| ≤ 0.7.x | ❌ (KiH mode — see advisory below) |

## Reporting a vulnerability

Please report security issues privately via **GitHub Security Advisories**
(<https://github.com/sovITxyz/keytr/security/advisories/new>) or by email to
**security@sovit.xyz**. Do not open a public issue for undisclosed
vulnerabilities. We aim to acknowledge reports within 72 hours.

Because keytr encrypts Nostr private keys, please include the affected version,
the browser/authenticator, and whether the issue requires attacker-controlled
script execution on the page (see the threat model below).

## Threat model

keytr encrypts your nsec client-side and publishes only the ciphertext to
public Nostr relays. Relays are treated as **untrusted, opaque storage** — the
published `kind:31777` blob is not decryptable from relay data alone.

The trust boundary is the **page's JavaScript execution environment**. Any code
that runs in your origin — injected via XSS, a malicious browser extension, or a
compromised dependency in the *consuming app* — can observe key material and the
decrypted nsec while you are logged in. keytr hardens against specific
interception techniques (see below) but cannot defend an already-compromised
page. Deploy keytr behind a strict Content-Security-Policy.

## Advisory: KiH key material interception (fixed in 0.8.0)

**Affected:** all versions **≤ 0.7.1** using Key-in-Handle (KiH) mode.
**Fixed in:** **0.8.0** (PRF-only).
**Severity:** Moderate–High (high impact; requires page-level code execution).

### Summary

In KiH mode the 32-byte AES key was stored inside the passkey's `user.id` and
returned to the page as `userHandle` on every login. Script running in the
page's origin could read that key material during a registration or login and
then decrypt the user's public `kind:31777` (`v=3`) blob offline, recovering the
nsec.

### Impact and preconditions

- **Not remotely/passively exploitable.** A genuine keytr build never publishes
  key material, so the existing corpus of `v=3` events on relays cannot be
  decrypted from relay data alone.
- Exploitation requires **attacker-controlled code executing in the victim's
  origin** (XSS, malicious extension, or a compromised dependency) **and** the
  victim performing a registration/login on that compromised page.

### Resolution

- **PRF mode is now the only registration mode.** The encryption key is derived
  inside the authenticator (WebAuthn PRF extension) and does not sit in
  `user.id`, eliminating the `userHandle` interception vector.
- **Limitation (honest caveat):** the *decrypted* nsec is still returned to the
  application, so a compromised page can always read the key once decryption
  happens. PRF removes the pre-decryption key-material exposure; it does not make
  a compromised environment safe. A strict CSP remains the highest-leverage
  mitigation.
- Additional hardening (0.7.1+): WebAuthn calls use native references captured at
  import time, and key buffers are zeroed via prototype-pollution-resistant
  helpers.

### What existing (KiH) users should do

Upgrade to `@sovit.xyz/keytr@0.8.0` and run **`migrateFromKih()`**, which
re-encrypts your nsec under a new PRF passkey, publishes the new `v=1` event, and
issues a NIP-09 deletion for the old KiH event. KiH decryption still works in
0.8.0 to enable this migration and will be removed in a future release.
