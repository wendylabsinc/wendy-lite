# Optional exact-anchor issuer omission

The carrier and application service ALPNs remain unchanged. A client may also
advertise `wendy-net-issuers/<digest>`, naming the sorted hashes of its presented
non-leaf certificates. Every named certificate must already be an exact,
independently provisioned local trust anchor. No hint is advertised when that
condition is absent, hashing fails, or optional state cannot be allocated.

A server omits its issuers only when the client's offered digest exactly
matches its own eligible issuer set. A client omits its issuers only after
verifying the server's certificate, CertificateVerify and Finished, observing
that the server sent one certificate, and matching its issuer name and authority
key identifier to the client's own leaf. The server still selects the real
service ALPN. Every peer undergoes the ordinary complete trust, identity and
validity checks; the hint adds no trust material.

Wire certificate count is retained before the TLS library compacts its parsed
peer chain. Own certificates continue to stream as binary DER through the
existing verified source callback; omission changes only where that callback
reports the end of its chain. Hint state and its ALPN pointers belong to one TLS
connection and are freed on both cancelled and established closes. There is no
new global cache, task, flash write or OFF allocation.

Automatic tail omission is limited to a provably self-signed CA exactly in local
trust. A non-root intermediate stays in an already-root-omitted source even
when it is locally pinned: another peer may trust only the common root.

The digest uses WendyOS's existing base64url representation of 16 hash bytes
(22 characters). This is an ALPN identifier, not encoded certificate or payload
material. Actual certificate, manifest and application bytes remain binary.

Current lab enrollment lacks the exact shared issuer anchors required for this
optimization, so no radio timing or RAM saving is claimed for those boards.
Normal host interop covers both TLS roles and both service ALPNs, shared issuers,
different issuer branches, an ordinary peer without the hint, partial local
trust, and cancellation before handshake. Fixtures use direct DER files and
verify complete ledger drain with the actual TLS allocation hooks installed.
