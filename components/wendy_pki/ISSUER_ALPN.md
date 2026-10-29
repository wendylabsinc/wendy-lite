# Known CA certificates during TLS setup

Fresh carrier, guest VIP and native WendyCom TLS handshakes transmit the leaf
and only the missing CA certificates. Locally held intermediates remain untrusted
path candidates: ordinary verification must still reach the configured anchors
and enforce the original identity, tenant and validity checks.

The wire format matches WendyOS. Each application protocol variant is:

```
application protocol | 00 57 43 49 01 | CA fingerprints
```

A fingerprint is the first 16 bytes of SHA-256 over the complete certificate DER.
The client's own path is ordered root first through its intermediates, excluding
the leaf. It offers the longest prefix first, shorter prefixes, then the ordinary
application protocol. The server selects the longest prefix it holds, explicitly
acknowledging which client CAs it can omit. The server independently omits its own
CA certificates advertised by the client. Paths contain at most eight CA hashes;
each ALPN name stays within 255 bytes.

Other resident cached CAs use auxiliary names beginning with `wendy-net-cached`,
a zero byte and up to eight concatenated fingerprints. These names are never
selected as an application. Lite advertises at most 24 available CA hashes,
including its own material, with at most eight loans from the existing RAM
certificate store. There is no base64 encoding.

The actor loans immutable resident CA bytes before handing a TLS context to the
crypto worker. The TLS library parses cached DER without copying it, and the
store cannot evict an actively loaned part. Loans survive cache shutdown and
release after verification or connection cleanup. Missing or evicted blobs are
not fetched just to prepare a handshake. Optional allocation failure uses an
ordinary certificate exchange.

Own certificates continue to stream as DER through the verified source callback.
A partial chain can omit common parents while retaining a different final issuing
CA. Nothing assumes that an entire tenant has the same issuing path. State and
ALPN buffers belong to the connection and drain on cancellation or close; there
are no new flash writes or allocations while Wendy Net is off.

The tracked Mbed TLS patches support opaque ALPN names with explicit lengths and
untrusted issuer candidates. They preserve normal certificate validation. Lite
TLS session resumption remains disabled; see the separate resumption follow-up.
