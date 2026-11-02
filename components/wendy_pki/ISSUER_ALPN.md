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
acknowledging which client CAs it can omit. When a hash-bearing variant is selected, the server independently omits its own
CA certificates advertised by the client. Selecting ordinary ALPN requests full
leaf-and-intermediate presentations in both directions, even if the client also
offered cached inventory names. Paths contain at most eight CA hashes;
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

A local certificate verification failure whose only flag is an untrusted issuer
path pauses certificate hints process-wide for 120 seconds. Known expiry,
not-yet-valid, revocation, usage, name and other policy flags exclude recovery,
including when combined with the untrusted-path flag. Generic peer alerts and
transport errors do not start recovery. The cause need not be a hash collision;
unavailable issuers or an ordinary trust configuration problem can look the same.

During the cooldown clients offer only the ordinary service name; servers select
ordinary ALPN and send their complete usual presentation, including all
intermediates. Cache contents and trust anchors remain intact, verification is
unchanged, and reconnects use the existing retry policy. The rejecting endpoint
alone can request a full exchange in either TLS role. Failures inside the window
do not prolong it, and new handshakes resume hints at the monotonic deadline.
The controller uses bounded atomic RAM state, with no peer map, timer or flash
writes. Lite resumption remains disabled.
