# TLS identity and connection layers

Identity certificates and trust material use DER directly in storage, on the
mesh wire and in the TLS library. Connections with exactly shared pinned issuer
sets can omit the shared issuer chain; other connections send their full chain.

A carrier authenticates neighbouring peers. A routed service connection has
its own end-to-end TLS session with the destination, independent of the route's
intermediate peers. WendyCom runs directly inside that destination session and
does not add another TLS wrapper. Physical and Cloud management retain their
existing authentication paths.

Heavy TLS and signature operations use the
[serialized crypto worker](CRYPTO_WORKER.md) while mesh is running. Existing
management callers can operate synchronously when it is off. A lent TLS context
has one owner until completion; unrelated established TLS connections remain
available to the mesh task.

The special leaf protocol is removed. Lite uses ordinary signed device manifests
and authenticated router connections; there is no legacy leaf compatibility mode.
