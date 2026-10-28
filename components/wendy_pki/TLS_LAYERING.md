# TLS foundation staging

Direct DER identity/trust and bounded TLS buffer ownership are integrated here.
The following layer replaces the synchronous baseline crypto facade with the
serialized worker and context admission; premature native actor enable fails
to compile. Existing baseline TLS callers retain synchronous behavior. Issuer
negotiation is now enabled only for exactly shared pinned issuer sets; every
other connection streams its ordinary full chain.

Keep existing legacy leaf byte/signature behavior under its existing compile
flag until final native activation removes that component. This is temporary
source staging, never an old/new wire negotiation or a new compatibility lane.
Future operator-origin proof APIs and diagnostic probes are excluded from the
initial product extraction; baseline operator TLS/Cloud authorization remains.
