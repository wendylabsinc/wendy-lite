These are public, self-signed ECDSA test certificates generated with OpenSSL.
Private keys were discarded. They test only the post-TLS operator identity
check; they are not trust anchors or enrollment credentials.

The cases cover a valid operator URI, a device URI, duplicate URI SANs,
serverAuth without clientAuth, and a CA certificate. The native test also
checks a different tenant and truncated DER. Certificate time and chain
verification are performed separately by the TLS handshake.
