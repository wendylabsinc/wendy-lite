# Optional exact-anchor issuer omission

The service ALPN stays unchanged; an auxiliary issuer-set identifier permits
full issuer omission only when every non-leaf certificate is already an exact
independently pinned anchor at the peer. Otherwise send the complete chain.
Current lab enrollment is ineligible; no record-buffer saving is claimed.
The identifier uses existing WendyOS base64url for a truncated digest; actual
certificate, manifest and application payloads remain binary.
