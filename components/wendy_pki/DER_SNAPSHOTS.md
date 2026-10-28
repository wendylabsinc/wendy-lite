# DER snapshot foundation

New consumers use `wendy_conf_copy_enrollment_der`, device-only or time-only
DER snapshots, generation checks and `pki_parse_certificate_bundle`. The existing
encoded snapshot API remains only while the following TLS layer adopts these
APIs. This staging preserves the current encrypted legacy paths without a
DER-to-PEM adapter. Native peer activation later removes obsolete leaf APIs.

The next TLS layer owns full identity/own-certificate DER cache integration,
while signed-session integration owns the once-per-boot publication allocator.
No learned peer material is persisted by this foundation.
