# Native peer format foundations

Pure current-format CBOR, verified manifest/directory projections, packet
framing and bounded RAM certificate fetch/store/wire primitives. No radio,
actor, service-gossip runtime, operator proof or delegated leaf mode is enabled.
A complete device manifest carries services with one inherited lease; service
metadata structures do not create independently signed/gossiped records.
Retained endpoint/key projections are bounded and grow on demand.
Certificate worker/read effects and signed routing sessions join next.
