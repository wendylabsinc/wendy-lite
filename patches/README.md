# Dependency patches

Firmware and host tests use these pinned dependencies:

| Dependency | Commit |
| --- | --- |
| [esp-pqc](https://github.com/espressif/esp-pqc) | `37953195672cbc7502b06fc845fc9219627f31fd` |
| [Espressif mbedTLS](https://github.com/espressif/mbedtls) | `3deef6a6ef81952c9468419fccd543f9caaebdb6` |
| [Espressif liboqs](https://github.com/espressif/liboqs) | `d9459ff25b8fd6181189ef3ace0e86f206d64dd8` |

[Espressif describes esp-pqc as experimental and intended for evaluation](https://github.com/espressif/esp-pqc/blob/37953195672cbc7502b06fc845fc9219627f31fd/README.md).
These patches and tests do not change that status. Device heap use, crypto latency
and the complete enrollment and relay flow still need physical-board validation.

`cmake/dependency_patches.cmake` copies dependencies into the build directory and
applies these patches there. The pinned submodules and downloaded components stay
unchanged. Configuration fails if a patch no longer applies. Mbed TLS, its PSA
libraries and the IDF adapter all use the copied headers and sources so their
private structures agree. Review and retest each patch when updating a dependency.

Patch application ignores inherited `GIT_DIR` and `GIT_WORK_TREE` and stops Git
repository discovery at the copied tree's parent. Without this isolation, an
in-checkout build can report successful patch application while skipping every
file. That produces firmware without the CA-verification and TLS-fragmentation
fixes below. The `dependency_patches_in_checkout` host test checks application
and reconfiguration inside a Git checkout, and verifies that the original
dependency stays unchanged.

## TLS certificate transmission

`esp-pqc-mbedtls-tls13-certificate-fragmentation.patch` lets TLS 1.3 clients and
servers send certificate messages larger than one record. It tracks the plaintext
offset, hashes each fragment once and resumes after retry responses only after
the previous ciphertext has flushed. Fragment sizes use the configured record
limit. Resuming a client certificate does not reset the traffic sequence counter.
The patch also corrects an ML-DSA-65 key-type enum used where a signature enum is
required.

The host TLS tests send chains larger than 16 KiB through socket and callback
stream adapters. They force 512-byte writes and retry responses, and check both
client and server certificate transmission. The CA compatibility patch below
allows incoming handshake messages up to 32 KiB; truncated and oversized
messages must fail. Individual TLS records remain limited to 16 KiB.

`CONFIG_MBEDTLS_DYNAMIC_BUFFER` must remain disabled. ESP-IDF 6.0.3 allocates a
dynamic receive buffer from the first TLS record's size, while this mbedTLS fork
uses the configured buffer limit during fragmented handshake reassembly. The
project rejects that incompatible configuration before compilation.

## ML-DSA-87 CA compatibility

`esp-pqc-mbedtls-mldsa87-ca.patch` adds pure ML-DSA-87 public-key parsing and
X.509 signature verification. It verifies the complete certificate TBS bytes
through liboqs and rejects AlgorithmIdentifier parameters. It adds no TLS
signature scheme or private-key support. Wendy's certificate policy permits
ML-DSA-87 keys only on CA certificates, preserving P-256 device keys and
ML-DSA-65 operator keys.

The existing PKI uses ML-DSA-87 roots and intermediates above ML-DSA-65 issuers.
These chains exceed one TLS record. The patch reserves 32 KiB of additional
receive-buffer space for in-place handshake reassembly, including a final
record that also carries the next message. It rejects a declared handshake
length above 32 KiB before collecting fragments. Record-size checks stay at
16 KiB. Fixed buffers are still required.

The firmware selects `CONFIG_MBEDTLS_DEFAULT_MEM_ALLOC` so boards with PSRAM
can allocate these large buffers through their normal PSRAM-aware heap policy.
Keeping mbedTLS on internal-only RAM can exhaust memory during TLS setup while
sensor and networking tasks are running.

`esp-pqc-liboqs-mldsa87.patch` uses the same ESP Keccak adapter and heap-backed
temporary allocations as the ML-DSA-65 integration. The firmware builds the
ML-DSA-87 reference implementation for verification only; signing and key
generation return errors. Host tests cover mixed CA chains, invalid signatures,
unsupported operator keys, and the TLS signature schemes advertised by servers.

## Host crypto headers

`esp-pqc-mbedtls4-private-headers.patch` keeps the public `bignum.h` and `ecp.h`
includes only for ESP-IDF builds, where those port headers declare hardware
accelerator functions. Host builds use the private headers already included by
the sources. The host CMake configuration also shares the ML-DSA-65 and X.509
definitions with every PSA object library so the key layout and OQS verifier
match the TLS library.

## WAMR on ESP-IDF 6

`wamr-idf6-platform.patch` applies to `espressif/wasm-micro-runtime` 2.4.0~1.
It includes `sys/stat.h` explicitly and declares WAMR's existing `renameat` stub.
When IDF memory protection
removes `MALLOC_CAP_EXEC`, executable-memory requests return `NULL` without an
allocation. Normal interpreter allocations and platforms that permit executable
heap memory retain their previous behavior. The patch does not disable memory
protection or substitute writable memory for executable memory.

Native builds exclude the optional WAMR runtime. Its registry dependencies are
enabled only with `CONFIG_WENDY_CORE_WASM_APP_SUPPORT`, through
`boards/wasm.defaults`.
