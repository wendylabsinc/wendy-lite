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
client and server certificate transmission. Incoming certificate messages remain
bounded to the configured 16 KiB receive buffer; truncated and oversized messages
must fail.

`CONFIG_MBEDTLS_DYNAMIC_BUFFER` must remain disabled. ESP-IDF 6.0.3 allocates a
dynamic receive buffer from the first TLS record's size, while this mbedTLS fork
uses the configured buffer limit during fragmented handshake reassembly. The
project rejects that incompatible configuration before compilation.

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
