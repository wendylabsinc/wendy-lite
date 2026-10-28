# Optional encrypted-stream checkpoints

`CONFIG_WENDY_NET_TEST_BLE_STREAM_CRC` is off by default. With lab diagnostics
enabled it adds 40 bytes per mesh pipe, no payload buffer, task or timer. Firmware
checks the actual ROM CRC32/IEEE API against the standard known vector and a
chained calculation before starting the diagnostic adapter.

Only positive stream read/write results advance counters. The first 4096-byte
checksum and latest complete 4096-byte boundary remain available alongside the
current prefix. Existing periodic diagnostics and CoC disconnect callbacks copy
metadata under the adapter gate and log after releasing it. A disconnect sample
is a prefix at that instant: buffered RX can still drain afterwards. Neither TX
acceptance nor a checksum establishes remote delivery.

Run the positive host fixture from the repository root:

```sh
python3 components/wendy_ble/tests/mesh_stream_crc_io_success.py
CFLAGS='-fsanitize=address,undefined -g' python3 components/wendy_ble/tests/mesh_stream_crc_io_success.py
```

It compiles the actual production stream functions, checks 53,352 exact bytes in
both directions, short/blocked writes and ring wrap, and compares checksums with
zlib. `mesh_stream_crc_success_test.c` additionally checks boundary accounting
with multiple chunk sizes; compile it with `src/mesh_stream_crc.c`, the component
include path and `-lz`. Only synthetic test bytes exist in temporary host memory.

Pair emitted offsets with a complete passive HCI stream reconstruction, starting
before that CoC opens. A capture drop, truncated record or missed epoch makes a
mismatch inconclusive. Invisible kernel observer allocation loss is an additional
limitation even when socket drop counters are zero. This diagnostic does not
change TLS, authentication, fragmentation, credit or admission behaviour.
