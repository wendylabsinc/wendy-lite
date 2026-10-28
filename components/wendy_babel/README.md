# Native Babel component

This component is a single-owner, sans-I/O C routing engine and Babel v2 codec.
Its four production sources depend only on `wendy_net_common`. It owns no task,
socket, actor, PKI service or device probe. The integrating router supplies
monotonic milliseconds, authenticated carrier identities, origin authorization,
forwarding installation and packet transport.

Zero-initialize an engine, call `wb_init`, and submit one event at a time. On
`WB_PENDING`, install the complete `routes` snapshot atomically, then call
`wb_commit` with its revision. A failed commit permanently stops the engine;
the caller must remove all forwarding. Output stays blocked until commit.
Drain `wb_next_packet` after every accepted event before submitting another.
`wb_next_deadline` supplies the next timer wakeup. `wb_lookup` returns an
unreachable suppression entry when it overrides a less specific live route.

An optional `allow` callback must authorize the originating router and prefix,
including relayed routes. It runs during admission and every route selection.
Transport authentication alone does not establish origin authority.

The defaults support transit routing. The integrating runtime chooses
`CONFIG_WENDY_NET_CONSTRAINED_PROFILE` for smaller ceilings, and chooses
`config.local_only` separately for endpoint operation. Neither choice is
inferred from the ESP32 chip family. `WB_ROUTES` bounds distinct admitted
prefixes, including suppression; `WB_CANDIDATES` separately bounds alternate
carrier routes. Tables grow with observed topology and shrink after expiry.
Allocator callbacks are optional and must be supplied as a pair. ESP defaults
use the common component's charged allocator; host defaults use libc.
`wb_memory` includes the engine, requested table bytes and transient resize
copies, excluding allocator headers and caller I/O/task buffers. Queue limits
or allocation pressure can drop output TLVs; inspect `queue_drops` and
`allocation_failures`. Periodic advertisements and requests provide retries.

`wb_save` and `wb_restore` expose an optional portable history checkpoint.
When using durable history, save before exporting output (and before committing
changed forwarding); the caller owns atomic storage and integrity. Restore
keeps feasibility and suppression history but restores no live links or routes.
This library adds no flash cache or storage implementation. A production device
can omit checkpoint storage and manage its restart policy in the outer router.
Call `wb_deinit` after all use to release every allocation.

Run host checks with:

```
cmake -S components/wendy_babel/tests -B /tmp/babel-host
cmake --build /tmp/babel-host
ctest --test-dir /tmp/babel-host --output-on-failure
```

The suite covers C transit/fallback, endpoint policy, authorization changes,
checkpoint restore, sparse memory and cleanup, allocation pressure, and 128
prefixes with six alternate carriers. For Go interoperability, copy
`tests/oracle/go.mod` to a temporary modfile, add a local `replace` for the
WendyOS `go/babel` module, and run the oracle with the built `babel_driver` path.
The oracle checks Go → C → Go transit, path withdrawal and authorization expiry.
