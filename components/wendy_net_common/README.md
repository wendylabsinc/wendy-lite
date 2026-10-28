# Wendy Net common foundations

This component supplies the memory, binary encoding and task helpers used by
Wendy Net. The helpers do not start a mesh runtime or radio themselves; the
runtime owns configuration, startup and shutdown.

`wendy_net_binary.h` provides a portable, allocation-free CBOR writer over a
caller-owned buffer. It emits definite containers and shortest-form unsigned
integers. Callers supply map keys in length-first deterministic order and can
first measure a message with a NULL output buffer. `wn_key` maps established
schema names to compact wire keys; unknown names pass through unchanged. This
component does not provide a CBOR decoder or validate schema/key ordering.

`wendy_net_datagram.h` supplies an ESP-IDF lwIP datagram length peek that leaves
the message queued, including zero-length messages. It uses the SDK's `recvmsg`
semantics and is not a portable host socket abstraction.

`wendy_net_profile.h` selects bounded resource and non-transit endpoint policy
with `CONFIG_WENDY_NET_CONSTRAINED_PROFILE`. This component declares no firmware
Kconfig options; the integrating runtime supplies those options and defaults.

## Allocation accounting

`wendy_net_memory.h` supplies a caller-owned bounded allocation ledger, strict
internal/PSRAM/RTC placement, reservation tokens and close/drain lifecycle checks.
Charged allocations include their aligned ownership prefix. Optional task-local
scopes and universal calloc/free callbacks retain ownership across worker
handoffs. Install library callbacks once before any library allocation, rather
than swapping hooks when the mesh starts or stops.

The ledger bounds managed payloads, prefixes and declared reservations. It does
not automatically capture SDK/radio allocations or heap allocator bookkeeping.
Runtime integrations must account those separately before claiming a whole-mesh
memory cap. No arena is reserved. Compiler scope storage adds a small fixed TLS
slot to each task's stack. Callers must stop all users of a previous generation
before reopening a closed and drained ledger.

`wendy_net_alloc.h` adds a global runtime ledger and convenience wrappers. Open
it before creating mesh state; close it and wait for outstanding ownership to
drain during shutdown. Its admission ceiling is 2 MiB with PSRAM and otherwise
`CONFIG_WENDY_NET_INTERNAL_MEMORY_LIMIT_KIB` (default 1024 KiB). The constrained
integration can set that ceiling to 160 KiB; physical SRAM and SDK headroom can
fail earlier. Host wrappers preserve libc ownership without runtime startup.
ESP allocations never fall back to uncharged memory when the budget is closed
or full. The host budget test mode exercises that firmware ownership path.

With `CONFIG_WENDY_NET_PEER` enabled, `wendy_net_task_create` reserves an internal
stack/TCB allowance before creating a task. It waits for the child to install its
deletion callback before returning its handle. Call it from a task with the
scheduler running. TLSP slot 0 remains reserved for IDF pthread; slot 1 belongs
to these tasks. The integration must enable at least two TLSP slots, deletion
callbacks and static allocation support. Library allocation scopes require an
explicit handoff to new tasks.

IDF deletion callbacks precede stack/TCB deallocation. For self-deletion or normal
task return, the reservation remains charged until the next idle hook on the
CPU whose pinned idle task performed cleanup. External deletion must use
`wendy_net_task_delete`: it suspends the owned task, waits until no CPU runs it,
then deletes it synchronously and retires its charge after SDK cleanup returns.
Callers must coordinate completion/deletion so the handle remains valid.
Raw external `vTaskDelete` cannot establish that lifetime on SMP and is outside
this API's ownership contract.
Idle hook registration uses one fixed SDK hook slot per CPU, is installed once,
and is retained across runtime reopen. Registration failure rejects creation
without allocating a task. A stalled idle task can delay drain, conservatively
retaining the reservation. With peer support disabled, the helper retains the
existing direct `xTaskCreate` behavior.

## Standalone verification

From this directory run `cmake -S tests -B <build-dir>`, build that directory,
then `ctest --test-dir <build-dir> --output-on-failure`.

The host suite covers allocation accounting, actor/worker ownership, quota reuse,
resize and shutdown, default and constrained runtime budgets, libc ownership,
exact CBOR wire bytes and sizing, supported profiles, and task startup/deletion
ordering using deterministic SDK shims. The task shims check API ordering and
accounting; a real SDK compile is still required to verify SDK types/configuration.
