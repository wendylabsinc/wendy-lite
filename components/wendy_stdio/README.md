# wendy_stdio

Intercepts everything written to `stdout` and `stderr` (log output and plain
`printf` alike) while keeping the normal console fully functional, and lets
the application inject data into `stdin`.

## How it works

At startup, ESP-IDF registers a VFS at `/dev/console` and newlib opens it
three times as `stdin`/`stdout`/`stderr`. That VFS is a pure forwarder to the
console device selected at compile time by Kconfig, and there is no runtime
API to observe or redirect the data flowing through it.

`wendy_stdio_init()` redirects the standard streams:

1. registers its own VFS at `/dev/wstdio`,
2. `freopen()`s `stdin`, `stdout` and `stderr` at it (the `FILE` objects live
   in `_GLOBAL_REENT` and are shared by all tasks, so every task is
   retargeted), and restores the standard buffering (line-buffered `stdout`,
   unbuffered `stderr`).

The SDK console stays registered while each old stream closes. This keeps
its descriptors reserved until `freopen()` releases them and prevents a stale
stdio descriptor from closing or aliasing the underlying device. Repeated
successful initialization is a no-op.

The new VFS opens the same
compile-time console device (`/dev/uart/N`, `/dev/usbserjtag`, `/dev/cdcacm`
or `/dev/null`) and forwards reads and writes to it. In addition, every chunk
written to `stdout`/`stderr` is passed to an application-registered handler.

With `CONFIG_WENDY_USJ_USE_UART`, the wired transport owns physical UART input
and output. The stdio VFS sends output only to its handler and reads only
injected input, returning `EAGAIN` when empty. Console flags stay local and
`fsync()` is a no-op, so application stdio cannot alter or drain management
traffic. The SDK console remains available for boot and panic diagnostics.

Because ESP-IDF's default log writer is plain `vprintf`, log messages travel
through `stdout` and are captured too. Only early-boot and ISR logs
(`esp_rom_printf`) bypass the VFS and go straight to the ROM console.

## Usage

```c
#include "wendy_stdio.h"

static wendy_stdio_out_data_handler_t s_prev_handler;

static void my_handler(const void *data, size_t size)
{
    if (s_prev_handler)
        s_prev_handler(data, size);   // keep earlier handlers working
    my_sink_write(data, size);
}

void app_init(void)
{
    ESP_ERROR_CHECK(wendy_stdio_init());
    s_prev_handler = wendy_stdio_set_out_data_handler(my_handler);
}
```

`wendy_stdio_set_out_data_handler()` returns the previously registered
handler (`NULL` if none) so handlers can be chained. It may be called before
or after `wendy_stdio_init()`; passing `NULL` unregisters.

`wendy_stdio_put_stdin_data()` injects data into `stdin`: reads on the
console first drain a 128-byte FIFO fed by this function. Unless Wendy owns
the UART transport, reads then fall back to the real console device, so injected
and typed input may interleave. Bytes
that don't fit in the FIFO are dropped; the function returns the number of
bytes accepted.

## Notes

- The handler receives the post-stdio-buffering byte stream with plain `\n`
  line endings. When forwarding to the physical console, LF→CRLF conversion
  happens below, in the device VFS driver.
  With line-buffered `stdout`, log output arrives as whole lines.
- The handler runs in the context of whatever task is printing.
- Call initialization before starting application tasks that use stdio.
- `select()` and termios are not forwarded (nothing in this project uses them
  on the console; `CONFIG_VFS_SUPPORT_TERMIOS` is disabled).
