#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_vfs.h"
#include "esp_vfs_ops.h"
#include "sdkconfig.h"

#include "wendy_stdio.h"

#define CONSOLE_PATH "/dev/wstdio"
_Static_assert(sizeof(CONSOLE_PATH) - 1 <= ESP_VFS_PATH_MAX,
               "Wendy stdio mount path exceeds ESP-IDF VFS limit");

#define STRINGIFY(s)  STRINGIFY2(s)
#define STRINGIFY2(s) #s

// Same compile-time device selection as IDF's esp_vfs_console
#if CONFIG_ESP_CONSOLE_UART
#define CONSOLE_DEV_PATH "/dev/uart/" STRINGIFY(CONFIG_ESP_CONSOLE_UART_NUM)
#elif CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
#define CONSOLE_DEV_PATH "/dev/usbserjtag"
#elif CONFIG_ESP_CONSOLE_USB_CDC
#define CONSOLE_DEV_PATH "/dev/cdcacm"
#else
#define CONSOLE_DEV_PATH "/dev/null"
#endif

#define STDIN_BUF_SIZE 128 // must be a power of two

static wendy_stdio_out_data_handler_t s_out_data_handler;
static int s_dev_fd = -1;
static size_t s_open_count;
static bool s_initialized;
#if CONFIG_WENDY_USJ_USE_UART
// UART's VFS flags are shared by all descriptors for a port. Keep console
// flags separate so app stdin cannot turn binary management reads blocking.
static atomic_int s_console_flags = O_RDWR | O_NONBLOCK;
#endif

// Injected stdin data, multi-producer/multi-consumer ring buffer with
// free-running counters (fill level = in - out, index = counter masked).
// Producers are lock-free: they claim a range by CAS on `in`, then publish
// each byte through its ready flag; consumers only trust flagged bytes, so a
// producer preempted mid-copy delays later data instead of corrupting it.
// Consumers are serialized by s_stdin_mutex; the empty check stays lock-free.
static uint8_t s_stdin_buf[STDIN_BUF_SIZE];
static atomic_uchar s_stdin_ready[STDIN_BUF_SIZE]; // 1 = byte committed
static atomic_size_t s_stdin_in;  // producers' claim counter
static atomic_size_t s_stdin_out; // consumers' counter
static SemaphoreHandle_t s_stdin_mutex;
static StaticSemaphore_t s_stdin_mutex_buf;

static int _console_open(const char *path, int flags, int mode)
{
    if (s_open_count == 0) {
#if CONFIG_WENDY_USJ_USE_UART
        // uart_open also updates the shared per-port nonblocking flag.
        flags |= O_NONBLOCK;
#endif
        s_dev_fd = open(CONSOLE_DEV_PATH, flags, mode);
        if (s_dev_fd < 0)
            return -1;
    }
    s_open_count++;
    return 0;
}

static int _console_close(int fd)
{
    if (s_open_count == 0) {
        errno = EBADF;
        return -1;
    }
    s_open_count--;
    if (s_open_count == 0) {
        close(s_dev_fd);
        s_dev_fd = -1;
    }
    return 0;
}

static ssize_t _console_write(int fd, const void *data, size_t size)
{
#if !CONFIG_WENDY_USJ_USE_UART
    // The device may accept fewer bytes than requested (e.g. usbserjtag, or
    // a fd switched to non-blocking); keep writing until drained.
    const char *p = data;
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t written = write(s_dev_fd, p, remaining);
        if (written <= 0)
            break;
        p += written;
        remaining -= written;
    }
#endif
    wendy_stdio_out_data_handler_t handler = s_out_data_handler;
    if (handler)
        handler(data, size);
    return size;
}

static ssize_t _console_read(int fd, void *dst, size_t size)
{
    if (size == 0)
        return 0;
#if !CONFIG_WENDY_USJ_USE_UART
    // Only non-blocking mode is allowed.
    // The fall-through read(s_dev_fd) below would otherwise block and starve
    // injected ring-buffer data.
    assert(fcntl(s_dev_fd, F_GETFL, 0) & O_NONBLOCK);
#endif
    // Lock-free empty check: producers claim `in` before they publish, so
    // in == out proves nothing is committed. Stale loads only err toward
    // taking the mutex, never toward missing data.
    size_t in = atomic_load_explicit(&s_stdin_in, memory_order_relaxed);
    size_t out = atomic_load_explicit(&s_stdin_out, memory_order_relaxed);
    if (in != out) {
        xSemaphoreTake(s_stdin_mutex, portMAX_DELAY);
        out = atomic_load_explicit(&s_stdin_out, memory_order_relaxed);
        uint8_t *d = dst;
        size_t n = 0;
        while (n < size) {
            size_t index = (out + n) & (STDIN_BUF_SIZE - 1);
            if (!atomic_load_explicit(&s_stdin_ready[index], memory_order_acquire))
                break;
            d[n++] = s_stdin_buf[index];
            // TODO: optimize this with memset()
            atomic_store_explicit(&s_stdin_ready[index], 0, memory_order_relaxed);
        }
        if (n > 0) {
            // Release orders the flag clears before the counter advance, so a
            // producer that acquires `out` sees the reclaimed slots unflagged.
            atomic_store_explicit(&s_stdin_out, out + n, memory_order_release);
        }
        xSemaphoreGive(s_stdin_mutex);
        if (n > 0)
            return n;
    }
#if CONFIG_WENDY_USJ_USE_UART
    // The wired transport is the sole UART reader and injects console input.
    // Reading its descriptor here would steal protocol bytes in COM mode.
    errno = EAGAIN;
    return -1;
#else
    return read(s_dev_fd, dst, size);
#endif
}

static int _console_fstat(int fd, struct stat *st)
{
    return fstat(s_dev_fd, st);
}

static int _console_fcntl(int fd, int cmd, int arg)
{
#if CONFIG_WENDY_USJ_USE_UART
    if (cmd == F_GETFL)
        return atomic_load(&s_console_flags);
    if (cmd == F_SETFL) {
        // Injected console input is always nonblocking, independently of the
        // physical UART's flags. Preserve other requested status flags here.
        atomic_store(&s_console_flags, (arg & ~O_ACCMODE) | O_RDWR | O_NONBLOCK);
        return 0;
    }
    errno = ENOSYS;
    return -1;
#else
    return fcntl(s_dev_fd, cmd, arg);
#endif
}

static int _console_fsync(int fd)
{
#if CONFIG_WENDY_USJ_USE_UART
    // There is no separate console queue to flush. Do not wait on COM traffic.
    return 0;
#else
    return fsync(s_dev_fd);
#endif
}

static const esp_vfs_fs_ops_t s_vfs = {
    .write = &_console_write,
    .open = &_console_open,
    .fstat = &_console_fstat,
    .close = &_console_close,
    .read = &_console_read,
    .fcntl = &_console_fcntl,
    .fsync = &_console_fsync,
};

size_t wendy_stdio_put_stdin_data(const void *data, size_t size)
{
    size_t in = atomic_load_explicit(&s_stdin_in, memory_order_relaxed);
    size_t n;
    for (;;) {
        // Acquire on `out` also makes the consumer's flag clears visible for
        // every slot inside the claimed range.
        size_t out = atomic_load_explicit(&s_stdin_out, memory_order_acquire);
        size_t free_space = STDIN_BUF_SIZE - (in - out);
        n = size < free_space ? size : free_space;
        if (n == 0)
            return 0;
        if (atomic_compare_exchange_weak_explicit(&s_stdin_in, &in, in + n,
                                                  memory_order_relaxed,
                                                  memory_order_relaxed))
            break;
    }
    const uint8_t *src = data;
    // TODO: optimize this with memcpy() for data and memset() of the ready flags
    for (size_t i = 0; i < n; i++) {
        size_t index = (in + i) & (STDIN_BUF_SIZE - 1);
        s_stdin_buf[index] = src[i];
        atomic_store_explicit(&s_stdin_ready[index], 1, memory_order_release);
    }
    return n;
}

wendy_stdio_out_data_handler_t
wendy_stdio_set_out_data_handler(wendy_stdio_out_data_handler_t handler)
{
    wendy_stdio_out_data_handler_t prev = s_out_data_handler;
    s_out_data_handler = handler;
    return prev;
}

esp_err_t wendy_stdio_init(void)
{
    if (s_initialized)
        return ESP_OK;

    _Static_assert(STDIN_BUF_SIZE > 0 && (STDIN_BUF_SIZE & (STDIN_BUF_SIZE - 1)) == 0,
                   "STDIN_BUF_SIZE must be a power of two");

    s_stdin_mutex = xSemaphoreCreateMutexStatic(&s_stdin_mutex_buf);

    // Keep the SDK console registered until freopen closes each old stream.
    // Unregistering it first releases fd0/1/2 while FILE still holds those
    // numbers, allowing a later freopen to close/reuse our physical device fd
    // and make _console_write recursively forward back into this VFS.
    esp_err_t err = esp_vfs_register_fs(CONSOLE_PATH, &s_vfs, ESP_VFS_FLAG_STATIC, NULL);
    if (err != ESP_OK)
        return err;

    // The FILE objects live in _GLOBAL_REENT and are shared by all tasks, so
    // freopen retargets every task's stdio.
    if (!freopen(CONSOLE_PATH, "r", stdin) ||
        !freopen(CONSOLE_PATH, "w", stdout) ||
        !freopen(CONSOLE_PATH, "w", stderr))
        return ESP_FAIL;

    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
    setvbuf(stderr, NULL, _IONBF, 0);
    s_initialized = true;

    return ESP_OK;
}
