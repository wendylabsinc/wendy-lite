#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "esp_vfs.h"

enum fd_kind { FD_FREE, FD_SDK_CONSOLE, FD_DEVICE, FD_WENDY_CONSOLE };
static enum fd_kind descriptors[32] = { FD_SDK_CONSOLE, FD_SDK_CONSOLE, FD_SDK_CONSOLE };
static int stream_fds[] = {0, 1, 2};
static int device_fd = -1;
static const esp_vfs_fs_ops_t *console;
static const char *console_path;
static unsigned unregisters, registrations;
static unsigned opens, closes, writes, reads, fcntls, fsyncs, fstats;
static unsigned stream_opens, buffering_calls, handler_calls;
static int physical_flags;
static uint8_t physical_output[256], captured_output[256];
static size_t physical_size, captured_size;

esp_err_t esp_vfs_unregister(const char *path)
{
    assert(!strcmp(path, "/dev/console"));
    ++unregisters;
    for (size_t i = 0; i < sizeof(descriptors) / sizeof(*descriptors); ++i)
        if (descriptors[i] == FD_SDK_CONSOLE) descriptors[i] = FD_FREE;
    return ESP_OK;
}

esp_err_t esp_vfs_register_fs(const char *path, const esp_vfs_fs_ops_t *ops,
                            int flags, void *context)
{
    assert(flags == ESP_VFS_FLAG_STATIC && !context);
    // Match ESP-IDF's is_path_prefix_valid, including its 15-byte limit.
    // An empty prefix is permitted for a fallback filesystem.
    size_t length = strlen(path);
    if (length && (length < 2 || length > ESP_VFS_PATH_MAX ||
                   path[0] != '/' || path[length - 1] == '/'))
        return ESP_ERR_INVALID_ARG;
    ++registrations;
    console = ops;
    console_path = path;
    return ESP_OK;
}

static int next_fd(void)
{
    for (int i = 0; i < (int)(sizeof(descriptors) / sizeof(*descriptors)); ++i)
        if (descriptors[i] == FD_FREE) return i;
    assert(!"file descriptor table full");
    return -1;
}

static int physical_open(const char *path, int flags, ...)
{
    assert(!strcmp(path, "/dev/uart/0"));
    ++opens;
    physical_flags = flags;
    device_fd = next_fd();
    descriptors[device_fd] = FD_DEVICE;
    return device_fd;
}

static int physical_close(int fd)
{
    assert(fd == device_fd && descriptors[fd] == FD_DEVICE);
    ++closes;
    descriptors[fd] = FD_FREE;
    return 0;
}

static void close_descriptor(int fd)
{
    enum fd_kind kind = descriptors[fd];
    if (kind == FD_DEVICE) {
        assert(physical_close(fd) == 0);
    } else {
        descriptors[fd] = FD_FREE;
        if (kind == FD_WENDY_CONSOLE) assert(console->close(0) == 0);
    }
}

static __attribute__((unused)) ssize_t physical_write(int fd, const void *data, size_t size)
{
    // The old takeover reused stdin/stdout's stale descriptor numbers, so
    // the backing fd could point at this VFS and recursively forward writes.
    assert(fd == device_fd && descriptors[fd] == FD_DEVICE && size > 0);
    ++writes;
    // Verify the normal console still retries short device writes.
    if (size > 2) size = 2;
    assert(physical_size + size <= sizeof(physical_output));
    memcpy(physical_output + physical_size, data, size);
    physical_size += size;
    return (ssize_t)size;
}

static __attribute__((unused)) ssize_t physical_read(int fd, void *data, size_t size)
{
    assert(fd == device_fd && descriptors[fd] == FD_DEVICE && size > 0);
    ++reads;
    ((uint8_t *)data)[0] = 0xa5;
    return 1;
}

static __attribute__((unused)) int physical_fcntl(int fd, int command, ...)
{
    assert(fd == device_fd && descriptors[fd] == FD_DEVICE);
    ++fcntls;
    if (command == F_GETFL) return physical_flags;
    if (command == F_SETFL) {
        va_list args;
        va_start(args, command);
        physical_flags = va_arg(args, int);
        va_end(args);
        return 0;
    }
    errno = ENOSYS;
    return -1;
}

static __attribute__((unused)) int physical_fsync(int fd)
{
    assert(fd == device_fd && descriptors[fd] == FD_DEVICE);
    ++fsyncs;
    return 0;
}

static int physical_fstat(int fd, struct stat *st)
{
    assert(fd == device_fd && descriptors[fd] == FD_DEVICE);
    ++fstats;
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFCHR | 0600;
    return 0;
}

static FILE *console_freopen(const char *path, const char *mode, FILE *stream)
{
    assert(console && !strcmp(path, console_path));
    assert(!strcmp(mode, "r") || !strcmp(mode, "w"));
    int stream_index = stream == stdin ? 0 : stream == stdout ? 1 : 2;
    assert(stream == stdin || stream == stdout || stream == stderr);
    close_descriptor(stream_fds[stream_index]);
    // ESP-IDF invokes the VFS open callback before assigning the outer fd.
    assert(console->open("/", !strcmp(mode, "r") ? O_RDONLY : O_WRONLY, 0) == 0);
    stream_fds[stream_index] = next_fd();
    descriptors[stream_fds[stream_index]] = FD_WENDY_CONSOLE;
    ++stream_opens;
    return stream;
}

static int console_setvbuf(FILE *stream, char *buffer, int mode, size_t size)
{
    ++buffering_calls;
    return 0;
}

#define open(...) physical_open(__VA_ARGS__)
#define close(...) physical_close(__VA_ARGS__)
#define write(...) physical_write(__VA_ARGS__)
#define read(...) physical_read(__VA_ARGS__)
#define fcntl(...) physical_fcntl(__VA_ARGS__)
#define fsync(...) physical_fsync(__VA_ARGS__)
#define fstat(...) physical_fstat(__VA_ARGS__)
#define freopen(...) console_freopen(__VA_ARGS__)
#define setvbuf(...) console_setvbuf(__VA_ARGS__)
#include "../src/wendy_stdio.c"
#undef open
#undef close
#undef write
#undef read
#undef fcntl
#undef fsync
#undef fstat
#undef freopen
#undef setvbuf

static void capture_output(const void *data, size_t size)
{
    ++handler_calls;
    assert(captured_size + size <= sizeof(captured_output));
    memcpy(captured_output + captured_size, data, size);
    captured_size += size;
}

static void test_output(void)
{
    static const uint8_t payload[] = {0, 0x10, 'x', '\n', 0xff};
    assert(wendy_stdio_set_out_data_handler(capture_output) == NULL);
    assert(console->write(0, payload, sizeof(payload)) == sizeof(payload));
    assert(handler_calls == 1 && captured_size == sizeof(payload));
    assert(!memcmp(captured_output, payload, sizeof(payload)));
#if CONFIG_WENDY_USJ_USE_UART
    assert(writes == 0 && physical_size == 0);
#else
    assert(writes == 3 && physical_size == sizeof(payload));
    assert(!memcmp(physical_output, payload, sizeof(payload)));
#endif
    assert(wendy_stdio_set_out_data_handler(NULL) == capture_output);
    assert(console->write(0, payload, sizeof(payload)) == sizeof(payload));
    assert(handler_calls == 1);
}

static void test_input(void)
{
    uint8_t input[128], extra[64], output[160];
    for (size_t i = 0; i < sizeof(input); ++i) input[i] = (uint8_t)i;
    memset(extra, 0x5a, sizeof(extra));
    assert(console->fcntl(0, F_SETFL, O_NONBLOCK) == 0);
    assert(console->read(0, output, 0) == 0 && reads == 0);
    assert(wendy_stdio_put_stdin_data(input, sizeof(input)) == sizeof(input));
    assert(wendy_stdio_put_stdin_data(extra, sizeof(extra)) == 0);
    assert(console->read(0, output, 64) == 64);
    assert(!memcmp(output, input, 64));
    assert(wendy_stdio_put_stdin_data(extra, sizeof(extra)) == sizeof(extra));
    assert(console->read(0, output, sizeof(output)) == 128);
    assert(!memcmp(output, input + 64, 64));
    assert(!memcmp(output + 64, extra, sizeof(extra)));
    assert(reads == 0);
    errno = 0;
#if CONFIG_WENDY_USJ_USE_UART
    assert(console->read(0, output, sizeof(output)) == -1 && errno == EAGAIN);
    assert(reads == 0 && fcntls == 0);
#else
    assert(console->read(0, output, sizeof(output)) == 1 && output[0] == 0xa5);
    assert(reads == 1 && fcntls > 0);
#endif
}

static void test_flags(void)
{
    int initial_physical_flags = physical_flags;
    assert(console->fcntl(0, F_SETFL, O_APPEND) == 0);
    int flags = console->fcntl(0, F_GETFL, 0);
    assert(flags & O_APPEND);
    assert(console->fsync(0) == 0);
    errno = 0;
    assert(console->fcntl(0, -999, 0) == -1 && errno == ENOSYS);
#if CONFIG_WENDY_USJ_USE_UART
    assert((flags & (O_ACCMODE | O_NONBLOCK)) == (O_RDWR | O_NONBLOCK));
    assert(physical_flags == initial_physical_flags && fcntls == 0 && fsyncs == 0);
#else
    assert(flags == O_APPEND && physical_flags == O_APPEND);
    assert(fcntls == 3 && fsyncs == 1);
    (void)initial_physical_flags;
#endif
}

static void test_metadata(void)
{
    struct stat st;
    assert(console->fstat(0, &st) == 0 && S_ISCHR(st.st_mode) && fstats == 1);
    for (unsigned i = 0; i < 3; ++i) {
        close_descriptor(stream_fds[i]);
        assert(closes == (i == 2 ? 1u : 0u));
    }
    assert(console->close(0) == -1 && errno == EBADF);
    // Reopening metadata while management is active must preserve UART's
    // global nonblocking state, even if the application requested blocking.
    assert(console->open("/", O_WRONLY, 0) == 0 && opens == 2);
#if CONFIG_WENDY_USJ_USE_UART
    assert(physical_flags & O_NONBLOCK);
#else
    assert(physical_flags == O_WRONLY);
#endif
    assert(console->close(0) == 0 && closes == 2);
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    assert(esp_vfs_register_fs("/dev/wendy_stdio", &s_vfs, ESP_VFS_FLAG_STATIC, NULL)
           == ESP_ERR_INVALID_ARG);
    assert(registrations == 0 && !console);
    assert(wendy_stdio_init() == ESP_OK);
    assert(console && opens == 1 && stream_opens == 3 && buffering_calls == 2);
    assert(!strcmp(console_path, "/dev/wstdio") && unregisters == 0);
    for (unsigned i = 0; i < 3; ++i) {
        assert(stream_fds[i] != device_fd);
        assert(descriptors[stream_fds[i]] == FD_WENDY_CONSOLE);
        for (unsigned j = 0; j < i; ++j) assert(stream_fds[i] != stream_fds[j]);
    }
    assert(descriptors[device_fd] == FD_DEVICE);
    assert(wendy_stdio_init() == ESP_OK);
    assert(registrations == 1 && opens == 1 && stream_opens == 3);
#if CONFIG_WENDY_USJ_USE_UART
    assert(physical_flags & O_NONBLOCK);
#endif
    if (!strcmp(argv[1], "output")) test_output();
    else if (!strcmp(argv[1], "input")) test_input();
    else if (!strcmp(argv[1], "flags")) test_flags();
    else if (!strcmp(argv[1], "metadata")) test_metadata();
    else assert(!"unknown test");
    return 0;
}
