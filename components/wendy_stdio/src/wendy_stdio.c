#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include "esp_vfs.h"
#include "esp_vfs_ops.h"
#include "sdkconfig.h"

#include "wendy_stdio.h"

#define CONSOLE_PATH "/dev/console"

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

static wendy_stdio_out_data_handler_t s_out_data_handler;
static int s_dev_fd = -1;
static size_t s_open_count;

static int _console_open(const char *path, int flags, int mode)
{
    if (s_open_count == 0) {
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
    wendy_stdio_out_data_handler_t handler = s_out_data_handler;
    if (handler)
        handler(data, size);
    return size;
}

static ssize_t _console_read(int fd, void *dst, size_t size)
{
    return read(s_dev_fd, dst, size);
}

static int _console_fstat(int fd, struct stat *st)
{
    return fstat(s_dev_fd, st);
}

static int _console_fcntl(int fd, int cmd, int arg)
{
    return fcntl(s_dev_fd, cmd, arg);
}

static int _console_fsync(int fd)
{
    return fsync(s_dev_fd);
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

wendy_stdio_out_data_handler_t
wendy_stdio_set_out_data_handler(wendy_stdio_out_data_handler_t handler)
{
    wendy_stdio_out_data_handler_t prev = s_out_data_handler;
    s_out_data_handler = handler;
    return prev;
}

esp_err_t wendy_stdio_init(void)
{
    // Not registered when CONFIG_VFS_SUPPORT_IO is disabled; ignore failure.
    esp_vfs_unregister(CONSOLE_PATH);

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

    return ESP_OK;
}
