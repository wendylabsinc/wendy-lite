#include "wendy_wasi_shim.h"

#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_system.h"
#include "wasm_export.h"
#include "wendy_safety.h"

static const char *TAG = "wendy_wasi";

/* WASI errno constants */
#define WASI_ESUCCESS   0
#define WASI_EBADF      8
#define WASI_EINVAL     28
#define WASI_ENOSYS     52
#define WASI_ENOTSUP    58

/* WASI clock IDs */
#define WASI_CLOCK_REALTIME          0
#define WASI_CLOCK_MONOTONIC         1
#define WASI_CLOCK_PROCESS_CPUTIME   2
#define WASI_CLOCK_THREAD_CPUTIME    3

/*
 * fd_write(fd, iovs_offset, iovs_len, nwritten_offset) -> errno
 * WASI iovec: { buf_offset: u32, buf_len: u32 }
 */
static int wasi_fd_write(wasm_exec_env_t exec_env,
                          int fd, uint32_t iovs_off, int iovs_len,
                          uint32_t nwritten_off)
{
    /* Only support stdout (1) and stderr (2) */
    if (fd != 1 && fd != 2) {
        return WASI_EBADF;
    }

    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);

    /* Validate nwritten pointer */
    if (!wasm_runtime_validate_app_addr(inst, nwritten_off, 4)) {
        return WASI_EINVAL;
    }

    /* Validate iovecs array */
    uint32_t iovs_size = iovs_len * 8; /* each iovec is 8 bytes */
    if (!wasm_runtime_validate_app_addr(inst, iovs_off, iovs_size)) {
        return WASI_EINVAL;
    }

    uint32_t *iovs = wasm_runtime_addr_app_to_native(inst, iovs_off);
    uint32_t *nwritten_ptr = wasm_runtime_addr_app_to_native(inst, nwritten_off);
    uint32_t total = 0;

    for (int i = 0; i < iovs_len; i++) {
        uint32_t buf_off = iovs[i * 2];
        uint32_t buf_len = iovs[i * 2 + 1];

        if (buf_len == 0) continue;

        if (!wasm_runtime_validate_app_addr(inst, buf_off, buf_len)) {
            return WASI_EINVAL;
        }

        const char *buf = wasm_runtime_addr_app_to_native(inst, buf_off);
        fwrite(buf, 1, buf_len, (fd == 2) ? stderr : stdout);
        total += buf_len;
    }

    if (fd == 1) {
        fflush(stdout);
    }

    *nwritten_ptr = total;
    return WASI_ESUCCESS;
}

/*
 * fd_read(fd, iovs_offset, iovs_len, nread_offset) -> errno
 * Stub: stdin not supported
 */
static int wasi_fd_read(wasm_exec_env_t exec_env,
                         int fd, uint32_t iovs_off, int iovs_len,
                         uint32_t nread_off)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    if (wasm_runtime_validate_app_addr(inst, nread_off, 4)) {
        uint32_t *nread = wasm_runtime_addr_app_to_native(inst, nread_off);
        *nread = 0;
    }
    return WASI_ENOSYS;
}

/* fd_close(fd) -> errno */
static int wasi_fd_close(wasm_exec_env_t exec_env, int fd)
{
    return WASI_ENOSYS;
}

/* fd_seek(fd, offset_i64, whence, new_offset_ptr) -> errno */
static int wasi_fd_seek(wasm_exec_env_t exec_env,
                         int fd, int64_t offset, int whence,
                         uint32_t new_offset_off)
{
    return WASI_ENOSYS;
}

/* fd_prestat_get(fd, prestat_off) -> errno */
static int wasi_fd_prestat_get(wasm_exec_env_t exec_env,
                                int fd, uint32_t prestat_off)
{
    return WASI_EBADF;
}

/* fd_prestat_dir_name(fd, path_off, path_len) -> errno */
static int wasi_fd_prestat_dir_name(wasm_exec_env_t exec_env,
                                     int fd, uint32_t path_off, int path_len)
{
    return WASI_EBADF;
}

/* path_open(...) -> errno */
static int wasi_path_open(wasm_exec_env_t exec_env,
                           int dirfd, int dirflags,
                           uint32_t path_off, int path_len,
                           int oflags, int64_t fs_rights_base,
                           int64_t fs_rights_inheriting,
                           int fdflags, uint32_t fd_out_off)
{
    return WASI_ENOSYS;
}

/*
 * clock_time_get(clock_id, precision, timestamp_offset) -> errno
 * Returns nanoseconds.
 */
static int wasi_clock_time_get(wasm_exec_env_t exec_env,
                                int clock_id, int64_t precision,
                                uint32_t ts_off)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    if (!wasm_runtime_validate_app_addr(inst, ts_off, 8)) {
        return WASI_EINVAL;
    }

    int64_t *ts = wasm_runtime_addr_app_to_native(inst, ts_off);

    if (clock_id == WASI_CLOCK_MONOTONIC ||
        clock_id == WASI_CLOCK_PROCESS_CPUTIME ||
        clock_id == WASI_CLOCK_THREAD_CPUTIME) {
        *ts = esp_timer_get_time() * 1000LL; /* us -> ns */
    } else if (clock_id == WASI_CLOCK_REALTIME) {
        /* No RTC — use monotonic as best effort */
        *ts = esp_timer_get_time() * 1000LL;
    } else {
        return WASI_EINVAL;
    }

    return WASI_ESUCCESS;
}

/* random_get(buf_offset, buf_len) -> errno */
static int wasi_random_get(wasm_exec_env_t exec_env,
                            uint32_t buf_off, int buf_len)
{
    if (buf_len <= 0) return WASI_ESUCCESS;

    void *buf = wendy_safety_get_native_ptr(exec_env, buf_off, buf_len);
    if (!buf) return WASI_EINVAL;

    esp_fill_random(buf, buf_len);
    return WASI_ESUCCESS;
}

/* proc_exit(code) — never returns */
static void wasi_proc_exit(wasm_exec_env_t exec_env, int code)
{
    ESP_LOGI(TAG, "proc_exit(%d)", code);
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    char buf[48];
    snprintf(buf, sizeof(buf), "proc_exit(%d)", code);
    wasm_runtime_set_exception(inst, buf);
}

/* environ_sizes_get(count_off, buf_size_off) -> errno */
static int wasi_environ_sizes_get(wasm_exec_env_t exec_env,
                                   uint32_t count_off, uint32_t buf_size_off)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    if (!wasm_runtime_validate_app_addr(inst, count_off, 4) ||
        !wasm_runtime_validate_app_addr(inst, buf_size_off, 4)) {
        return WASI_EINVAL;
    }
    uint32_t *count = wasm_runtime_addr_app_to_native(inst, count_off);
    uint32_t *buf_size = wasm_runtime_addr_app_to_native(inst, buf_size_off);
    *count = 0;
    *buf_size = 0;
    return WASI_ESUCCESS;
}

/* environ_get(environ_off, buf_off) -> errno */
static int wasi_environ_get(wasm_exec_env_t exec_env,
                             uint32_t environ_off, uint32_t buf_off)
{
    return WASI_ESUCCESS;
}

/* args_sizes_get(count_off, buf_size_off) -> errno */
static int wasi_args_sizes_get(wasm_exec_env_t exec_env,
                                uint32_t count_off, uint32_t buf_size_off)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(exec_env);
    if (!wasm_runtime_validate_app_addr(inst, count_off, 4) ||
        !wasm_runtime_validate_app_addr(inst, buf_size_off, 4)) {
        return WASI_EINVAL;
    }
    uint32_t *count = wasm_runtime_addr_app_to_native(inst, count_off);
    uint32_t *buf_size = wasm_runtime_addr_app_to_native(inst, buf_size_off);
    *count = 0;
    *buf_size = 0;
    return WASI_ESUCCESS;
}

/* args_get(argv_off, buf_off) -> errno */
static int wasi_args_get(wasm_exec_env_t exec_env,
                          uint32_t argv_off, uint32_t buf_off)
{
    return WASI_ESUCCESS;
}

/* sched_yield() -> errno */
static int wasi_sched_yield(wasm_exec_env_t exec_env)
{
    taskYIELD();
    return WASI_ESUCCESS;
}

static NativeSymbol s_wasi_symbols[] = {
    { "fd_write",              (void *)wasi_fd_write,              "(iiii)i",      NULL },
    { "fd_read",               (void *)wasi_fd_read,               "(iiii)i",      NULL },
    { "fd_close",              (void *)wasi_fd_close,              "(i)i",         NULL },
    { "fd_seek",               (void *)wasi_fd_seek,               "(iIii)i",      NULL },
    { "fd_prestat_get",        (void *)wasi_fd_prestat_get,        "(ii)i",        NULL },
    { "fd_prestat_dir_name",   (void *)wasi_fd_prestat_dir_name,   "(iii)i",       NULL },
    { "path_open",             (void *)wasi_path_open,             "(iiiiiIIii)i", NULL },
    { "clock_time_get",        (void *)wasi_clock_time_get,        "(iIi)i",       NULL },
    { "random_get",            (void *)wasi_random_get,            "(ii)i",        NULL },
    { "proc_exit",             (void *)wasi_proc_exit,             "(i)",          NULL },
    { "environ_sizes_get",     (void *)wasi_environ_sizes_get,     "(ii)i",        NULL },
    { "environ_get",           (void *)wasi_environ_get,           "(ii)i",        NULL },
    { "args_sizes_get",        (void *)wasi_args_sizes_get,        "(ii)i",        NULL },
    { "args_get",              (void *)wasi_args_get,              "(ii)i",        NULL },
    { "sched_yield",           (void *)wasi_sched_yield,           "()i",          NULL },
};

int wendy_wasi_shim_init(void)
{
    if (!wasm_runtime_register_natives("wasi_snapshot_preview1",
                                       s_wasi_symbols,
                                       sizeof(s_wasi_symbols) / sizeof(s_wasi_symbols[0]))) {
        ESP_LOGE(TAG, "failed to register WASI shim");
        return -1;
    }
    ESP_LOGI(TAG, "WASI Preview 1 shim registered (%d functions)",
             (int)(sizeof(s_wasi_symbols) / sizeof(s_wasi_symbols[0])));
    return 0;
}
