#pragma once
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "esp_err.h"

typedef struct {
    ssize_t (*write)(int, const void *, size_t);
    int (*open)(const char *, int, int);
    int (*fstat)(int, struct stat *);
    int (*close)(int);
    ssize_t (*read)(int, void *, size_t);
    int (*fcntl)(int, int, int);
    int (*fsync)(int);
} esp_vfs_fs_ops_t;

#define ESP_VFS_FLAG_STATIC 1
#define ESP_VFS_PATH_MAX 15
esp_err_t esp_vfs_unregister(const char *path);
esp_err_t esp_vfs_register_fs(const char *path, const esp_vfs_fs_ops_t *ops,
                            int flags, void *context);
