#pragma once
#include "esp_err.h"
typedef struct {unsigned max_fds;} esp_vfs_eventfd_config_t;
esp_err_t esp_vfs_eventfd_register(const esp_vfs_eventfd_config_t *);
int eventfd(unsigned int,int);
