#pragma once
#include "esp_err.h"
#include <stddef.h>
#include <stdint.h>
typedef int nvs_handle_t;
typedef enum {NVS_TYPE_BLOB=1} nvs_type_t;
typedef struct test_nvs_iterator *nvs_iterator_t;
typedef struct {char namespace_name[16],key[16];nvs_type_t type;} nvs_entry_info_t;
typedef struct {size_t used_entries,free_entries,total_entries,namespace_count;} nvs_stats_t;
#define NVS_READWRITE 1
#define NVS_READONLY 0
esp_err_t nvs_open_from_partition(const char *, const char *, int, nvs_handle_t *);
void nvs_close(nvs_handle_t);
esp_err_t nvs_get_blob(nvs_handle_t, const char *, void *, size_t *);
esp_err_t nvs_set_blob(nvs_handle_t, const char *, const void *, size_t);
esp_err_t nvs_get_str(nvs_handle_t, const char *, char *, size_t *);
esp_err_t nvs_set_str(nvs_handle_t, const char *, const char *);
esp_err_t nvs_get_i64(nvs_handle_t, const char *, int64_t *);
esp_err_t nvs_set_i64(nvs_handle_t, const char *, int64_t);
esp_err_t nvs_erase_key(nvs_handle_t, const char *);
esp_err_t nvs_commit(nvs_handle_t);
esp_err_t nvs_entry_find(const char *,const char *,nvs_type_t,nvs_iterator_t *);
esp_err_t nvs_entry_next(nvs_iterator_t *);
esp_err_t nvs_entry_info(const nvs_iterator_t,nvs_entry_info_t *);
void nvs_release_iterator(nvs_iterator_t);
esp_err_t nvs_get_stats(const char *,nvs_stats_t *);
