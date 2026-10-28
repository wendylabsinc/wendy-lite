#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
enum {ESP_OK,ESP_ERR_NOT_FOUND,ESP_ERR_INVALID_ARG,ESP_ERR_INVALID_STATE,ESP_ERR_NO_MEM};
#define MDNS_TYPE_PTR 12
typedef struct mdns_search_once_s {bool finished;unsigned deletes;} mdns_search_once_t;
typedef struct mdns_result_s {unsigned value;} mdns_result_t;
typedef void (*mdns_query_notify_t)(mdns_search_once_t *);
typedef struct {const char *key,*value;} mdns_txt_item_t;
int mdns_service_add(const char *,const char *,const char *,uint16_t,mdns_txt_item_t *,size_t);
int mdns_service_remove(const char *,const char *);
mdns_search_once_t *mdns_query_async_new(const char *,const char *,const char *,uint16_t,uint32_t,size_t,mdns_query_notify_t);
bool mdns_query_async_get_results(mdns_search_once_t *,uint32_t,mdns_result_t **,uint8_t *);
void mdns_query_results_free(mdns_result_t *);
int mdns_query_async_delete(mdns_search_once_t *);
