#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#define ESP_OK 0
#define ESP_IPADDR_TYPE_V4 0
typedef int esp_err_t;
typedef struct mdns_ip_addr_s {
    struct { int type; union { struct { uint32_t addr; } ip4; } u_addr; } addr;
    struct mdns_ip_addr_s *next;
} mdns_ip_addr_t;
typedef struct { const char *key, *value; } mdns_txt_item_t;
typedef struct mdns_result_s {
    struct mdns_result_s *next;
    uint32_t ttl;
    uint16_t port;
    mdns_txt_item_t *txt;
    size_t txt_count;
    uint8_t *txt_value_len;
    mdns_ip_addr_t *addr;
} mdns_result_t;
esp_err_t mdns_query_ptr(const char *, const char *, uint32_t, size_t, mdns_result_t **);
void mdns_query_results_free(mdns_result_t *);
