#pragma once
#include "esp_err.h"
#include <stdint.h>
typedef enum { WIFI_AUTH_OPEN, WIFI_AUTH_WEP, WIFI_AUTH_WPA_PSK, WIFI_AUTH_WPA2_PSK,
    WIFI_AUTH_WPA_WPA2_PSK, WIFI_AUTH_WPA3_PSK, WIFI_AUTH_WPA2_WPA3_PSK,
    WIFI_AUTH_WPA2_ENTERPRISE } wifi_auth_mode_t;
typedef struct { uint8_t ssid[33], bssid[6]; int8_t rssi; wifi_auth_mode_t authmode; } wifi_ap_record_t;
esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *);
