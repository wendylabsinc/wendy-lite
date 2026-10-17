#pragma once

void sensor_link_test_warning(const char *tag, const char *format, ...);

#define ESP_LOGI(tag, ...) ((void)(tag))
#define ESP_LOGW(tag, ...) sensor_link_test_warning(tag, __VA_ARGS__)
#define ESP_LOGE(tag, ...) ((void)(tag))
