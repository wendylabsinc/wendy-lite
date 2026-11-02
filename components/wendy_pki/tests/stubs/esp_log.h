#pragma once
#if WENDY_MESH_TEST_LOG
#include <stdio.h>
#define ESP_LOGE(tag, ...) do { (void)(tag); fprintf(stderr, __VA_ARGS__); fputc('\n',stderr); } while(0)
#define ESP_LOGW(tag, ...) ESP_LOGE(tag, __VA_ARGS__)
#define ESP_LOGI(tag, ...) ESP_LOGE(tag, __VA_ARGS__)
#else
#define ESP_LOGE(tag, ...) ((void)(tag))
#define ESP_LOGW(tag, ...) ((void)(tag))
#define ESP_LOGI(tag, ...) ((void)(tag))
#endif

#ifndef ESP_LOGD
#define ESP_LOGD(tag, ...) ESP_LOGI(tag, __VA_ARGS__)
#endif
