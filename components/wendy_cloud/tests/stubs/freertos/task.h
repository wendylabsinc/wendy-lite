#pragma once
#include "FreeRTOS.h"
typedef void *TaskHandle_t;
BaseType_t xTaskCreatePinnedToCore(void (*entry)(void *),const char *,unsigned,void *,unsigned,TaskHandle_t *,unsigned);
void vTaskDelete(TaskHandle_t);
