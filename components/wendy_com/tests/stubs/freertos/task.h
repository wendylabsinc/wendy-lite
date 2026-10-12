#pragma once
#include "FreeRTOS.h"
#include <stddef.h>
static inline TaskHandle_t xTaskGetCurrentTaskHandle(void) { return NULL; }
static inline int xTaskCreatePinnedToCore(void (*fn)(void *), const char *name,
    unsigned stack, void *arg, int priority, TaskHandle_t *task, int core) { return 0; }
