#pragma once
#include "FreeRTOS.h"
typedef StaticSemaphore_t *SemaphoreHandle_t;
SemaphoreHandle_t xSemaphoreCreateBinaryStatic(StaticSemaphore_t *);
BaseType_t xSemaphoreGive(SemaphoreHandle_t);
BaseType_t xSemaphoreTake(SemaphoreHandle_t, uint32_t);
void vSemaphoreDelete(SemaphoreHandle_t);
