#pragma once
#include "FreeRTOS.h"
typedef struct test_semaphore *SemaphoreHandle_t;
SemaphoreHandle_t xSemaphoreCreateMutex(void);
int xSemaphoreTake(SemaphoreHandle_t semaphore, TickType_t ticks);
int xSemaphoreGive(SemaphoreHandle_t semaphore);
void vSemaphoreDelete(SemaphoreHandle_t semaphore);
