#pragma once
#include <assert.h>
#include "FreeRTOS.h"
typedef struct { int held; } StaticSemaphore_t;
typedef StaticSemaphore_t *SemaphoreHandle_t;
static inline SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t *storage)
{
    storage->held = 0;
    return storage;
}
static inline BaseType_t xSemaphoreTake(SemaphoreHandle_t semaphore, TickType_t wait)
{
    assert(semaphore && !semaphore->held);
    semaphore->held = 1;
    return pdTRUE;
}
static inline BaseType_t xSemaphoreGive(SemaphoreHandle_t semaphore)
{
    assert(semaphore && semaphore->held);
    semaphore->held = 0;
    return pdTRUE;
}
