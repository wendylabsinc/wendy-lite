#pragma once
#include "FreeRTOS.h"
typedef void (*TaskFunction_t)(void *);
typedef struct mock_task *TaskHandle_t;
BaseType_t xTaskCreate(TaskFunction_t, const char *, uint32_t, void *, UBaseType_t, TaskHandle_t *);
void vTaskDelete(TaskHandle_t);
void vTaskSuspend(TaskHandle_t);
TaskHandle_t xTaskGetCurrentTaskHandle(void);
TaskHandle_t xTaskGetCurrentTaskHandleForCore(BaseType_t);
TaskHandle_t xTaskGetIdleTaskHandleForCore(BaseType_t);
void *pvTaskGetThreadLocalStoragePointer(TaskHandle_t, BaseType_t);
void vTaskSetThreadLocalStoragePointerAndDelCallback(TaskHandle_t, BaseType_t, void *, void (*)(int, void *));
