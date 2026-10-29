#pragma once
#include "FreeRTOS.h"
typedef void *TaskHandle_t;
typedef void (*TaskFunction_t)(void *);
TaskHandle_t xTaskGetCurrentTaskHandle(void);
BaseType_t xTaskNotifyGive(TaskHandle_t);
uint32_t ulTaskNotifyTake(BaseType_t,TickType_t);
UBaseType_t uxTaskGetStackHighWaterMark(TaskHandle_t);
void vTaskDelay(TickType_t);
void vTaskDelete(TaskHandle_t);
