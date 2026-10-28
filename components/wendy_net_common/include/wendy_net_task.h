#pragma once
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* Reserve owned tasks until FreeRTOS reaps them. Slot0 belongs to IDF pthread;
 * slot1 is mesh-owned. Library allocation scopes are explicitly handed off. */
BaseType_t wendy_net_task_create(TaskFunction_t function,const char *name,
    uint32_t stack_bytes,void *argument,UBaseType_t priority,TaskHandle_t *task);
