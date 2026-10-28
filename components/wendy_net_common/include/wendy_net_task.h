#pragma once
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* Reserve owned tasks through FreeRTOS deletion and the following same-core
 * idle hook, after SDK storage is freed. Slot0 belongs to IDF pthread; slot1
 * is mesh-owned. Library allocation scopes are explicitly handed off.
 * Call from a task with the scheduler running; waits for child initialization
 * before publishing its handle. Idle hooks are installed once and retained. */
BaseType_t wendy_net_task_create(TaskFunction_t function,const char *name,
    uint32_t stack_bytes,void *argument,UBaseType_t priority,TaskHandle_t *task);
/* Use this for external deletion of an owned task; raw external vTaskDelete
 * cannot establish when SDK cleanup has completed on SMP. NULL means self.
 * Coordinate with task completion so the handle remains live until this call;
 * do not delete the same task concurrently. A task may also return normally
 * or call vTaskDelete(NULL), in which case idle cleanup retains its charge. */
void wendy_net_task_delete(TaskHandle_t task);
