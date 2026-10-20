#pragma once

#include "FreeRTOS.h"

typedef uint32_t EventBits_t;
#ifdef SENSOR_LINK_TEST_THREADS
typedef struct test_event_group *EventGroupHandle_t;
#else
typedef EventBits_t *EventGroupHandle_t;
#endif
EventGroupHandle_t xEventGroupCreate(void);
void vEventGroupDelete(EventGroupHandle_t group);
EventBits_t xEventGroupSetBits(EventGroupHandle_t group, EventBits_t bits);
EventBits_t xEventGroupClearBits(EventGroupHandle_t group, EventBits_t bits);
EventBits_t xEventGroupGetBits(EventGroupHandle_t group);
EventBits_t xEventGroupWaitBits(EventGroupHandle_t group, EventBits_t bits,
                               int clear, int all, TickType_t ticks);
