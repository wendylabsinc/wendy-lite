#pragma once
#include <stdint.h>
#include <pthread.h>
typedef int BaseType_t;
typedef unsigned UBaseType_t;
typedef uint32_t TickType_t;
typedef int portMUX_TYPE;
typedef struct {pthread_mutex_t lock;pthread_cond_t ready;unsigned value;} StaticSemaphore_t;
#define portMUX_INITIALIZER_UNLOCKED 0
#define portMAX_DELAY UINT32_MAX
#define pdTRUE 1
#define pdPASS 1
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms))
