#pragma once
#include <pthread.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
typedef int BaseType_t;
typedef unsigned UBaseType_t;
typedef struct { unsigned char storage[256]; } StaticTask_t;
typedef struct { unsigned count; } StaticSemaphore_t;
typedef pthread_mutex_t portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED PTHREAD_MUTEX_INITIALIZER
#define portENTER_CRITICAL(lock) ((void)pthread_mutex_lock(lock))
#define portEXIT_CRITICAL(lock) ((void)pthread_mutex_unlock(lock))
#define pdPASS 1
#define pdFAIL 0
#define errCOULD_NOT_ALLOCATE_REQUIRED_MEMORY (-1)
#define portMAX_DELAY UINT32_MAX
#define configSUPPORT_STATIC_ALLOCATION 1
#define configASSERT(condition) assert(condition)
#define taskYIELD() ((void)0)
#define CONFIG_FREERTOS_NUMBER_OF_CORES 2
#define CONFIG_FREERTOS_THREAD_LOCAL_STORAGE_POINTERS 2
#define CONFIG_FREERTOS_TLSP_DELETION_CALLBACKS 1
unsigned xPortGetCoreID(void);
