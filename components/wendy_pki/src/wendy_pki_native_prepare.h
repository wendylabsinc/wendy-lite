/* Physical native setup waits outside the crypto worker, before copying trust,
 * reserving a large TLS input, or loading the identity. No heap or network I/O. */
#pragma once
#include "wendy_pki.h"
#include "wendy_pki_work.h"
#include "esp_timer.h"
#include <time.h>
#include <pthread.h>
#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#endif
static inline void pki_native_prepare_yield(void)
{
#ifdef ESP_PLATFORM
    vTaskDelay(1);
#else
    const struct timespec tick={.tv_nsec=1000000};(void)nanosleep(&tick,NULL);
#endif
}
static inline bool pki_native_prepare_claim(void *owner,int64_t deadline)
{
    /* A worker callback must return a future/busy result rather than await a
     * lease that another callback on this same queue may need to release. */
    if(!owner || wendy_pki_work_is_current())return false;
    for(;;){
        if(wendy_pki_reset_in_progress() || esp_timer_get_time()>=deadline)return false;
        if(wendy_pki_handshake_claim(owner))return true;
        pki_native_prepare_yield();
    }
}

/* The caller enters and returns holding identity. There are no borrowed
 * snapshots/handles at this boundary. Never await either scarce resource while
 * owning the other: legacy Cloud/identity work can take them in the reverse
 * order, and an actor PREPARE job must be able to trylock identity meanwhile. */
static inline bool pki_native_prepare_with_identity(void *owner,pthread_mutex_t *identity,int64_t deadline)
{
    if(!owner || wendy_pki_work_is_current())return false;
    pthread_mutex_unlock(identity);
    while(pki_native_prepare_claim(owner,deadline)){
        if(!pthread_mutex_trylock(identity))return true;
        wendy_pki_handshake_release(owner);
        pki_native_prepare_yield();
    }
    /* Restore the caller's existing lock contract without holding workspace.
     * Another identity operation may still own its legacy network interval. */
    pthread_mutex_lock(identity);return false;
}
