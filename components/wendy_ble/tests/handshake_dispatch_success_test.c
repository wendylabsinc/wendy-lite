/* Compile the actual physical BLE coordinator with the production CPU/I/O
 * dispatchers. Only the radio/RTOS and TLS entry adapter are represented. */
#define main ordinary_advertisement_fixture_main
#include "advertising_test.c"
#undef main
int64_t esp_timer_get_time(void);
#include "wendy_pki_native_prepare.h"
#include <time.h>
static unsigned io_entries,cpu_entries;
int64_t esp_timer_get_time(void){struct timespec now;clock_gettime(CLOCK_MONOTONIC,&now);return (int64_t)now.tv_sec*1000000+now.tv_nsec/1000;}
void test_physical_tls_entry(void)
{
    assert(!wendy_pki_work_is_current());
    char owner;assert(pki_native_prepare_claim(&owner,esp_timer_get_time()+1000000));
    wendy_pki_handshake_release(&owner);io_entries++;
}
static void poll_io(void){assert(wendy_pki_io_work_poll());}
static void cpu_work(void *arg){assert(arg==&cpu_entries && wendy_pki_work_is_current());cpu_entries++;}
int main(void)
{
    reset_fixture();_enrolled=true;test_enrolled=test_current=true;
    wendy_pki_work_enable();test_pending_wait=poll_io;
    assert(wendy_pki_work_submit(cpu_work,&cpu_entries));
    assert(_run_session_handshake()==ESP_OK);
    assert(io_entries==1 && test_handshake_calls==1 && !cpu_entries);
    assert(!test_tasks_created && !wendy_pki_handshake_busy() && wendy_pki_io_work_idle());
    assert(wendy_pki_work_poll() && cpu_entries==1);
    assert(_run_session_handshake()==ESP_OK && io_entries==2);
    assert(!test_tasks_created && !wendy_pki_handshake_busy());
    puts("Physical BLE handoff uses real I/O slot, preserves CPU queue, accepts native admission and creates no task");
    return 0;
}
