/* Normal worker lifecycle: planned renewal, ordinary failures and handoff. */
#include <assert.h>
#include <stdio.h>
#include "../src/wendy_cloud.c"
struct wendy_pki_connection {int fd;};
static struct wendy_pki_connection connections[4];
static unsigned connect_count,close_count,delays,handoffs,completed;
bool wendy_conf_has_enrollment(void){return true;}
SemaphoreHandle_t xSemaphoreCreateBinary(void){return (void *)1;}
BaseType_t xTaskCreatePinnedToCore(void (*entry)(void *),const char *name,unsigned stack,void *arg,unsigned priority,TaskHandle_t *handle,unsigned core)
{(void)entry;(void)name;(void)stack;(void)arg;(void)priority;(void)handle;(void)core;return pdPASS;}
BaseType_t xSemaphoreTake(SemaphoreHandle_t handle,TickType_t ticks)
{
    assert(handle==s_wake && ticks==5000);
    assert(connect_count==2 || connect_count==3);
    if(connect_count==3)assert(wendy_cloud_connect_failures()==1);
    delays++;return pdTRUE;
}
BaseType_t xSemaphoreGive(SemaphoreHandle_t handle)
{assert(handle==s_stopped);completed++;return pdTRUE;}
void vTaskDelete(TaskHandle_t task){assert(!task);}
esp_err_t wendy_pki_connect(wendy_pki_connection **out)
{
    connect_count++;assert(connect_count<=4);
    assert((connect_count!=2 || delays==0) && (connect_count!=3 || delays==1));
    if(connect_count==3)return ESP_FAIL;
    connections[connect_count-1].fd=100+(int)connect_count;
    *out=&connections[connect_count-1];return ESP_OK;
}
int wendy_pki_fd(void *connection){return ((struct wendy_pki_connection *)connection)->fd;}
int wendy_pki_relay_upgrade(wendy_pki_connection *connection,struct wendy_lite_trust *trust)
{
    assert(trust && connection && s_outer_fd==connection->fd);
    if(connect_count==1)return WENDY_PKI_RELAY_RENEW;
    if(connect_count==2)return WENDY_PKI_RELAY_FAILED;
    assert(connect_count==4);return 42;
}
void wendy_pki_close(wendy_pki_connection *connection)
{(void)connection;assert(s_outer_fd==-1);close_count++;}
void wendy_server_accept_operator(int fd,const struct wendy_lite_trust *trust)
{assert(fd==42 && trust && delays==2);handoffs++;atomic_store(&s_stop,true);}
int main(void)
{
    s_wake=(void *)2;s_stopped=(void *)3;s_task=(void *)4;
    cloud_task(NULL);
    assert(connect_count==4 && close_count==4 && delays==2 && handoffs==1 && completed==1);
    assert(!s_task && s_outer_fd==-1 && wendy_cloud_get_state()==WENDY_CLOUD_STATE_IDLE);
    assert(!wendy_cloud_connect_failures());
    puts("PASS planned refresh retries immediately; transport/connect failures back off; handoff replaces waiter and drains ownership");
}
