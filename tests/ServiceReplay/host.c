#include "host.h"
#include <assert.h>
static long long now;
static unsigned epoch,published,withdrawn;
static int busy,restart;
long long sys_uptime_ms(void){return now;}
void replay_test_time(long long value){now=value;}
void replay_test_epoch(unsigned value){epoch=value;}
void replay_test_busy(void){busy=1;}
void replay_test_restart(void){restart=1;}
unsigned replay_test_publications(void){return published;}
unsigned replay_test_withdrawals(void){return withdrawn;}
int services_epoch(void){return (int)epoch;}
int services_publish(const void *bytes,int size)
{assert(bytes && size>0 && epoch);published++;if(busy){busy=0;return -2;}if(restart){restart=0;epoch++;}return 0;}
int services_withdraw(const void *bytes,int size)
{assert(bytes && size>0 && epoch);withdrawn++;return 0;}
