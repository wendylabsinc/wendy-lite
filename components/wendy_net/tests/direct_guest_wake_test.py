"""Exercise production guest wake, registration and native receive drain."""
from pathlib import Path
import os,re,subprocess,tempfile
source=(Path(__file__).resolve().parents[2]/'wendy_net/src/wendy_net.c').read_text()
def function(name):
    m=re.search(r'(?m)^(?:static )?[^\n]*\b'+name+r'\([^;{}]*\)\s*\{',source);assert m
    a=source.index('{',m.start());end=a+1;depth=1
    while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[m.start():end]
fixture=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#define WENDYNET_SOCK_UDP 1
#define WENDYNET_SOCK_UDP_PEER 2
#define WENDYNET_BUFFER_SIZE 1024
typedef void *wasm_exec_env_t;
typedef struct {size_t rx_len;bool rx_datagram,native_datagram,resolving,connecting,closing,closed,error;int sock_type;char *rx;} wendynet_socket_t;
static wendynet_socket_t socket_state;
static int s_wakeup_fd=-1;
static void (*s_wendynet_mesh_wake)(void);
static bool held;
static unsigned wakes,writes;
static void wendynet_lock(void){assert(!held);held=true;}
static void wendynet_unlock(void){assert(held);held=false;}
static void wake(void){assert(held);wakes++;}
static ssize_t fake_write(int fd,const void *bytes,size_t size){assert(held&&fd==9&&size==8&&*(const uint64_t *)bytes==1);writes++;return -1;}
#define write fake_write
static wendynet_socket_t *wendynet_find_socket_locked(int handle){assert(held&&handle==7);return &socket_state;}
static void wendynet_release_rx_locked(wendynet_socket_t *s){assert(held);s->rx_len=0;s->rx_datagram=false;}
static void wendynet_release_drained_closed_socket_locked(wendynet_socket_t *s){(void)s;assert(held);}
'''+function('wendynet_wake_locked')+'\n'+function('wendy_net_set_mesh_waker')+'\n'+function('wendynet_socket_recv_wrapper')+r'''
int main(void){
 wendy_net_set_mesh_waker(wake);assert(wakes==1&&!writes);
 /* no sleeps or scheduler polling in the wake path */
 wendynet_lock();wendynet_wake_locked();wendynet_unlock();assert(wakes==2&&!writes);
 char data[4]="abc",out[4];socket_state=(wendynet_socket_t){.rx=data,.rx_len=3,.rx_datagram=true,.native_datagram=true,.sock_type=WENDYNET_SOCK_UDP_PEER};
 assert(wendynet_socket_recv_wrapper(NULL,7,out,sizeof out)==3&&!memcmp(out,"abc",3));assert(wakes==3);
 socket_state.rx_datagram=true; /* empty packet also releases queue credit */
 assert(wendynet_socket_recv_wrapper(NULL,7,out,sizeof out)==0&&wakes==4);
 s_wakeup_fd=9;wendynet_lock();wendynet_wake_locked();wendynet_unlock();assert(wakes==5&&writes==1);
 wendy_net_set_mesh_waker(NULL);wendynet_lock();wendynet_wake_locked();wendynet_unlock();assert(wakes==5&&writes==2&&!held);
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='wendy-guest-wake-') as tmp:
 p=Path(tmp);(p/'test.c').write_text(fixture)
 subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
