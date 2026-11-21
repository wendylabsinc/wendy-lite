"""Compile the real guest delivery routine; closure must not reopen an OPEN."""
from pathlib import Path
import os, re, subprocess, tempfile
root=Path(__file__).resolve().parents[2]
source=(root/'wendy_net/src/wendy_net.c').read_text()
start=source.index('static int guest_datagram_deliver(')
a=source.index('{',start);depth=1;end=a+1
while depth:
    depth+=(source[end]=='{')-(source[end]=='}');end+=1
function=source[start:end]
fixture=r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#define WENDYNET_DATAGRAM_MAX 1024
#define WENDYNET_ACCEPT_QUEUE_SIZE 4
#define WENDYNET_SOCK_UDP_PEER 3
#define WENDYNET_EVENT_ACCEPT_READY 1
#define WENDYNET_EVENT_READ_READY 2
typedef void (*wendy_net_packet_release_fn)(void *);
typedef struct {bool is_udp;unsigned accepted_count;} wendynet_listener_t;
typedef struct {bool native_datagram,closed,error,closing,rx_datagram;int listener_handle,handle,sock_type;unsigned datagram_limit;uint8_t *rx;size_t rx_len;wendy_net_packet_release_fn rx_release;} wendynet_socket_t;
static wendynet_listener_t listener={.is_udp=true};
static wendynet_socket_t socket_state;
static bool held,listener_live=true;
static unsigned allocations;
static void wendynet_lock(void){assert(!held);held=true;}
static void wendynet_unlock(void){assert(held);held=false;}
static wendynet_listener_t *wendynet_find_listener_locked(int handle){assert(held);return listener_live&&handle==5?&listener:NULL;}
static wendynet_socket_t *wendynet_find_socket_locked(int handle){assert(held);return handle>0&&handle==socket_state.handle?&socket_state:NULL;}
static wendynet_socket_t *wendynet_alloc_socket_locked(int fd){assert(held&&fd==-1);allocations++;socket_state=(wendynet_socket_t){.handle=7};return &socket_state;}
static bool wendynet_listener_enqueue_locked(wendynet_listener_t *l,int handle){assert(held&&l==&listener&&handle==7);return true;}
static void wendynet_release_socket_locked(wendynet_socket_t *s){(void)s;assert(0);}
static void wendynet_notify_locked(int flags){assert(held&&flags);}
'''+function+r'''
int main(void){
 int association=0;uint8_t *packet=malloc(1);assert(packet);
 assert(guest_datagram_deliver(5,&association,&packet,0,1024,free,true)==1&&!packet&&association==7&&allocations==1);
 socket_state.rx_release(socket_state.rx);socket_state.rx=NULL;socket_state.rx_datagram=false;
 packet=malloc(1);socket_state.closing=true;
 assert(guest_datagram_deliver(5,&association,&packet,0,1024,free,true)==-1&&packet&&allocations==1);
 socket_state.closing=false;socket_state.closed=true;
 assert(guest_datagram_deliver(5,&association,&packet,0,1024,free,true)==-1&&packet&&allocations==1);
 socket_state.handle=8; /* retired association no longer resolves */
 assert(guest_datagram_deliver(5,&association,&packet,0,1024,free,true)==-1&&packet&&allocations==1);
 listener_live=false;
 assert(guest_datagram_deliver(5,&association,&packet,0,1024,free,true)==-1&&packet);
 listener_live=true;
 /* Legacy TLS API deliberately retains its prior recreation semantics. */
 assert(guest_datagram_deliver(5,&association,&packet,0,1024,free,false)==1&&!packet&&allocations==2);
 socket_state.rx_release(socket_state.rx);assert(!held);return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='wendy-retained-udp-') as tmp:
    p=Path(tmp);(p/'test.c').write_text(fixture)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True)
