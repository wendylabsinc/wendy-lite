/* Real bounded socket I/O and ordinary worker-start failure, without radios. */
#include "actor_driver.h"
#include "wendy_pki_work.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static bool worker_ok=true;
static int wake_fd=-1;
static unsigned binds,starts,closes;
static int wake_close(int fd)
{if(fd==wake_fd){closes++;wake_fd=-1;}return close(fd);}
#define close wake_close
#include "../src/actor_driver.c"
#undef close
esp_err_t esp_vfs_eventfd_register(const esp_vfs_eventfd_config_t *c)
{assert(c && c->max_fds==1);return ESP_OK;}
int eventfd(unsigned int value,int flags)
{assert(!value && !flags && wake_fd<0);return wake_fd=open("/dev/null",O_RDWR);}
void wendy_pki_work_bind_actor(void){binds++;}
bool wendy_pki_work_start(void (*wake)(void))
{assert(wake==wnad_wake);starts++;return worker_ok;}
void wendy_pki_work_metrics(struct wendy_pki_work_metrics *out){memset(out,0,sizeof *out);}
bool wendy_pki_handshake_claim(void *owner){return owner!=NULL;}
void wendy_pki_handshake_release(void *owner){assert(owner);}
int main(void)
{
    worker_ok=false;assert(wnad_start()==-1 && wnad_wake_fd()==-1 && closes==1);
    wnad_wake();
    worker_ok=true;assert(!wnad_start() && wnad_wake_fd()>=0);
    wnad_wake();wnad_wake();wnad_drain_wake();
    assert(!wnad_start() && starts==2 && binds==2);wnad_stop();assert(closes==2);
    int first[2],second[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,first));
    assert(!socketpair(AF_UNIX,SOCK_STREAM,0,second));
    /* Production descriptors are nonblocking even on hosts whose AF_UNIX
     * implementation does not honour MSG_DONTWAIT for a full send buffer. */
    assert(!fcntl(first[0],F_SETFL,O_NONBLOCK));
    assert(!fcntl(second[0],F_SETFL,O_NONBLOCK));
    int small=1024;assert(!setsockopt(first[0],SOL_SOCKET,SO_SNDBUF,&small,sizeof small));
    struct wna_channel blocked={0},available={0};uint8_t bytes[WNA_IO_BYTES];memset(bytes,7,sizeof bytes);
    bool pressure=false;
    for(unsigned i=0;i<10000;i++){
        if(!blocked.output.size)assert(wna_write(&blocked,bytes,sizeof bytes)==sizeof bytes);
        int n=wnad_channel_io(&blocked,first[0],NULL);assert(n>=0);
        if(!n && blocked.output.size){pressure=true;break;}
    }
    assert(pressure && !blocked.failed);
    assert(send(second[1],"sensor",6,0)==6);
    assert(wnad_channel_io(&available,second[0],NULL)==1);
    uint8_t received[16];assert(wna_read(&available,received,sizeof received)==6 && !memcmp(received,"sensor",6));
    assert(wna_write(&available,"reply",5)==5);
    assert(wnad_channel_io(&available,second[0],NULL)==1);
    assert(recv(second[1],received,sizeof received,0)==5 && !memcmp(received,"reply",5));
    assert(!shutdown(second[1],SHUT_WR));assert(wnad_channel_io(&available,second[0],NULL)==1 && available.eof);
    assert(!close(first[0]) && !close(first[1]) && !close(second[0]) && !close(second[1]));
    int listener=socket(AF_INET,SOCK_STREAM,0);assert(listener>=0);
    struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(!bind(listener,(struct sockaddr *)&addr,sizeof addr) && !listen(listener,1));
    socklen_t length=sizeof addr;assert(!getsockname(listener,(struct sockaddr *)&addr,&length));
    bool connecting=false;int client=wnad_connect("127.0.0.1",ntohs(addr.sin_port),&connecting);assert(client>=0);
    int accepted=accept(listener,NULL,NULL);assert(accepted>=0);
    assert(wnad_prepare_socket(accepted) && (fcntl(accepted,F_GETFL)&O_NONBLOCK));
    for(unsigned i=0;connecting && i<1000;i++){int r=wnad_connected(client);assert(r>=0);if(r>0)connecting=false;}
    assert(!connecting && (fcntl(client,F_GETFL)&O_NONBLOCK));
    assert(!close(client) && !close(accepted) && !close(listener));
    puts("outer driver partial I/O, saturated-link independence, wake restart and numeric connect pass");
}
