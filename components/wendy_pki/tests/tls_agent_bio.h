/* Ordinary native TLS through the same small memory BIO as the mesh actor.
 * Only these outer-driver helpers perform socket I/O; CPU-step callbacks do
 * not have access to the socket or wait on it. */
#include "../../wendy_net_peer/include/wendy_net_actor.h"
struct agent_bio {
    struct wna_channel channel;
    int fd;
    unsigned reads,writes,steps;
    bool lent;
};
static int agent_bio_pump(struct agent_bio *bio)
{
    assert(!bio->lent);
    int progress=0;uint8_t bytes[31];
    size_t room=wna_buffer_space(&bio->channel.input);if(room>sizeof bytes)room=sizeof bytes;
    if(room){
        ssize_t n=recv(bio->fd,bytes,room,MSG_DONTWAIT);
        if(n>0){memcpy(bio->channel.input.bytes+bio->channel.input.size,bytes,(size_t)n);
            bio->channel.input.size+=(size_t)n;bio->reads++;progress=1;}
        else if(!n)bio->channel.eof=true;
        else assert(errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR);
    }
    size_t count=bio->channel.output.size;if(count>17)count=17;
    if(count){
        ssize_t n=send(bio->fd,bio->channel.output.bytes+bio->channel.output.offset,count,MSG_DONTWAIT);
        if(n>0){wna_buffer_consume(&bio->channel.output,(size_t)n);bio->writes++;progress=1;}
        else assert(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR));
    }
    return progress;
}
static int agent_bio_wait(void *context,bool writing,int64_t deadline)
{
    (void)writing;struct agent_bio *bio=context;assert(!bio->lent);
    if(agent_bio_pump(bio))return 0;
    int64_t remaining=deadline-esp_timer_get_time();if(remaining<=0)return -1;
    struct pollfd p={.fd=bio->fd,.events=POLLIN | (bio->channel.output.size ? POLLOUT:0)};
    int r=poll(&p,1,(int)(remaining/1000>100 ? 100:remaining/1000));
    if(r<0 && errno!=EINTR)return -1;
    (void)agent_bio_pump(bio);return 0;
}
static int agent_tls_test_begin(int fd,struct pki_tls_owned_identity *owned,
    struct wendy_conf_span roots,struct agent_bio *bio,wendy_pki_connection **out)
{
    *bio=(struct agent_bio){.fd=fd};
    assert(!fcntl(fd,F_SETFL,O_NONBLOCK));
    /* CPU callbacks only receive the memory channel, not its owning outer fd. */
    struct wendy_pki_stream stream={.context=&bio->channel,.read=wna_read,.write=wna_write,.wait=agent_bio_wait};
    bio->lent=true;
    int r=pki_tls_agent_begin(&stream,"2558fd76-afc7-466e-9613-6b715296a526",
        "00000000-0000-4000-8000-000000000004",owned,roots,out);
    bio->lent=false;
    if(r)return r;
    int64_t deadline=esp_timer_get_time()+30000000;
    for(unsigned steps=0;steps<20000;steps++){
        (void)agent_bio_pump(bio);
        bio->lent=true;r=pki_tls_agent_advance(*out);bio->lent=false;bio->steps++;
        if(!r){
            /* Established application I/O still uses memory callbacks. Its
             * explicit outer wait pumps this fd after a WANT result. */
            return 0;
        }
        if(r<0 && r!=-2 && r!=-3)break;
        if(agent_bio_wait(bio,r==-3,deadline))break;
    }
    wendy_pki_close(*out);*out=NULL;
    return -1;
}
