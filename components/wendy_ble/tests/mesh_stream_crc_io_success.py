#!/usr/bin/env python3
"""Positive accepted-byte accounting using the actual production stream bodies."""
from pathlib import Path
import os,shlex,subprocess,tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'src/wendy_ble_mesh.c').read_text()
bodies=s[s.index('static ssize_t stream_read('):s.index('static int stream_wait(')]
prefix=r'''
#include "mesh_stream_crc.h"
#include "mesh_rx_window.h"
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <zlib.h>
#define CONFIG_WENDY_NET_TEST_BLE_STREAM_CRC 1
#define MTU 490
#define TX_MAX 240
#define RX_SLOTS 2
struct wble_mesh_pipe {
    unsigned char ring[2*MTU],tx[TX_MAX];
    size_t ring_head,ring_size,tx_size,tx_mtu;
    bool connected,closing,tx_pending,stalled;
    unsigned rx_owed;
    struct wble_stream_crc crc;
};
static bool gate=true;
static bool trylock(void){return gate;}
static void unlock(void){}
static void post(struct wble_mesh_pipe *p){(void)p;}
'''
suffix=r'''
int main(void){
    unsigned char input[53352],output[53352];
    for(size_t i=0;i<sizeof input;i++)input[i]=(unsigned char)(i*37+i/251);
    struct wble_mesh_pipe p={.connected=true,.tx_mtu=240};
    size_t at=0;
    while(at<sizeof input){
        struct wble_stream_crc before=p.crc;
        gate=false;assert(stream_write(&p,input+at,sizeof input-at)==-3);gate=true;
        assert(!memcmp(&before,&p.crc,sizeof before));
        ssize_t n=stream_write(&p,input+at,sizeof input-at);assert(n>0);
        memcpy(output+at,p.tx,(size_t)n);at+=(size_t)n;
        before=p.crc;
        assert(stream_write(&p,input,1)==-3);
        p.tx_pending=false;p.stalled=true;assert(stream_write(&p,input,1)==-3);
        p.stalled=false;p.connected=false;assert(stream_write(&p,input,1)==-1);
        p.connected=true;assert(stream_write(&p,input,0)==0);
        assert(!memcmp(&before,&p.crc,sizeof before));
    }
    assert(!memcmp(input,output,sizeof input));
    assert(p.crc.bytes[0]==sizeof input && p.crc.crc[0]==crc32(0,input,sizeof input));
    p.ring_head=900;at=0;size_t got=0;
    while(at<sizeof input){
        size_t n=sizeof input-at;if(n>MTU)n=MTU;
        size_t tail=(p.ring_head+p.ring_size)%sizeof p.ring;
        for(size_t i=0;i<n;i++)p.ring[(tail+i)%sizeof p.ring]=input[at+i];
        at+=n;p.ring_size+=n;
        while(p.ring_size){
            struct wble_stream_crc before=p.crc;
            gate=false;assert(stream_read(&p,output+got,73)==-2);gate=true;
            assert(!memcmp(&before,&p.crc,sizeof before));
            ssize_t read=stream_read(&p,output+got,73);assert(read>0);got+=(size_t)read;
        }
        struct wble_stream_crc before=p.crc;
        assert(stream_read(&p,output+got,1)==-2);
        p.connected=false;assert(stream_read(&p,output+got,1)==0);p.connected=true;
        assert(stream_read(&p,output+got,0)==0);
        assert(!memcmp(&before,&p.crc,sizeof before));
    }
    assert(got==sizeof input && !memcmp(input,output,sizeof input));
    assert(p.crc.bytes[1]==sizeof input && p.crc.crc[1]==crc32(0,input,sizeof input));
    assert(p.crc.first_crc[0]==crc32(0,input,4096));
    assert(p.crc.first_crc[0]==p.crc.first_crc[1]);
    return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='wendy-stream-crc-') as tmp:
    source=Path(tmp)/'fixture.c';source.write_text(prefix+bodies+suffix)
    binary=Path(tmp)/'fixture'
    command=shlex.split(os.environ.get('CC','cc'))+['-std=c11','-Wall','-Wextra','-Werror','-UNDEBUG']
    command+=shlex.split(os.environ.get('CFLAGS',''))
    command+=['-I'+str(root/'include'),'-I'+str(root/'src'),str(source),str(root/'src/mesh_stream_crc.c'),'-lz','-o',str(binary)]
    subprocess.run(command,check=True);subprocess.run([str(binary)],check=True)
print('PASS: actual BLE stream bodies; exact53352B in both directions, short writes, blocked retries and ring wrap; no payload retained')
