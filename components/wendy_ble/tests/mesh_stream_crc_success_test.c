/* SPDX-License-Identifier: Apache-2.0 */
#include "mesh_stream_crc.h"
#include <assert.h>
#include <string.h>
#include <zlib.h>

int main(void)
{
    assert(wble_stream_crc_self_test());
    struct wble_stream_crc known={0};
    wble_stream_crc_accept(&known,0,"123456789",9);
    assert(known.crc[0]==UINT32_C(0xcbf43926));
    uint8_t bytes[53352];
    for(size_t i=0;i<sizeof bytes;i++)bytes[i]=(uint8_t)(i*37+i/251);
    const size_t chunks[]={1,73,240,490,980,4096,8193};
    for(size_t c=0;c<sizeof chunks/sizeof *chunks;c++){
        struct wble_stream_crc s={0};
        for(unsigned direction=0;direction<2;direction++){
            for(size_t at=0;at<sizeof bytes;){
                size_t n=chunks[c];if(n>sizeof bytes-at)n=sizeof bytes-at;
                wble_stream_crc_accept(&s,direction,bytes+at,n);at+=n;
                assert(s.bytes[direction]==at);
                assert(s.crc[direction]==(uint32_t)crc32(0,bytes,(uInt)at));
                size_t boundary=at/WBLE_CRC_STRIDE*WBLE_CRC_STRIDE;
                if(boundary)assert(s.boundary_crc[direction]==(uint32_t)crc32(0,bytes,(uInt)boundary));
                if(at>=WBLE_CRC_STRIDE)assert(s.first_crc[direction]==(uint32_t)crc32(0,bytes,WBLE_CRC_STRIDE));
            }
        }
        struct wble_stream_crc snapshot=s;
        wble_stream_crc_accept(&s,0,bytes,0);
        assert(!memcmp(&snapshot,&s,sizeof s));
    }
    return 0;
}
