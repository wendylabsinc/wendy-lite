/* SPDX-License-Identifier: Apache-2.0 */
#include "mesh_stream_crc.h"
#ifdef ESP_PLATFORM
#include "esp_rom_crc.h"
#else
/* Host reference for exercising the production boundary accounting. */
static uint32_t esp_rom_crc32_le(uint32_t previous,const uint8_t *data,uint32_t size)
{
    uint32_t crc=~previous;
    for(uint32_t i=0;i<size;i++){
        crc^=data[i];
        for(unsigned bit=0;bit<8;bit++)
            crc=(crc>>1)^((0u-(crc&1u))&UINT32_C(0xedb88320));
    }
    return ~crc;
}
#endif
bool wble_stream_crc_self_test(void)
{
    const uint8_t text[]="123456789";
    uint32_t first=esp_rom_crc32_le(0,text,4);
    return esp_rom_crc32_le(0,text,9)==UINT32_C(0xcbf43926) &&
        esp_rom_crc32_le(first,text+4,5)==UINT32_C(0xcbf43926);
}
void wble_stream_crc_accept(struct wble_stream_crc *s,unsigned direction,
                            const void *data,size_t size)
{
    if(!s || direction>1 || !size)return;
    const uint8_t *bytes=data;
    while(size){
        size_t part=(size_t)(WBLE_CRC_STRIDE-s->bytes[direction]%WBLE_CRC_STRIDE);
        if(part>size)part=size;
        s->crc[direction]=esp_rom_crc32_le(s->crc[direction],bytes,(uint32_t)part);
        s->bytes[direction]+=part;bytes+=part;size-=part;
        if(!(s->bytes[direction]%WBLE_CRC_STRIDE)){
            s->boundary_crc[direction]=s->crc[direction];
            if(s->bytes[direction]==WBLE_CRC_STRIDE)
                s->first_crc[direction]=s->crc[direction];
        }
    }
}
