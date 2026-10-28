/* SPDX-License-Identifier: Apache-2.0 */
#include "certificate_wire.h"
#include <stdio.h>
#include <string.h>
static int read_hash(const struct wn_doc *d,int token,uint8_t out[32])
{size_t n=0;return wn_doc_copy_bytes(d,token,out,32,&n) || n!=32 ? -1:0;}
int wncf_chain_read(const struct wn_doc *d,unsigned object,const char *tenant,
                    struct wncf_chain *out)
{
    static const char *const fields[]={"principal","hashes",NULL};uint8_t device[16];
    if(!d || !out || !wn_doc_fields(d,object,fields))return -1;
    memset(out,0,sizeof *out);
    if(wn_doc_string(d,wn_doc_member(d,object,"principal"),out->principal,sizeof out->principal)!=105 ||
       wn_principal_device(out->principal,tenant,device))return -1;
    int array=wn_doc_member(d,object,"hashes");
    if(array<0 || d->tokens[array].type!='[')return -1;
    for(unsigned i=(unsigned)array+1;i<d->tokens[array].next;i=d->tokens[i].next){
        if(out->count==WNCF_CHAIN_MAX || read_hash(d,(int)i,out->hashes[out->count]))return -1;
        for(unsigned j=0;j<out->count;j++)if(!memcmp(out->hashes[j],out->hashes[out->count],32))return -1;
        out->count++;
    }
    return out->count ? 0:-1;
}
int wncf_descriptor_write(const struct wncf_chain *chain,char *out,size_t cap)
{
    if(!chain || !out || !chain->count || chain->count>WNCF_CHAIN_MAX)return -1;
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_CONTROL_MAX};
    wn_map(&w,2);wn_key(&w,"hashes");wn_array(&w,chain->count);
    for(unsigned i=0;i<chain->count;i++)wn_bytes(&w,chain->hashes[i],32);
    wn_key(&w,"principal");wn_text(&w,chain->principal);return wn_finish(&w);
}
int wncf_chain_write(const struct wncf_chain *chain,char *out,size_t cap)
{
    if(!out || cap<32)return -1;
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_CONTROL_MAX};
    wn_map(&w,2);wn_key(&w,"kind");wn_text(&w,"certificate");wn_key(&w,"certificate");
    wn_map(&w,1);wn_key(&w,"chain");if(w.failed)return -1;
    int n=wncf_descriptor_write(chain,(char*)w.data+w.size,cap-w.size);
    return n<0 ? -1:(int)w.size+n;
}
int wncf_request_read(const struct wn_doc *d,unsigned object,struct wncf_request *out)
{
    static const char *const fields[]={"hash","offset",NULL};uint64_t offset;
    if(!out || !wn_doc_fields(d,object,fields) ||
       read_hash(d,wn_doc_member(d,object,"hash"),out->hash) ||
       wn_doc_u64(d,wn_doc_member(d,object,"offset"),&offset) ||
       offset>=WNCF_PART_MAX || offset%WNCF_CHUNK)return -1;
    out->offset=(size_t)offset;return 0;
}
int wncf_request_write(const struct wncf_request *q,char *out,size_t cap)
{
    if(!q || !out || q->offset>=WNCF_PART_MAX || q->offset%WNCF_CHUNK)return -1;
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_CONTROL_MAX};
    wn_map(&w,2);wn_key(&w,"kind");wn_text(&w,"certificate");wn_key(&w,"certificate");
    wn_map(&w,1);wn_key(&w,"request");wn_map(&w,2);
    wn_key(&w,"hash");wn_bytes(&w,q->hash,32);wn_key(&w,"offset");wn_uint(&w,q->offset);
    return wn_finish(&w);
}
int wncf_chunk_read_view(const struct wn_doc *d,unsigned object,struct wncf_chunk *out,
                    const uint8_t **data)
{
    static const char *const fields[]={"hash","offset","total","data",NULL};
    uint64_t offset,total;
    if(!out || !data || !wn_doc_fields(d,object,fields) ||
       read_hash(d,wn_doc_member(d,object,"hash"),out->hash) ||
       wn_doc_u64(d,wn_doc_member(d,object,"offset"),&offset) ||
       wn_doc_u64(d,wn_doc_member(d,object,"total"),&total) ||
       !total || total>WNCF_PART_MAX || offset>=total || offset%WNCF_CHUNK)return -1;
    size_t size=0;
    if(wn_doc_bytes(d,wn_doc_member(d,object,"data"),data,&size) || size>WNCF_CHUNK ||
       size!=(total-offset<WNCF_CHUNK ? total-offset:WNCF_CHUNK))return -1;
    out->offset=(size_t)offset;out->total=(size_t)total;out->size=size;return 0;
}
int wncf_chunk_read(const struct wn_doc *d,unsigned object,struct wncf_chunk *out,uint8_t data[WNCF_CHUNK])
{
    const uint8_t *bytes;if(!data || wncf_chunk_read_view(d,object,out,&bytes))return -1;
    memcpy(data,bytes,out->size);return 0;
}
int wncf_chunk_write(const struct wncf_chunk *chunk,const void *data,char *out,size_t cap)
{
    if(!chunk || !data || !out || !chunk->total || chunk->total>WNCF_PART_MAX ||
       chunk->offset>=chunk->total || chunk->offset%WNCF_CHUNK ||
       chunk->size!=(chunk->total-chunk->offset<WNCF_CHUNK ? chunk->total-chunk->offset:WNCF_CHUNK))return -1;
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_CONTROL_MAX};
    wn_map(&w,2);wn_key(&w,"kind");wn_text(&w,"certificate");wn_key(&w,"certificate");
    wn_map(&w,1);wn_key(&w,"chunk");wn_map(&w,4);
    wn_key(&w,"data");wn_bytes(&w,data,chunk->size);wn_key(&w,"hash");wn_bytes(&w,chunk->hash,32);
    wn_key(&w,"total");wn_uint(&w,chunk->total);wn_key(&w,"offset");wn_uint(&w,chunk->offset);
    return wn_finish(&w);
}

int wncf_missing_write(const struct wncf_request *q,bool operator_domain,char *out,size_t cap)
{
    if(!q || !out || q->offset>=WNCF_PART_MAX || q->offset%WNCF_CHUNK)return -1;
    struct wn_writer w={.data=(uint8_t*)out,.capacity=cap,.maximum=WN_CONTROL_MAX};
    wn_map(&w,2);wn_key(&w,"kind");wn_text(&w,operator_domain ? "operator-certificate":"certificate");
    wn_key(&w,operator_domain ? "operatorCertificate":"certificate");wn_map(&w,1);
    wn_key(&w,"missing");wn_map(&w,2);wn_key(&w,"hash");wn_bytes(&w,q->hash,32);
    wn_key(&w,"offset");wn_uint(&w,q->offset);return wn_finish(&w);
}
