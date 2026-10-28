/* Normal generated identities shared by the native VIP integration fixtures. */
#pragma once
struct der_source_test { mbedtls_x509_crt chain; };
static int read_der_test(void *context,unsigned index,uint8_t **bytes,size_t *size)
{
    const mbedtls_x509_crt *part=&((struct der_source_test *)context)->chain;
    for(unsigned i=0;i<index && part;i++)part=part->next;
    *bytes=NULL;*size=0;if(!part || !part->raw.len)return 0;
    *bytes=pki_owned_malloc(part->raw.len);if(!*bytes)return -1;
    *size=part->raw.len;memcpy(*bytes,part->raw.p,*size);return 1;
}
static int hash_der_test(void *context,unsigned index,uint8_t hash[32],size_t *size)
{
    const mbedtls_x509_crt *part=&((struct der_source_test *)context)->chain;
    for(unsigned i=0;i<index && part;i++)part=part->next;
    *size=0;if(!part || !part->raw.len)return 0;
    if(wendy_pki_sha256(part->raw.p,part->raw.len,hash))return -1;
    *size=part->raw.len;return 1;
}
static int read_der_range_test(void *context,unsigned index,size_t offset,
    uint8_t *output,size_t count,const uint8_t expected[32])
{
    uint8_t *der=NULL,hash[32];size_t size=0;
    int loaded=read_der_test(context,index,&der,&size);
    bool valid=loaded==1 && offset<=size && count<=size-offset &&
        !wendy_pki_sha256(der,size,hash) && !memcmp(hash,expected,32);
    if(valid && count)memcpy(output,der+offset,count);
    pki_owned_free(der);return valid ? (int)count:-1;
}
