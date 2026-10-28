#pragma once
#include <psa/crypto.h>
#include <stddef.h>
#include <stdint.h>
/* Bound temporary copies in ordinary PSA builds. The pinned ESP port already
 * aliases exclusive input buffers; there, one update avoids needless chunk
 * dispatch. This helper never enables the exclusive-buffer assumption. */
static inline psa_status_t wendy_pki_hash_update_bounded(psa_hash_operation_t *operation,
    const void *data,size_t size)
{
    if(!size)return PSA_SUCCESS;
#if defined(MBEDTLS_PSA_ASSUME_EXCLUSIVE_BUFFERS)
    return psa_hash_update(operation,data,size);
#else
    const uint8_t *bytes=data;
    while(size){
        size_t part=size>256 ? 256:size;
        psa_status_t status=psa_hash_update(operation,bytes,part);
        if(status!=PSA_SUCCESS)return status;
        bytes+=part;size-=part;
    }
    return PSA_SUCCESS;
#endif
}
