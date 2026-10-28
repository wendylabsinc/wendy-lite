#pragma once
#include <mbedtls/pk.h>
#include <stddef.h>
#include <stdint.h>
/* No session authorization here: caller exclusively owns an already admitted
 * private key and performs the normal session/principal checks first. */
size_t pki_artifact_signature_capacity(const mbedtls_pk_context *);
int pki_artifact_sign(mbedtls_pk_context *,unsigned kind,const char *principal,
    const void *body,size_t size,uint8_t *signature,size_t capacity,size_t *written);
