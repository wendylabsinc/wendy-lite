/* Transport/BIO results are distinct from TLS's own internal invariants. */
#pragma once
#include <limits.h>
#include <stddef.h>
#include <sys/types.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>

static inline int pki_stream_read_result(ssize_t result,size_t requested)
{
    if(result==-2)return MBEDTLS_ERR_SSL_WANT_READ;
    if(result==-3)return MBEDTLS_ERR_SSL_WANT_WRITE;
    if(result<0)return MBEDTLS_ERR_NET_RECV_FAILED;
    if((size_t)result>requested || result>INT_MAX)return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    return (int)result; /* Ordinary transport EOF remains EOF. */
}

static inline int pki_stream_write_result(ssize_t result,size_t requested)
{
    if(result==-2)return MBEDTLS_ERR_SSL_WANT_READ;
    if(result==-3)return MBEDTLS_ERR_SSL_WANT_WRITE;
    if(result<0)return MBEDTLS_ERR_NET_SEND_FAILED;
    if(!result)return MBEDTLS_ERR_NET_CONN_RESET;
    if((size_t)result>requested || result>INT_MAX)return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    return (int)result;
}
