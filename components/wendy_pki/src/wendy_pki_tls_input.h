#pragma once
#include <stdbool.h>
#include <stddef.h>
#define PKI_TLS_INPUT_RESERVE 26624U
/* Inactive/default: ordinary calloc/free. Active: at most one cached/loaned
 * preferred-size allocation; callers own all returned allocations. Reuse is
 * exact for certificate workspaces. Baseline TLS may borrow the tracked mesh
 * input block without retagging its owner; mesh shutdown remains draining until
 * that finite loan returns, then frees it instead of recaching. A preferred
 * baseline reservation predating activation delays cache allocation until it
 * returns, without adopting its owner. Repeating active(true) from the mesh
 * owner retries that deferred allocation. */
void wendy_pki_input_workspace_active(bool active);
size_t wendy_pki_input_workspace_cached_bytes(void);
unsigned char *wendy_pki_input_workspace_borrow(size_t *capacity);
void wendy_pki_input_workspace_release(unsigned char *);
void pki_tls_input_discard_cached(void);
unsigned char *pki_tls_input_take(size_t size);
void pki_tls_input_return(unsigned char *,size_t);
/* Mbed TLS passes already-zeroized bytes and honors a nonzero ownership claim. */
int pki_tls_input_recycle(void *,unsigned char *,size_t);
