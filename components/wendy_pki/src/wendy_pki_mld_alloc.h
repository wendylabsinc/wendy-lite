#pragma once
/* Forced into the reference ML-DSA translation units by our component build.
 * The pinned dependency explicitly supports consumer-provided heap temporaries.
 * It zeroizes secret temporaries before invoking its matching free macro. */
#include <stddef.h>
void *wendy_pki_oqs_malloc(size_t bytes);
void wendy_pki_oqs_free(void *ptr);
#define MLD_CUSTOM_ALLOC(v, T, N) T *v = (T *)wendy_pki_oqs_malloc(sizeof(T) * (N))
#define MLD_CUSTOM_FREE(v, T, N) wendy_pki_oqs_free(v)
