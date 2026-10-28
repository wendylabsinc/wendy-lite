#pragma once
#include <stdint.h>
/* RAM publication epoch, updated under PKI's identity lock before replacing
 * public certificate material. A stale source remains readable only through
 * its existing full-validation path, never advertised as current metadata. */
uint32_t pki_public_certificate_epoch(void);
void pki_public_certificate_changed(void);
