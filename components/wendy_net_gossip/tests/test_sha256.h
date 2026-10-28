/* Host fixture only; firmware supplies its own SHA-256 backend. */
#include <openssl/evp.h>
static int identify(void *ctx, uint8_t type, const void *data, size_t size,
                    uint8_t out[32]) {
  (void)ctx;
  static const char domain[] = "wendy-mesh-artifact/1";
  uint8_t n[4] = {(uint8_t)(size >> 24), (uint8_t)(size >> 16),
                  (uint8_t)(size >> 8), (uint8_t)size};
  EVP_MD_CTX *hash = EVP_MD_CTX_new();
  unsigned written = 0;
  int ok = hash && EVP_DigestInit_ex(hash, EVP_sha256(), NULL) &&
           EVP_DigestUpdate(hash, domain, sizeof domain) &&
           EVP_DigestUpdate(hash, &type, 1) && EVP_DigestUpdate(hash, n, 4) &&
           EVP_DigestUpdate(hash, data, size) &&
           EVP_DigestFinal_ex(hash, out, &written) && written == 32;
  EVP_MD_CTX_free(hash);
  return ok ? 0 : -1;
}
