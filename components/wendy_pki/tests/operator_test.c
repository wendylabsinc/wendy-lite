#include "wendy_pki_verify.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <wolfssl/ssl.h>
int main(int argc, char **argv) {
    assert(argc == 2);
    wolfSSL_Init();
    const char *names[] = {"valid", "wrong-role", "duplicate", "wrong-eku", "ca"};
    for (int i = 0; i < 5; i++) {
        char path[1024]; snprintf(path, sizeof path, "%s/%s.der", argv[1], names[i]);
        FILE *f = fopen(path, "rb"); assert(f);
        unsigned char der[4096]; size_t n = fread(der, 1, sizeof der, f); fclose(f);
        int result = wendy_pki_verify_operator(der, n, "11111111-1111-4111-8111-111111111111");
        assert((result == 0) == (i == 0));
        assert(wendy_pki_verify_operator(der, n, "33333333-3333-4333-8333-333333333333") != 0);
        assert(wendy_pki_verify_operator(der, n / 2, "11111111-1111-4111-8111-111111111111") != 0);
    }
    assert(wendy_pki_verify_operator(NULL, 0, "") != 0);
    return 0;
}
