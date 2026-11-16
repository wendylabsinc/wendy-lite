#include "wendy_net_direct_wire.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned nibble(char c)
{
    if (c >= '0' && c <= '9')
        return (unsigned)(c - '0');
    if (c >= 'a' && c <= 'f')
        return (unsigned)(c - 'a' + 10);
    return 256;
}
static size_t unhex(const char *s, uint8_t *b)
{
    size_t n = strlen(s);
    assert(n % 2 == 0 && n / 2 <= WN_DIRECT_MAX_FRAME);
    for (size_t i = 0; i < n / 2; i++) {
        unsigned a = nibble(s[2 * i]), c = nibble(s[2 * i + 1]);
        assert(a < 16 && c < 16);
        b[i] = (uint8_t)(a * 16 + c);
    }
    return n / 2;
}
int main(void)
{
    const char *vectors[] = {"011122334400000001aabb",
                             "021122334401000000010000000000000102000000000000040001",
                             "030000000100000002000000000000002a",
                             "04000000010000000102002a1000",
                             "0500000001000000010002",
                             "0600000001000000000000000a",
                             "070000000100000001000000000000000200040002aabb",
                             "0800000001000000010003",
                             "090000000100000001",
                             "0a000000011000"};
    uint8_t in[WN_DIRECT_MAX_FRAME], out[WN_DIRECT_MAX_FRAME];
    for (size_t i = 0; i < sizeof vectors / sizeof *vectors; i++) {
        size_t n = unhex(vectors[i], in), written = 0;
        struct wn_direct_frame f;
        assert(!wn_direct_frame_decode(in, n, &f));
        assert(f.kind == i + 1);
        assert(!wn_direct_frame_encode(&f, out, sizeof out, &written));
        assert(written == n && !memcmp(in, out, n));
    }
    puts("direct wire golden records passed");
    return 0;
}
