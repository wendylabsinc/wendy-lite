#include "wendy_net_direct_binding.h"
#include "wendy_net_direct_flows.h"
int wn_direct_promoted_poll(struct wn_direct_promoted_binding *b, const struct wn_direct_upper *io)
{
    if (!b || !io || !io->read || !io->write || b->failed)
        return -1;
    if (b->done)
        return 0;
    const uint8_t *bytes;
    size_t size;
    int ready = wn_direct_promoted_output(b, &bytes, &size);
    if (ready < 0)
        return -1;
    if (ready) {
        int n = io->write(io->context, bytes, size);
        if (n > 0) {
            if ((size_t)n > size || wn_direct_promoted_sent(b, (size_t)n))
                return -1;
            return 1;
        }
        return n == -2 || n == -3 ? 0 : -1;
    }
    uint8_t input[64];
    size_t wanted = b->size - b->offset;
    if (!wanted || wanted > sizeof input)
        return -1;
    int n = io->read(io->context, input, wanted);
    if (n > 0) {
        size_t used;
        if ((size_t)n > wanted || wn_direct_promoted_input(b, input, (size_t)n, &used) ||
            used != (size_t)n)
            return -1;
        return 1;
    }
    return n == -2 || n == -3 ? 0 : -1;
}
