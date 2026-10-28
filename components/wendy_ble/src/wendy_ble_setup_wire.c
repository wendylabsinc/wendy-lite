#include "wendy_ble_setup_wire.h"
#include "pb_decode.h"
#include "pb_encode.h"

bool wble_setup_unwrap(const uint8_t *data, size_t size, uint32_t *tag, struct wble_setup_span *body)
{
    pb_istream_t input = pb_istream_from_buffer(data, size), sub;
    pb_wire_type_t wire;
    bool eof;
    if (!pb_decode_tag(&input, &wire, tag, &eof) || !*tag || wire != PB_WT_STRING ||
        !pb_make_string_substream(&input, &sub)) return false;
    *body = (struct wble_setup_span){ sub.state, sub.bytes_left };
    return pb_close_string_substream(&input, &sub) && input.bytes_left == 0;
}

bool wble_setup_wrap(uint32_t tag, const void *data, size_t size,
                     uint8_t *out, size_t capacity, size_t *written)
{
    pb_ostream_t output = pb_ostream_from_buffer(out, capacity);
    bool ok = pb_encode_tag(&output, PB_WT_STRING, tag) && pb_encode_string(&output, data, size);
    *written = ok ? output.bytes_written : 0;
    return ok;
}

bool wble_setup_encode(uint32_t tag, const pb_msgdesc_t *fields, const void *message,
                       uint8_t *out, size_t capacity, size_t *written)
{
    pb_ostream_t output = pb_ostream_from_buffer(out, capacity);
    bool ok = pb_encode_tag(&output, PB_WT_STRING, tag) && pb_encode_submessage(&output, fields, message);
    *written = ok ? output.bytes_written : 0;
    return ok;
}
