#ifndef WENDY_PKI_HTTP_RESPONSE_H
#define WENDY_PKI_HTTP_RESPONSE_H

/* Shared bounded response parsing for the two authenticated HTTPS backends. */
#define LITE_AUTHORITY_HEADER "x-wendy-lite-operator-authority"
struct response {
    uint8_t *bytes;
    size_t size, capacity;
    bool complete, capture_lite_authority, headers_complete, alloc_failed;
    char field[sizeof LITE_AUTHORITY_HEADER];
    size_t field_size;
    bool in_value, authority_value, authority_seen;
    char *lite_authority;
    size_t lite_authority_size;
};

static bool authority_field(const struct response *r)
{
    return r->field_size == sizeof LITE_AUTHORITY_HEADER - 1 &&
        !memcmp(r->field, LITE_AUTHORITY_HEADER, sizeof LITE_AUTHORITY_HEADER - 1);
}

static int finish_header(struct response *r)
{
    return authority_field(r) && (!r->in_value || !r->lite_authority_size) ? -1 : 0;
}

static int on_header_field(http_parser *p, const char *bytes, size_t size)
{
    struct response *r = p->data;
    if (!r->capture_lite_authority) return 0;
    if (r->in_value) {
        if (finish_header(r)) return -1;
        r->field_size = 0;
        r->in_value = r->authority_value = false;
    }
    /* Keep only enough of an unrelated field to rule out an exact match. */
    for (size_t i = 0; i < size && r->field_size < sizeof r->field; ++i) {
        unsigned char c = (unsigned char)bytes[i];
        r->field[r->field_size++] = c >= 'A' && c <= 'Z' ? (char)(c + 'a' - 'A') : (char)c;
    }
    return 0;
}

static int on_header_value(http_parser *p, const char *bytes, size_t size)
{
    struct response *r = p->data;
    if (!r->capture_lite_authority) return 0;
    if (!r->in_value) {
        r->in_value = true;
        r->authority_value = authority_field(r);
        if (r->authority_value) {
            if (r->authority_seen || r->headers_complete) return -1;
            r->authority_seen = true;
            r->lite_authority = calloc(1, WENDY_LITE_AUTHORITY_HEADER_MAX + 1);
            if (!r->lite_authority) return -1;
        }
    }
    if (!r->authority_value) return 0;
    if (size > WENDY_LITE_AUTHORITY_HEADER_MAX - r->lite_authority_size) return -1;
    memcpy(r->lite_authority + r->lite_authority_size, bytes, size);
    r->lite_authority_size += size;
    return 0;
}

static int on_headers_complete(http_parser *p)
{
    struct response *r = p->data;
    if (r->capture_lite_authority && finish_header(r)) return -1;
    r->headers_complete = true;
    /* With Content-Length, allocate the body once instead of growing it. */
    if (!r->bytes && p->content_length > 0 && p->content_length <= PKI_MAX_RESPONSE) {
        r->bytes = malloc(p->content_length + 1);
        if (!r->bytes) {
            r->alloc_failed = true;
            return -1;
        }
        r->capacity = p->content_length + 1;
    }
    return 0;
}

static int on_body(http_parser *p, const char *bytes, size_t size)
{
    struct response *r = p->data;
    if (size > PKI_MAX_RESPONSE - r->size) return -1;
    /* Grow a body without Content-Length: boards without PSRAM may lack a free
     * 64 KiB block for a fixed buffer. */
    if (r->size + size + 1 > r->capacity) {
        size_t capacity = r->capacity ? r->capacity : 4096;
        while (capacity < r->size + size + 1) capacity *= 2;
        if (capacity > PKI_MAX_RESPONSE + 1) capacity = PKI_MAX_RESPONSE + 1;
        uint8_t *grown = realloc(r->bytes, capacity);
        if (!grown) {
            r->alloc_failed = true;
            return -1;
        }
        r->bytes = grown;
        r->capacity = capacity;
    }
    memcpy(r->bytes + r->size, bytes, size);
    r->size += size;
    r->bytes[r->size] = 0;
    return 0;
}

static int on_complete(http_parser *p)
{
    ((struct response *)p->data)->complete = true;
    return 0;
}
#endif
