#ifndef WENDY_PKI_HTTP_RESPONSE_H
#define WENDY_PKI_HTTP_RESPONSE_H

/* Shared bounded response parsing for the two authenticated HTTPS backends. */
#define LITE_AUTHORITY_HEADER "x-wendy-lite-operator-authority"
struct response_chunk {
    struct response_chunk *next;
    size_t used;
    uint8_t bytes[4096];
};
struct response {
    uint8_t *bytes;
    size_t size, capacity;
    struct response_chunk *head, *tail;
    bool complete, capture_lite_authority, headers_complete;
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
    return 0;
}

static int on_body(http_parser *p, const char *bytes, size_t size)
{
    struct response *r = p->data;
    if (size > PKI_MAX_RESPONSE - r->size) return -1;
    while (size) {
        if (!r->tail || r->tail->used == sizeof r->tail->bytes) {
            struct response_chunk *chunk = calloc(1, sizeof *chunk);
            if (!chunk) return -1;
            if (r->tail) r->tail->next = chunk;
            else r->head = chunk;
            r->tail = chunk;
            r->capacity += sizeof chunk->bytes;
        }
        size_t count = sizeof r->tail->bytes - r->tail->used;
        if (count > size) count = size;
        memcpy(r->tail->bytes + r->tail->used, bytes, count);
        r->tail->used += count;
        r->size += count;
        bytes += count;
        size -= count;
    }
    return 0;
}

static void response_free_chunks(struct response *r)
{
    while (r->head) {
        struct response_chunk *next = r->head->next;
        free(r->head);
        r->head = next;
    }
    r->tail = NULL;
}
/* Call only after closing TLS: no large contiguous response allocation or
 * realloc copy must compete with the live certificate/record buffers. */
static int response_flatten(struct response *r)
{
    uint8_t *bytes = malloc(r->size + 1);
    if (!bytes) return -1;
    size_t offset = 0;
    for (struct response_chunk *chunk = r->head; chunk; chunk = chunk->next) {
        memcpy(bytes + offset, chunk->bytes, chunk->used);
        offset += chunk->used;
    }
    bytes[offset] = 0;
    r->bytes = bytes;
    response_free_chunks(r);
    return 0;
}

static int on_complete(http_parser *p)
{
    ((struct response *)p->data)->complete = true;
    return 0;
}
#endif
