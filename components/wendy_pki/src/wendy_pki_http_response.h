#ifndef WENDY_PKI_HTTP_RESPONSE_H
#define WENDY_PKI_HTTP_RESPONSE_H

/* Shared bounded response parsing for the two authenticated HTTPS backends. */
#define LITE_AUTHORITY_HEADER "x-wendy-lite-operator-authority"
/* A body without Content-Length is kept in small segments and joined after
 * the TLS connection closes. Boards without PSRAM may lack a free block for
 * the TLS buffers and a growing copy of the body at the same time. */
#define RESPONSE_SEGMENT 4096
struct segment {
    struct segment *next;
    size_t size;
    uint8_t bytes[RESPONSE_SEGMENT];
};
struct response {
    uint8_t *bytes;
    size_t size, capacity;
    struct segment *head, *tail;
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
    /* With Content-Length, allocate the body once instead of segments. */
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
    if (r->bytes) {
        /* Content-Length sized the buffer, and the parser stops there. */
        if (size >= r->capacity - r->size) return -1;
        memcpy(r->bytes + r->size, bytes, size);
        r->size += size;
        r->bytes[r->size] = 0;
        return 0;
    }
    while (size) {
        if (!r->tail || r->tail->size == RESPONSE_SEGMENT) {
            struct segment *s = malloc(sizeof *s);
            if (!s) {
                r->alloc_failed = true;
                return -1;
            }
            s->next = NULL;
            s->size = 0;
            if (r->tail) r->tail->next = s;
            else r->head = s;
            r->tail = s;
        }
        size_t n = RESPONSE_SEGMENT - r->tail->size;
        if (n > size) n = size;
        memcpy(r->tail->bytes + r->tail->size, bytes, n);
        r->tail->size += n;
        r->size += n;
        bytes += n;
        size -= n;
    }
    return 0;
}

/* Join the segments into one NUL-terminated buffer, freeing each one as it
 * is copied. */
static int join_body(struct response *r)
{
    if (r->bytes || !r->head) return 0;
    r->bytes = malloc(r->size + 1);
    if (!r->bytes) {
        r->alloc_failed = true;
        return -1;
    }
    size_t at = 0;
    while (r->head) {
        struct segment *s = r->head;
        memcpy(r->bytes + at, s->bytes, s->size);
        at += s->size;
        r->head = s->next;
        free(s);
    }
    r->tail = NULL;
    r->bytes[at] = 0;
    return 0;
}

static void free_body(struct response *r)
{
    free(r->bytes);
    r->bytes = NULL;
    while (r->head) {
        struct segment *s = r->head;
        r->head = s->next;
        free(s);
    }
    r->tail = NULL;
}

static int on_complete(http_parser *p)
{
    ((struct response *)p->data)->complete = true;
    return 0;
}
#endif
