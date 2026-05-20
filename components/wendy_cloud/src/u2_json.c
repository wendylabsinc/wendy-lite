//
//  u2_json.c
//  swi mit
//
//  Created by Gabriele Mondada on September 30, 2015.
//  Copyright (c) 2015 Switcher Inc. MIT License.
//

#include "u2_json.h"
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>


static inline int _decode_hex_digit(char digit)
{
    if (digit >= '0' && digit <= '9')
        return digit - '0';
    if (digit >= 'a' && digit <= 'f')
        return digit - 'a' + 10;
    if (digit >= 'A' && digit <= 'F')
        return digit - 'A' + 10;
    return -1;
}

static inline int64_t _str_to_i64(const char *str, char **end, int base)
{
    return (int64_t)strtoll(str, end, base);
}

static inline size_t _encode_utf8(char *buf, size_t max, int unicode_char)
{
    // TODO
    if (max > 0)
        *buf = '?';
    return 1;
}

static inline void _skip_blanks(U2_JSON *json)
{
    const char *end = json->buf + json->size;

    for (;;) {
        if (json->p >= end)
            break;

        uint8_t c = *json->p;
        if (c > 32)
            break;

        json->p++;
    }
}

static inline void _skip_colon(U2_JSON *json)
{
    const char *end = json->buf + json->size;

    if (json->p < end && *json->p == ',')
        json->p++;
}

static inline void _skip_str(U2_JSON *json)
{
    const char *end = json->buf + json->size;

    for (;;) {
        if (json->p >= end)
            return;

        if (*json->p == '\"')
            return;

        if (*json->p == '\\') {
            json->p++;

            if (json->p >= end)
                return;

            char c = *json->p;

            if (c == 'u') {
                for (int i = 0; i < 4; i++) {
                    json->p++;
                    if (json->p >= end)
                        break;
                    char c = *json->p;
                    if (_decode_hex_digit(c) == -1)
                        break;
                }
            }
        }

        json->p++;
    }
}

static inline bool _skip_num(U2_JSON *json)
{
    bool real = false;
    const char *end = json->buf + json->size;

    if (json->p < end && *json->p == '-')
        json->p++;

    while (json->p < end && *json->p >= '0' && *json->p <= '9')
        json->p++;

    if (json->p < end && *json->p == '.') {
        real = true;
        json->p++;
        while (json->p < end && *json->p >= '0' && *json->p <= '9')
            json->p++;
    }

    if (json->p < end && (*json->p == 'E' || *json->p == 'e')) {
        real = true;
        json->p++;
        if (json->p < end && (*json->p == '-' || *json->p == '+'))
            json->p++;
        while (json->p < end && *json->p >= '0' && *json->p <= '9')
            json->p++;
    }
    return real;
}

static inline bool _match_str(U2_JSON *json, const char *str)
{
    size_t len = strlen(str);
    const char *end = json->buf + json->size;

    if (json->p + len > end)
        return false;

    return strncmp(json->p, str, len) == 0;
}

const char *u2_json_element_name(enum u2_json_elem element)
{
    switch (element) {
        case U2_JSON_ELEM_UNDEFINED:
            return "UNDEFINED";
        case U2_JSON_ELEM_END:
            return "END";
        case U2_JSON_ELEM_KEY:
            return "KEY";
        case U2_JSON_ELEM_STR:
            return "STR";
        case U2_JSON_ELEM_INT:
            return "INT";
        case U2_JSON_ELEM_REAL:
            return "REAL";
        case U2_JSON_ELEM_OBJ:
            return "OBJ";
        case U2_JSON_ELEM_ARRAY:
            return "ARRAY";
        case U2_JSON_ELEM_OBJ_END:
            return "OBJ_END";
        case U2_JSON_ELEM_ARRAY_END:
            return "ARRAY_END";
        case U2_JSON_ELEM_TRUE:
            return "TRUE";
        case U2_JSON_ELEM_FALSE:
            return "FALSE";
        case U2_JSON_ELEM_NULL:
            return "NULL";
        default:
            return "?";
    }
}

void u2_json_init_with_buf(U2_JSON *json, const void *buf, size_t size)
{
    assert(size < 0x7fffffff);
    memset(json, 0, sizeof(*json));
    json->elem = U2_JSON_ELEM_UNDEFINED;
    json->buf = buf;
    json->size = (int)size;
    json->p = buf;
}

void u2_json_rewind(U2_JSON *json)
{
    json->p = json->buf;
}

/**
 * Return the next element type.
 */
enum u2_json_elem u2_json_next(U2_JSON *json)
{
    const char *end = json->buf + json->size;

    if (json->elem == U2_JSON_ELEM_OBJ)
        json->level++;
    if (json->elem == U2_JSON_ELEM_ARRAY)
        json->level++;

    _skip_blanks(json);

    if (json->p >= end) {
        json->e_beg = end;
        json->e_end = end;
        json->elem = U2_JSON_ELEM_END;
        return json->elem;
    }

    char c = *json->p;

    if (c == '\"') {
        json->p++;
        json->e_beg = json->p;
        _skip_str(json);
        json->e_end = json->p;
        if (json->p < end && *json->p == '\"')
            json->p++;

        _skip_blanks(json);

        if (json->p != end && *json->p == ':') {
            json->p++;
            json->elem = U2_JSON_ELEM_KEY;
        } else {
            _skip_colon(json);
            json->elem = U2_JSON_ELEM_STR;
        }
        return json->elem;
    }

    if (c == '-' || (c >= '0' && c <= '9')) {
        json->e_beg = json->p;
        bool real = _skip_num(json);
        json->e_end = json->p;
        _skip_blanks(json);
        _skip_colon(json);
        if (real)
            json->elem = U2_JSON_ELEM_REAL;
        else
            json->elem = U2_JSON_ELEM_INT;
        return json->elem;
    }

    if (c == '{') {
        json->e_beg = json->p;
        json->p++;
        json->e_end = json->p;
        json->elem = U2_JSON_ELEM_OBJ;
        return json->elem;
    }

    if (c == '}') {
        json->e_beg = json->p;
        json->p++;
        json->e_end = json->p;
        _skip_blanks(json);
        _skip_colon(json);
        json->level--;
        json->elem = U2_JSON_ELEM_OBJ_END;
        return json->elem;
    }

    if (c == '[') {
        json->e_beg = json->p;
        json->p++;
        json->e_end = json->p;
        json->elem = U2_JSON_ELEM_ARRAY;
        return json->elem;
    }

    if (c == ']') {
        json->e_beg = json->p;
        json->p++;
        json->e_end = json->p;
        _skip_blanks(json);
        _skip_colon(json);
        json->level--;
        json->elem = U2_JSON_ELEM_ARRAY_END;
        return json->elem;
    }

    if (_match_str(json, "true")) {
        json->e_beg = json->p;
        json->p += 4;
        json->e_end = json->p;
        _skip_blanks(json);
        _skip_colon(json);
        json->elem = U2_JSON_ELEM_TRUE;
        return json->elem;
    }

    if (_match_str(json, "false")) {
        json->e_beg = json->p;
        json->p += 5;
        json->e_end = json->p;
        _skip_blanks(json);
        _skip_colon(json);
        json->elem = U2_JSON_ELEM_FALSE;
        return json->elem;
    }

    if (_match_str(json, "null")) {
        json->e_beg = json->p;
        json->p += 4;
        json->e_end = json->p;
        _skip_blanks(json);
        _skip_colon(json);
        json->elem = U2_JSON_ELEM_NULL;
        return json->elem;
    }

    json->e_beg = json->p;
    json->p++;
    json->e_end = json->p;
    json->elem = U2_JSON_ELEM_UNDEFINED;
    return json->elem;
}

/**
 * Skip the current element and all its sub-elements.
 * If the current element is a JSON_ELEM_OBJ, this
 * function moves to the corresponding JSON_ELEM_OBJ_END.
 * In the same way, for JSON_ELEM_ARRAY, it moves to the
 * corresponding JSON_ELEM_ARRAY_END.
 * For elements that are neither objects nor arrays, this function
 * does nothing. In fact, the end of a JSON_ELEM_INT, for instance,
 * is the element itself.
 */
void u2_json_skip(U2_JSON *json)
{
    enum u2_json_elem elem = u2_json_element(json);
    enum u2_json_elem end_elem;

    switch (elem) {
        case U2_JSON_ELEM_ARRAY:
            end_elem = U2_JSON_ELEM_ARRAY_END;
            break;
        case U2_JSON_ELEM_OBJ:
            end_elem = U2_JSON_ELEM_OBJ_END;
            break;
        default:
            return;
    }

    int level = u2_json_level(json);
    for (;;) {
        elem = u2_json_next(json);
        if (elem == U2_JSON_ELEM_END)
            break;
        if (elem == end_elem && u2_json_level(json) == level)
            break;
    }
}

/**
 * Return the position and size of the current element in the json buffer.
 * The returned span covers the element and all its sub-elements.
 * Once returned, the json parser has been moved to the end of the element,
 * as when calling json_skip().
 */
struct u2_json_span u2_json_span(U2_JSON *json)
{
    const char *beg = json->e_beg;
    u2_json_skip(json);
    const char *end = json->e_end;
    if (beg == NULL || end == NULL) {
        beg = NULL;
        end = NULL;
    } else if (json->elem == U2_JSON_ELEM_STR || json->elem == U2_JSON_ELEM_KEY) {
        beg--;
        if (end < json->buf + json->size)
            end++;
    }
    struct u2_json_span span = {
        .data = beg,
        .size = end - beg,
    };
    return span;
}

/**
 * Caller must free the returned string.
 */
char *u2_json_str(U2_JSON *json)
{
    assert(json->elem == U2_JSON_ELEM_KEY || json->elem == U2_JSON_ELEM_STR);

    int len = 1;

    for (const char *p = json->e_beg; p < json->e_end; p++) {
        len++;
        if (*p == '\\')
            len += 4; // more than needed
    }

    char *str = malloc(len);
    const char *p = json->e_beg;
    char *q = str;

    for (;;) {
        if (p >= json->e_end)
            break;
        if (*p == '\\') {
            p++;
            if (p >= json->e_end)
                break;
            char c = *p;
            p++;
            switch (c) {
                case 'n':
                    *q = 10;
                    q++;
                    break;
                case 'r':
                    *q = 13;
                    q++;
                    break;
                case 't':
                    *q = '\t';
                    q++;
                    break;
                case 'b':
                    *q = '\b';
                    q++;
                    break;
                case 'f':
                    *q = '\f';
                    q++;
                    break;
                case 'u': {
                    int n = 0;
                    for (int i = 0; i < 4; i++) {
                        if (p >= json->e_end)
                            break;
                        int v = _decode_hex_digit(*p);
                        if (v == -1)
                            break;
                        n = (n << 4) | v;
                        p++;
                    }
                    if (n > 0) {
                        char *str_end = str + len - 1;
                        assert(str_end > q);
                        size_t available = str_end - q;
                        size_t len = _encode_utf8(q, available, n);
                        q += len;
                    }
                    break;
                }
                default:
                    *q = c;
                    q++;
                    break;
            }
        } else {
            *q = *p;
            p++;
            q++;
        }
    }

    *q = 0;

    assert(q - str + 1 <= len);

    return str;
}

int64_t u2_json_i64(U2_JSON *json)
{
    size_t len = json->e_end - json->e_beg;
    assert(json->elem == U2_JSON_ELEM_INT);
    assert(json->e_beg);
    assert(len < 1024);
    char *buf = malloc(len + 1);
    strlcpy(buf, json->e_beg, len + 1);
    int64_t ret = _str_to_i64(buf, NULL, 0);
    free(buf);
    return ret;
}

double u2_json_f64(U2_JSON *json)
{
    size_t len = json->e_end - json->e_beg;
    assert(json->elem == U2_JSON_ELEM_INT || json->elem == U2_JSON_ELEM_REAL);
    assert(json->e_beg);
    assert(len < 1024);
    char *buf = malloc(len + 1);
    strlcpy(buf, json->e_beg, len + 1);
    double ret = strtod(buf, NULL);
    free(buf);
    return ret;
}

bool u2_json_equal_str(U2_JSON *json, const char *str)
{
    if (json->elem != U2_JSON_ELEM_KEY && json->elem != U2_JSON_ELEM_STR)
        return false;
    char *val = u2_json_str(json);
    bool ret = strcmp(str, val) == 0;
    free(val);
    return ret;
}

void u2_json_dump(U2_JSON *json)
{
    for (;;) {
        enum u2_json_elem e = u2_json_next(json);

        switch (e) {
            case U2_JSON_ELEM_KEY:
            case U2_JSON_ELEM_STR: {
                char *str = u2_json_str(json);
                printf("level=%d e=%s val=%s\n", u2_json_level(json), u2_json_name(json), str);
                free(str);
                break;
            }
            case U2_JSON_ELEM_INT: {
                int64_t val = u2_json_i64(json);
                printf("level=%d e=%s val=%" PRId64 "\n", u2_json_level(json), u2_json_name(json), val);
                break;
            }
            case U2_JSON_ELEM_REAL: {
                double val = u2_json_f64(json);
                printf("level=%d e=%s val=%g\n", u2_json_level(json), u2_json_name(json), val);
                break;
            }
            default:
                printf("level=%d e=%s\n", u2_json_level(json), u2_json_name(json));
                break;
        }

        if (e == U2_JSON_ELEM_UNDEFINED || e == U2_JSON_ELEM_END) {
            size_t unread = json->size - (json->p - json->buf);
            if (unread)
                printf("%d bytes unread\n", (int)unread);
            return;
        }
    }
}

#ifdef U2_JSON_STATIC

/**
 * Return the theoretical length as snprintf().
 */
size_t json_str(JSON *json, char *str, size_t max)
{
    assert(json->elem == JSON_ELEM_KEY || json->elem == JSON_ELEM_STR);

    const char *p = json->e_beg;
    size_t out = 0;

    for (;;) {
        if (p >= json->e_end)
            break;
        if (*p == '\\') {
            p++;
            if (p >= json->e_end)
                break;
            char c = *p;
            p++;
            switch (c) {
                case 'n':
                    if (out < max)
                        str[out] = 10;
                    out++;
                    break;
                case 'r':
                    if (out < max)
                        str[out] = 13;
                    out++;
                    break;
                case 't':
                    if (out < max)
                        str[out] = '\t';
                    out++;
                    break;
                case 'b':
                    if (out < max)
                        str[out] = '\b';
                    out++;
                    break;
                case 'f':
                    if (out < max)
                        str[out] = '\f';
                    out++;
                    break;
                case 'u': {
                    int n = 0;
                    for (int i = 0; i < 4; i++) {
                        if (p >= json->e_end)
                            break;
                        int v = _decode_hex_digit(*p);
                        if (v == -1)
                            break;
                        n = (n << 4) | v;
                        p++;
                    }
                    if (n > 0) {
                        size_t available = out < max ? max - out : 0;
                        size_t len = _encode_utf8(str + out, available, n);
                        out += len;
                    }
                    break;
                }
                default:
                    if (out < max)
                        str[out] = c;
                    out++;
                    break;
            }
        } else {
            if (out < max)
                str[out] = *p;
            p++;
            out++;
        }
    }

    if (out < max)
        str[out] = 0;
    else if (max > 0)
        str[max - 1] = 0;

    return out;
}

int64_t json_i64(JSON *json)
{
    char buf[128];
    size_t len = json->e_end - json->e_beg;
    assert(json->elem == JSON_ELEM_INT);
    assert(json->e_beg);
    assert(len < sizeof(buf));
    strlcpy(buf, json->e_beg, len + 1);
    int64_t ret = _str_to_i64(buf, NULL, 0);
    return ret;
}

double json_f64(JSON *json)
{
    char buf[128];
    size_t len = json->e_end - json->e_beg;
    assert(json->elem == JSON_ELEM_INT || json->elem == JSON_ELEM_REAL);
    assert(json->e_beg);
    assert(len < sizeof(buf));
    strlcpy(buf, json->e_beg, len + 1);
    double ret = strtod(buf, NULL);
    return ret;
}

// TODO: we only support strings up to 511 chars
bool json_equal_str(JSON *json, const char *str)
{
    if (json->elem != JSON_ELEM_KEY && json->elem != JSON_ELEM_STR)
        return false;
    char buf[512];
    size_t len = json_str(json, buf, sizeof(buf));
    if (len >= sizeof(buf)) {
        // overflow, let's check if the input string is also so long
        assert(strlen(str) < sizeof(buf));
        // here we know that len != strlen(str), so the strings are different
        return false;
    }
    return strcmp(str, buf) == 0;
}

void json_dump(JSON *json)
{
    for (;;) {
        enum json_elem e = json_next_element(json);

        switch (e) {
            case JSON_ELEM_KEY:
            case JSON_ELEM_STR: {
                char buf[1024];
                size_t len = json_str(json, buf, sizeof(buf));
                printf("level=%d e=%s len=%d val=%s\n", json_level(json), json_name(json), (int)len, buf);
                break;
            }
            case JSON_ELEM_INT: {
                int64_t val = json_i64(json);
                printf("level=%d e=%s val=%" PRId64 "\n", json_level(json), json_name(json), val);
                break;
            }
            case JSON_ELEM_REAL: {
                double val = json_f64(json);
                printf("level=%d e=%s val=%g\n", json_level(json), json_name(json), val);
                break;
            }
            default:
                printf("level=%d e=%s\n", json_level(json), json_name(json));
                break;
        }

        if (e == JSON_ELEM_UNDEFINED || e == JSON_ELEM_END) {
            size_t unread = json->size - (json->p - json->buf);
            if (unread)
                printf("%d bytes unread\n", (int)unread);
            return;
        }
    }
}

#endif
