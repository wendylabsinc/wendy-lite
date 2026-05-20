//
//  u2_json.h
//  swi mit
//
//  Created by Gabriele Mondada on September 30, 2015.
//  Copyright (c) 2015 Switcher Inc. MIT License.
//

#ifndef _U2_JSON_H_
#define _U2_JSON_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>


/*** types ***/

enum u2_json_elem {
    U2_JSON_ELEM_UNDEFINED = 0,
    U2_JSON_ELEM_END,
    U2_JSON_ELEM_KEY,
    U2_JSON_ELEM_STR,
    U2_JSON_ELEM_INT,
    U2_JSON_ELEM_REAL,
    U2_JSON_ELEM_OBJ,
    U2_JSON_ELEM_ARRAY,
    U2_JSON_ELEM_OBJ_END,
    U2_JSON_ELEM_ARRAY_END,
    U2_JSON_ELEM_TRUE,
    U2_JSON_ELEM_FALSE,
    U2_JSON_ELEM_NULL,
};

typedef struct u2_json U2_JSON;

struct u2_json_span {
    const void *data;
    size_t size;
};

struct u2_json {
    int elem;
    int level;
    const char *buf;
    int size;
    const char *p;
    const char *e_beg;
    const char *e_end;
};


/*** prototypes ***/

const char *u2_json_element_name(enum u2_json_elem element);
void u2_json_init_with_buf(U2_JSON *json, const void *buf, size_t size);
void u2_json_rewind(U2_JSON *json);
enum u2_json_elem u2_json_next(U2_JSON *json);
void u2_json_skip(U2_JSON *json);
struct u2_json_span u2_json_span(U2_JSON *json);
char *u2_json_str(U2_JSON *json);
int64_t u2_json_i64(U2_JSON *json);
double u2_json_f64(U2_JSON *json);
bool u2_json_equal_str(U2_JSON *json, const char *str);
void u2_json_dump(U2_JSON *json);


/*** inline functions ***/

static inline enum u2_json_elem u2_json_element(U2_JSON *json)
{
    return json->elem;
}

static inline const char *u2_json_name(U2_JSON *json)
{
    return u2_json_element_name(json->elem);
}

static inline int u2_json_level(U2_JSON *json)
{
    return json->level;
}


#endif
