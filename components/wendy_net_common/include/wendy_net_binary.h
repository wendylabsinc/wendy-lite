#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Definite, length-first deterministic CBOR. Callers emit map keys in order. */
struct wn_writer {uint8_t *data;size_t size,capacity,maximum;bool failed;};
void wn_map(struct wn_writer *,size_t);
void wn_array(struct wn_writer *,size_t);
void wn_text(struct wn_writer *,const char *);
void wn_bytes(struct wn_writer *,const void *,size_t);
void wn_uint(struct wn_writer *,uint64_t);
void wn_bool(struct wn_writer *,bool);
void wn_raw(struct wn_writer *,const void *,size_t);
int wn_finish(struct wn_writer *);

/* Defined schema keys; text values always use wn_text directly. */
const char *wn_key_name(const char *);
void wn_key(struct wn_writer *,const char *);
