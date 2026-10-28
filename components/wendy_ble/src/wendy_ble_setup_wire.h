#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "pb.h"
struct wble_setup_span { const uint8_t *data; size_t size; };
/* Exactly one length-delimited field; ambiguous/duplicate commands fail. */
bool wble_setup_unwrap(const uint8_t *, size_t, uint32_t *, struct wble_setup_span *);
bool wble_setup_wrap(uint32_t, const void *, size_t, uint8_t *, size_t, size_t *);
bool wble_setup_encode(uint32_t, const pb_msgdesc_t *, const void *, uint8_t *, size_t, size_t *);
