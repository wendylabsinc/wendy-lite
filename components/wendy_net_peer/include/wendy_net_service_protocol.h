/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "wendy_net_peer_protocol.h"
#define WNS_BODY_MAX 8192
#define WNS_WIRE_MAX (12*1024)
#define WNS_SIGNATURE_MAX WN_ORIGIN_SIGNATURE_MAX
#define WNS_TXT_MAX 32
struct wns_text {uint16_t offset,size;};
/* Operation-owned view. body/signature point into immutable caller-owned wire;
 * TXT offsets preserve the exact signed CBOR body; UTF-8 text is read on demand. */
struct wns_record {
    const char *body;size_t body_size;
    const uint8_t *signature;size_t signature_size;
    char mesh[64],principal[106],app[254],service[64],type[22],instance[64];
    uint64_t generation;
    int64_t issued,expires;
    uint8_t device[16],fingerprint[32],txt_count;
    uint16_t port;
    bool withdraw,gateway;
    struct wns_text txt[WNS_TXT_MAX];
};
/* Local single-guest publication metadata; ownership is checked by the host.
 * TXT spans borrow input, as with record_read. Owner/generation/time/signature
 * are assigned by the native runtime, never supplied by guest JSON. */
int wns_spec_read(const void *,size_t,struct wns_record *);
int wns_record_txt(const struct wns_record *,unsigned,char *,size_t);
bool wns_label_valid(const char *);
bool wns_app_id_valid(const char *);
/* Local WASM JSON ABI adapters; these formats never enter a carrier. */
int wns_spec_from_json(const void *,size_t,char **,size_t *);
int wns_record_json(const struct wns_record *,char *,size_t);

int wns_manifest_service_read(const struct wn_doc *,struct wns_record *);
int wns_manifest_services_validate(const struct wn_doc *,unsigned);
