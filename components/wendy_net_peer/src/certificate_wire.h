/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "certificate_fetch.h"
#include "wendy_net_peer_protocol.h"
struct wncf_chunk {uint8_t hash[32];size_t offset,total,size;};
int wncf_chain_read(const struct wn_doc *,unsigned,const char *tenant,struct wncf_chain *);
int wncf_chain_write(const struct wncf_chain *,char *,size_t);
int wncf_descriptor_write(const struct wncf_chain *,char *,size_t);
int wncf_request_read(const struct wn_doc *,unsigned,struct wncf_request *);
int wncf_request_write(const struct wncf_request *,char *,size_t);
int wncf_chunk_read(const struct wn_doc *,unsigned,struct wncf_chunk *,uint8_t data[WNCF_CHUNK]);
int wncf_chunk_read_view(const struct wn_doc *,unsigned,struct wncf_chunk *,const uint8_t **data);
int wncf_chunk_write(const struct wncf_chunk *,const void *,char *,size_t);

int wncf_missing_write(const struct wncf_request *,char *,size_t);
