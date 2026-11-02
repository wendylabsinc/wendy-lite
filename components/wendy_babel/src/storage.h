/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include "wendy_babel.h"
bool wb_reserve_links(struct wb_engine *, size_t count);
void wb_free_links(struct wb_engine *);
bool wb_reserve_candidates(struct wb_engine *, size_t count);
void wb_free_candidates(struct wb_engine *);
bool wb_reserve_sources(struct wb_engine *, size_t count);
void wb_free_sources(struct wb_engine *);
bool wb_reserve_local(struct wb_engine *, size_t count);
void wb_free_local(struct wb_engine *);
bool wb_reserve_drops(struct wb_engine *, size_t count);
void wb_free_drops(struct wb_engine *);
bool wb_reserve_requests(struct wb_engine *, size_t count);
void wb_free_requests(struct wb_engine *);
bool wb_reserve_routes(struct wb_engine *, size_t count);
void wb_free_routes(struct wb_engine *);
bool wb_reserve_before(struct wb_engine *, size_t count);
void wb_free_before(struct wb_engine *);
bool wb_reserve_scratch(struct wb_engine *, size_t count);
void wb_free_scratch(struct wb_engine *);
bool wb_reserve_messages(struct wb_engine *, size_t count);
void wb_free_messages(struct wb_engine *);
void wb_collect(struct wb_engine *);
