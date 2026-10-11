#pragma once
#include <stddef.h>
#include <stdint.h>

#define WENDY_RT_SERVERS 4
#define WENDY_RT_MAX_RESPONSE 4096
struct wendy_rt_server { const char *host; const char *port; uint8_t key[32]; };
extern const struct wendy_rt_server wendy_rt_servers[WENDY_RT_SERVERS];
/* Index of the pinned server named "host:port", or -1 when none matches. */
int wendy_rt_find_server(const char *address);
struct wendy_rt_interval { int64_t lower, upper; }; /* Unix microseconds */
/* Draft 08/11 wire format used by wendyos/internal/shared/roughtime. */
int wendy_rt_verify(const uint8_t *response, size_t size, const uint8_t nonce[32],
                    const uint8_t root_key[32], struct wendy_rt_interval *out);
void wendy_rt_request(uint8_t request[1024], const uint8_t nonce[32], const uint8_t key[32]);
int wendy_rt_consensus(const struct wendy_rt_interval intervals[WENDY_RT_SERVERS],
                      unsigned mask, struct wendy_rt_interval *out);
/* Network queries use fresh nonces, and do not require wall-clock time. */
int wendy_rt_query(struct wendy_rt_interval *out);
