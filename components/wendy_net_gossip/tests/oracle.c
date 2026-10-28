/* Host-only line adapter for the real Go/C announcement protocol oracle. */
#include "test_sha256.h"
#include "wendy_net_gossip.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void hex(const uint8_t *p, size_t n) {
  if (!n)
    putchar('-');
  else
    for (size_t i = 0; i < n; i++)
      printf("%02x", p[i]);
}
static int unhex(const char *s, uint8_t *out, size_t capacity) {
  if (!strcmp(s, "-"))
    return 0;
  size_t n = strlen(s);
  if (n % 2 || n / 2 > capacity)
    return -1;
  for (size_t i = 0; i < n / 2; i++) {
    unsigned v;
    if (sscanf(s + 2 * i, "%2x", &v) != 1)
      return -1;
    out[i] = v;
  }
  return (int)(n / 2);
}
static int emit(void *ctx, const struct wg_message *m) {
  (void)ctx;
  printf("M %d %u ", m->op, m->id.type);
  hex(m->id.hash, 32);
  printf(" %llu %u %u ", (unsigned long long)m->request, m->offset, m->total);
  hex(m->data, m->size);
  putchar('\n');
  return 0;
}
struct context {
  struct wg_pool pool;
  uint64_t now;
};
static int complete(void *ctx, const struct wg_id *id, const void *bytes,
                    size_t size) {
  struct context *c = ctx;
  struct wg_id accepted;
  /* Oracle payloads stand in for independently verified signed artifacts. */
  int r = wg_offer(&c->pool, id->type, bytes, size, c->now + 60000, c->now,
                   &accepted);
  if (!r) {
    printf("C ");
    hex(bytes, size);
    putchar('\n');
  }
  return r;
}
int main(void) {
  struct context c = {0};
  struct wg_config config = {
      .identify = identify, .objects = 32, .pending = 16, .bytes = 256 * 1024};
  struct wg_session session = {0};
  if (wg_init(&c.pool, &config) || wg_open(&c.pool, &session, 1))
    return 2;
  char *line = NULL;
  size_t capacity = 0;
  uint8_t bytes[WG_OBJECT_MAX];
  while (getline(&line, &capacity, stdin) > 0) {
    char *save = NULL, *command = strtok_r(line, " \n", &save);
    int result = -1;
    if (!command)
      break;
    if (!strcmp(command, "offer")) {
      char *data = strtok_r(NULL, " \n", &save);
      int n = data ? unhex(data, bytes, sizeof bytes) : -1;
      struct wg_id id;
      if (n > 0) {
        result = wg_offer(&c.pool, 1, bytes, n, c.now + 60000, c.now, &id);
        if (!result) {
          printf("I ");
          hex(id.hash, 32);
          putchar('\n');
        }
      }
    } else if (!strcmp(command, "poll")) {
      char *when = strtok_r(NULL, " \n", &save);
      if (when) {
        c.now = strtoull(when, NULL, 10);
        result = wg_poll(&session, c.now, emit, &c);
      }
    } else if (!strcmp(command, "recv")) {
      char *args[7];
      unsigned count = 0;
      for (; count < 7; count++) {
        args[count] = strtok_r(NULL, " \n", &save);
        if (!args[count])
          break;
      }
      struct wg_message m = {0};
      if (count == 7) {
        m.op = (enum wg_op)atoi(args[0]);
        m.id.type = 1;
        m.request = strtoull(args[2], NULL, 10);
        m.offset = (uint32_t)strtoul(args[3], NULL, 10);
        m.total = (uint32_t)strtoul(args[4], NULL, 10);
        c.now = strtoull(args[5], NULL, 10);
        int n = unhex(args[6], bytes, sizeof bytes);
        if (unhex(args[1], m.id.hash, 32) == 32 && n >= 0) {
          m.data = bytes;
          m.size = n;
          result = wg_receive(&session, &m, c.now, emit, complete, &c);
        }
      }
    }
    printf("OK %d\n", result);
    fflush(stdout);
  }
  free(line);
  wg_close(&session);
  wg_deinit(&c.pool);
  return 0;
}
