"""Exercise production setup entry/advancement under admission and I/O failures."""
from pathlib import Path
import os
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
source = (root / 'src/peer.c').read_text()

def function(name):
    start = source.index(name + '(')
    start = source.rfind('\n', 0, start) + 1
    begin = source.index('{', start)
    depth, end = 1, begin + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end] + '\n'

head = r'''
#include "wendy_net_actor.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
struct wn_candidate { int port; char address[64]; };
struct wendy_pki_stream { int unused; };
struct peer_state {
 struct wn_candidate candidate;
 char authenticated_peer[37];
 struct wna_channel *tls_channel;
 struct wna_session tls_state;
 size_t hello_in, hello_out, hello_size;
 bool hello_started, setup_connecting, setup_have_stream, setup_waiting, setup_server, failed;
 int setup_fd, setup_result;
 int64_t setup_at;
 atomic_bool setup_complete, setup_pending;
 struct wendy_pki_stream setup_stream;
};
static int64_t clock_us = 100;
static bool allocation_ok = true, candidate_ok = true, connect_ready, worker_accept;
static unsigned io_calls, connection_checks, submissions, closes;
static int reserve_candidate(struct peer_state *s, const struct wn_candidate *c) {
 (void)s; (void)c; return candidate_ok ? 0 : -1;
}
static void *wendy_net_calloc(size_t n, size_t size) { return allocation_ok ? calloc(n,size) : NULL; }
static int64_t esp_timer_get_time(void) { return clock_us; }
static int wnad_connect(const char *host, unsigned port, bool *connecting) {
 (void)host; (void)port; *connecting = true; return 7;
}
static bool wnad_prepare_socket(int fd) { return fd == 7; }
static int close(int fd) { assert(fd == 7); closes++; return 0; }
static int wnad_connected(int fd) { assert(fd == 7); connection_checks++; return connect_ready ? 1 : 0; }
static int wnad_channel_io(struct wna_channel *c, int fd, const struct wendy_pki_stream *stream) {
 (void)fd; (void)stream; io_calls++; return c->failed ? -1 : 0;
}
static int setup_hello(struct peer_state *s) { (void)s; return 1; }
static bool wnad_handshake_claim(void *p) { assert(p); return true; }
static void wnad_handshake_release(void *p) { assert(p); }
static void setup_work(void *p) { (void)p; }
static bool wendy_pki_work_submit(void (*work)(void *), void *p) {
 assert(work == setup_work && p); submissions++; return worker_accept;
}
'''
main = r'''
static void reset(void) {
 allocation_ok = candidate_ok = true;
 connect_ready = worker_accept = false;
 io_calls = connection_checks = submissions = 0;
 clock_us = 100;
}
int main(int argc, char **argv) {
 assert(argc == 2);
 struct peer_state link = {0};
 struct wn_candidate candidate = {.port = 43024, .address = "127.0.0.1"};
 reset();
 if (!strcmp(argv[1], "allocation")) {
  allocation_ok = false;
  begin_setup(&link, &candidate, 7);
  assert(link.tls_state.phase == WNA_FAILED && !link.tls_channel);
  assert(advance_setup(&link, clock_us) == -1 && !io_calls && !submissions);
 } else if (!strcmp(argv[1], "admission")) {
  candidate_ok = false;
  begin_setup(&link, &candidate, 7);
  assert(link.tls_state.phase == WNA_FAILED && !link.tls_channel);
  assert(advance_setup(&link, clock_us) == -1 && !io_calls && !submissions);
 } else if (!strcmp(argv[1], "deadline")) {
  begin_setup(&link, &candidate, -1);
  assert(link.setup_connecting);
  assert(advance_setup(&link, clock_us) == 1 && connection_checks == 1);
  assert(advance_setup(&link, (int64_t)link.tls_state.deadline) == -1);
  assert(connection_checks == 1 && !io_calls && !submissions);
 } else if (!strcmp(argv[1], "cancel")) {
  begin_setup(&link, &candidate, -1);
  link.tls_state.cancel = true;
  assert(advance_setup(&link, clock_us) == -1 && !connection_checks && !io_calls);
 } else if (!strcmp(argv[1], "loan")) {
  begin_setup(&link, &candidate, 7);
  link.tls_state.lent = true;
  link.tls_state.cancel = true;
  assert(advance_setup(&link, (int64_t)link.tls_state.deadline) == 1);
  assert(link.tls_state.lent && !io_calls);
  link.setup_complete = true;
  assert(advance_setup(&link, (int64_t)link.tls_state.deadline) == -1);
  assert(!link.tls_state.lent && !io_calls && !submissions);
 } else if (!strcmp(argv[1], "ready")) {
  begin_setup(&link, &candidate, -1);
  connect_ready = worker_accept = true;
  assert(advance_setup(&link, clock_us) == 1);
  assert(!link.setup_connecting && io_calls == 1 && submissions == 1);
  assert(link.tls_state.lent && link.setup_pending);
 } else assert(0);
 free(link.tls_channel);
 return 0;
}
'''
with tempfile.TemporaryDirectory() as tmp:
    p = Path(tmp)
    (p / 'test.c').write_text(head + function('advance_setup') + function('begin_setup') + main)
    subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-I' + str(root / 'include'),
                    str(p / 'test.c'), str(root / 'src/actor.c'), '-o', str(p / 'test')], check=True)
    failures = []
    for case in ('allocation', 'admission', 'deadline', 'cancel', 'loan', 'ready'):
        result = subprocess.run([str(p / 'test'), case])
        print(case + ': ' + ('PASS' if result.returncode == 0 else 'FAIL'), flush=True)
        if result.returncode:
            failures.append(case)
    if failures:
        raise SystemExit(1)
print('Production setup rejects failed admission/allocation and expired/cancelled connects; loans drain before disposal')
