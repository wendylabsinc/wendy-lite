/* Normal reusable storage, overlapping owners, zeroization and idle release. */
#include "wendy_pki_tls_input.h"
#include "wendy_net_memory.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
 assert(!wendy_pki_input_workspace_cached_bytes());
 wendy_pki_input_workspace_active(true);
 assert(wendy_pki_input_workspace_cached_bytes()==PKI_TLS_INPUT_RESERVE);
 unsigned char *first=pki_tls_input_take(PKI_TLS_INPUT_RESERVE);assert(first);
 assert(!wendy_pki_input_workspace_cached_bytes());
 memset(first,37,PKI_TLS_INPUT_RESERVE);
 /* Another normal context cannot grow the retained pool while it is loaned. */
 unsigned char *other=pki_tls_input_take(PKI_TLS_INPUT_RESERVE);assert(other && other!=first);
 pki_tls_input_return(other,PKI_TLS_INPUT_RESERVE);
 assert(!wendy_pki_input_workspace_cached_bytes());
 pki_tls_input_return(first,PKI_TLS_INPUT_RESERVE);
 assert(wendy_pki_input_workspace_cached_bytes()==PKI_TLS_INPUT_RESERVE);
 /* Public DER work borrows the existing allocation, then TLS sees the same
  * storage zeroized again. It cannot create another cached workspace. */
 size_t capacity=0;
 unsigned char *scratch=wendy_pki_input_workspace_borrow(&capacity);
 assert(scratch==first && capacity==PKI_TLS_INPUT_RESERVE);
 memset(scratch,0x5a,23741);
 assert(!wendy_pki_input_workspace_cached_bytes());
 size_t unavailable=99;
 assert(!wendy_pki_input_workspace_borrow(&unavailable) && !unavailable);
 wendy_pki_input_workspace_release(scratch);
 for(unsigned round=0;round<3;round++){
  unsigned char *again=pki_tls_input_take(PKI_TLS_INPUT_RESERVE);assert(again==first);
  for(size_t i=0;i<PKI_TLS_INPUT_RESERVE;i++)assert(!again[i]);
  memset(again,(int)round+1,PKI_TLS_INPUT_RESERVE);
  pki_tls_input_return(again,PKI_TLS_INPUT_RESERVE);
 }
 unsigned char *held=pki_tls_input_take(PKI_TLS_INPUT_RESERVE);assert(held==first);
 wendy_pki_input_workspace_active(false);assert(!wendy_pki_input_workspace_cached_bytes());
 pki_tls_input_return(held,PKI_TLS_INPUT_RESERVE);
 assert(!wendy_pki_input_workspace_cached_bytes());
 wendy_pki_input_workspace_active(true);assert(wendy_pki_input_workspace_cached_bytes()==PKI_TLS_INPUT_RESERVE);
 pki_tls_input_discard_cached();assert(!wendy_pki_input_workspace_cached_bytes());
 wendy_pki_input_workspace_active(false);
 capacity=99;
 assert(!wendy_pki_input_workspace_borrow(&capacity) && !capacity);
 wendy_pki_input_workspace_active(true);
 scratch=wendy_pki_input_workspace_borrow(&capacity);assert(scratch);
 memset(scratch,0x42,capacity);
 wendy_pki_input_workspace_active(false);
 wendy_pki_input_workspace_release(scratch);
 assert(!wendy_pki_input_workspace_cached_bytes());
 /* Baseline management borrows the idle mesh reserve without changing owner. */
 wendy_net_memory_t mesh=WENDY_NET_MEMORY_INITIALIZER;
 assert(wendy_net_memory_open(&mesh,65536,true));
 wendy_net_memory_scope_t previous=wendy_net_memory_scope_enter(&mesh,WENDY_NET_MEMORY_EXTERNAL);
 wendy_pki_input_workspace_active(true);
 unsigned char *mesh_buffer=pki_tls_input_take(PKI_TLS_INPUT_RESERVE);assert(mesh_buffer);
 pki_tls_input_return(mesh_buffer,PKI_TLS_INPUT_RESERVE);
 wendy_net_memory_scope_leave(previous);
 capacity=99;
 assert(!wendy_pki_input_workspace_borrow(&capacity) && !capacity);
 unsigned char *management=pki_tls_input_take(PKI_TLS_INPUT_RESERVE);assert(management==mesh_buffer);
 pki_tls_input_return(management,PKI_TLS_INPUT_RESERVE);
 assert(wendy_pki_input_workspace_cached_bytes()==PKI_TLS_INPUT_RESERVE);
 previous=wendy_net_memory_scope_enter(&mesh,WENDY_NET_MEMORY_EXTERNAL);
 scratch=wendy_pki_input_workspace_borrow(&capacity);assert(scratch==mesh_buffer);
 wendy_pki_input_workspace_active(false);
 wendy_pki_input_workspace_release(scratch);
 wendy_net_memory_scope_leave(previous);
 wendy_net_memory_close(&mesh);
 puts("one zeroized TLS workspace reused, ownership-scoped and released at shutdown");
}
