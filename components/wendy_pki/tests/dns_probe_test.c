#include "wendy_pki_dns.h"
#include <assert.h>
int main(void)
{
    uint8_t q[272], r[1024] = {0}, ip[4];
    size_t n = pki_dns_query(q, "broker.example.com", 1234);
    assert(n && !pki_dns_query(r, "", 1) && !pki_dns_query(r, "a..b", 1));
    memcpy(r, q, n); r[2] = 0x81; r[3] = 0x80; r[7] = 1;
    const uint8_t a[] = {0xc0,12,0,1,0,1,0,0,0,30,0,4,203,0,113,1};
    memcpy(r + n, a, sizeof a);
    size_t size = n + sizeof a;
    assert(!pki_dns_answer(q, n, r, size, ip));
    assert(!memcmp(ip, a + 12, 4));
    for (size_t i = 0; i < size; i++) assert(pki_dns_answer(q, n, r, i, ip));
    r[0] ^= 1; assert(pki_dns_answer(q,n,r,size,ip)); r[0] ^= 1;
    r[2] |= 2; assert(pki_dns_answer(q,n,r,size,ip)); r[2] &= ~2;
    r[3] |= 3; assert(pki_dns_answer(q,n,r,size,ip)); r[3] &= ~3;
    r[14] ^= 1; assert(pki_dns_answer(q,n,r,size,ip)); r[14] ^= 1;
    r[n] = 0xff; r[n+1] = 0xff; assert(pki_dns_answer(q,n,r,size,ip));
    memcpy(r+n,a,sizeof a); r[n+11] = 255; assert(pki_dns_answer(q,n,r,size,ip));
    memcpy(r+n,a,sizeof a); r[n+3] = 5; assert(pki_dns_answer(q,n,r,size,ip));
    /* A CNAME preceding an A record, with bounded compressed owner names. */
    memcpy(r+n+sizeof a,a,sizeof a); r[7] = 2;
    assert(!pki_dns_answer(q,n,r,size+sizeof a,ip));
}
