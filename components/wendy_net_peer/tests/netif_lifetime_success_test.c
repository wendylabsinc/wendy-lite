#include "../src/netif_lifetime.h"
#include <assert.h>
#include <stdio.h>

int main(void)
{
    struct wnnl s = {0};
    assert(!wnnl_update(&s, false, false, 0));
    assert(wnnl_update(&s, true, true, 1000000));
    /* Losing the last physical carrier preserves the logical address. Repeated
     * actor ticks cannot extend that deadline; normal reconnection cancels it. */
    assert(wnnl_update(&s, false, true, 2000000));
    assert(s.until == 32000000);
    assert(wnnl_update(&s, false, true, 12000000));
    assert(s.until == 32000000);
    assert(wnnl_update(&s, true, true, 31000000));
    assert(!s.until);
    assert(wnnl_update(&s, false, true, 40000000));
    assert(wnnl_current(&s, true, 69999999));
    assert(!wnnl_current(&s, true, 70000000));
    assert(!wnnl_update(&s, false, true, 70000000));
    assert(!wnnl_update(&s, false, true, 80000000));
    /* Normal identity/time renewal restores service; ordinary expiration ends
     * the grace immediately instead of retaining an expired local address. */
    assert(wnnl_update(&s, true, true, 90000000));
    assert(wnnl_update(&s, false, true, 91000000));
    assert(!wnnl_update(&s, false, false, 92000000));
    assert(wnnl_update(&s, true, true, 93000000));
    printf("Logical address recovery/return/expiry pass; state=%zu bytes\n", sizeof s);
    return 0;
}
