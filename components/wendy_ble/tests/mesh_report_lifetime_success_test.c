#include "mesh_report_lifetime.h"
#include <assert.h>

int main(void)
{
    struct wble_report_lifetime l={0};
    assert(wble_report_drained(&l) && !wble_report_acquire(&l));
    wble_report_open(&l);
    /* The host copied a live report/context, then an ordinary OFF arrives
     * before the callback returns. Closing must not falsely acknowledge it. */
    assert(wble_report_acquire(&l));
    wble_report_close(&l);
    assert(!wble_report_drained(&l) && !wble_report_acquire(&l));
    wble_report_release(&l);
    assert(wble_report_drained(&l));
    /* An independent next ON can now publish its own context. */
    wble_report_open(&l);
    assert(wble_report_acquire(&l) && wble_report_acquire(&l));
    wble_report_release(&l);
    assert(!wble_report_drained(&l));
    wble_report_close(&l);
    wble_report_release(&l);
    assert(wble_report_drained(&l));
    return 0;
}
