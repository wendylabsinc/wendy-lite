#include "mesh_gap_effect.h"
#include "mesh_report_lifetime.h"
#include <assert.h>

int main(void)
{
    struct wble_gap_effect e;wble_gap_effect_init(&e);
    struct wble_gap_command got;
    assert(!wble_gap_take(&e,&got));
    assert(wble_gap_submit(&e,WBLE_GAP_INIT,NULL));
    assert(wble_gap_take(&e,&got) && got.action==WBLE_GAP_INIT);
    /* A normal command is lent to the host, whose HCI completion is delayed.
     * Producers still submit one immutable dial and coalesce scan requests. */
    struct wble_gap_dial dial={.address={1,2,3,4,5,6},.type=1,.psm=129,.epoch=7};
    assert(wble_gap_submit(&e,WBLE_GAP_DIAL,&dial));
    dial.address[0]=9;
    assert(!wble_gap_submit(&e,WBLE_GAP_DIAL,&dial));
    for(unsigned i=0;i<50;i++)assert(wble_gap_submit(&e,WBLE_GAP_SCAN,NULL));
    wble_gap_complete(&e,WBLE_GAP_INIT,0);
    assert(wble_gap_take(&e,&got) && got.action==WBLE_GAP_DIAL);
    assert(got.dial.address[0]==1 && got.dial.epoch==7 && got.dial.psm==129);
    wble_gap_complete(&e,WBLE_GAP_DIAL,6);
    assert(wble_gap_take(&e,&got) && got.action==WBLE_GAP_SCAN);
    wble_gap_complete(&e,WBLE_GAP_SCAN,0);
    unsigned action;assert(wble_gap_error(&e,&action)==6 && action==WBLE_GAP_DIAL);
    assert(!wble_gap_error(&e,&action) && !wble_gap_take(&e,&got));
    /* Retry a failed normal dial, then OFF supersedes queued scan/dial work.
     * Already lent work and a borrowed report must still acknowledge. */
    assert(wble_gap_submit(&e,WBLE_GAP_DIAL,&dial));
    assert(wble_gap_take(&e,&got));
    struct wble_report_lifetime reports={0};wble_report_open(&reports);
    assert(wble_report_acquire(&reports));
    assert(wble_gap_submit(&e,WBLE_GAP_SCAN,NULL));
    assert(wble_gap_submit(&e,WBLE_GAP_STOP,NULL));
    assert(!wble_gap_submit(&e,WBLE_GAP_DIAL,&dial));
    wble_gap_complete(&e,WBLE_GAP_DIAL,0);
    assert(wble_gap_take(&e,&got) && got.action==WBLE_GAP_STOP);
    assert(!wble_gap_take(&e,&got));
    wble_report_close(&reports);assert(!wble_report_drained(&reports));
    wble_report_release(&reports);assert(wble_report_drained(&reports));
    /* A busy metadata publisher never makes either side spin or wait. */
    assert(!atomic_flag_test_and_set(&e.gate));
    assert(!wble_gap_submit(&e,WBLE_GAP_SCAN,NULL) && !wble_gap_take(&e,&got));
    atomic_flag_clear(&e.gate);
    assert(wble_gap_submit(&e,WBLE_GAP_SCAN,NULL));
    assert(wble_gap_take(&e,&got) && got.action==WBLE_GAP_SCAN);
    wble_gap_complete(&e,WBLE_GAP_SCAN,-1);
    assert(wble_gap_error(&e,&action)==-1 && action==WBLE_GAP_SCAN);
    /* A new mesh-created ACL completes after OFF started. A successful
     * terminate command does not itself acknowledge its later disconnect. */
    struct wble_gap_retirement acls[4]={0};
    struct wble_gap_retirement *acl=wble_gap_retiring_add(acls,4,12);
    assert(acl && wble_gap_retiring_busy(acls,4));
    acl->sent=true;
    assert(wble_gap_retiring_busy(acls,4));
    assert(wble_gap_retiring_add(acls,4,12)==acl);
    wble_gap_retiring_done(acls,4,12);
    assert(!wble_gap_retiring_busy(acls,4));
    /* An ordinary scan error (including another baseline scanner owning the
     * radio) schedules one deadline. Frequent actor I/O must not generate a
     * command storm. The next exact deadline retries without steady delay. */
    struct wble_gap_retry retry={0};int64_t first=2000000;
    assert(wble_gap_retry_due(&retry,first));
    wble_gap_retry_failed(&retry,first);
    unsigned attempts=1;
    for(int64_t now=first+1;now<first+WBLE_GAP_RETRY_US;now+=100)
        if(wble_gap_retry_due(&retry,now))attempts++;
    assert(attempts==1);
    assert(wble_gap_retry_deadline(&retry,first)==first+WBLE_GAP_RETRY_US);
    assert(wble_gap_retry_due(&retry,first+WBLE_GAP_RETRY_US));
    attempts++;wble_gap_retry_clear(&retry);
    assert(attempts==2 && wble_gap_retry_due(&retry,first+WBLE_GAP_RETRY_US));
    assert(wble_gap_retry_deadline(&retry,first+WBLE_GAP_RETRY_US)==INT64_MAX);
    /* Failed-init cleanup retains pacing; actual OFF cancels it so the next
     * ON gets an immediate first attempt rather than inheriting a cooldown. */
    wble_gap_retry_failed(&retry,first);
    assert(!wble_gap_retry_due(&retry,first+1));
    assert(wble_gap_submit(&e,WBLE_GAP_STOP,NULL));
    wble_gap_retry_clear(&retry);
    assert(wble_gap_take(&e,&got) && got.action==WBLE_GAP_STOP);
    assert(wble_gap_retry_due(&retry,first+1));
    return 0;
}
