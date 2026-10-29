#pragma once
#include <stddef.h>
/* Every armed slot, including a partially received SDU, reserves a full MTU
 * in the consumer ring. A replacement cannot borrow another armed slot's room. */
static inline unsigned wble_rx_rearm_budget(unsigned slots,unsigned owed,size_t room,size_t mtu)
{
    if(!mtu || owed>slots)return 0;
    unsigned armed=slots-owed;size_t capacity=room/mtu;
    if(capacity<=armed)return 0;
    size_t available=capacity-armed;return available<owed ? (unsigned)available:owed;
}
