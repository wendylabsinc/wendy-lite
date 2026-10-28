#include "wendy_net_profile.h"
_Static_assert(WENDY_NET_NON_TRANSIT==EXPECTED_NON_TRANSIT,"forwarding policy matches profile");
_Static_assert(WENDY_NET_SMALL_RESOURCES==CONFIG_WENDY_NET_CONSTRAINED_PROFILE,"transit preserves small resource policy");
int main(void){return 0;}
