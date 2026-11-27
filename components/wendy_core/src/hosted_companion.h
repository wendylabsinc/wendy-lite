#pragma once

#include "wendy_com_msg.pb.h"

WendyComResult hosted_companion_get(WendyComHostedCompanionInfo *out);
WendyComResult hosted_companion_begin(size_t size);
bool hosted_companion_pending(void);
WendyComResult hosted_companion_write(size_t offset, const uint8_t *data, size_t size);
WendyComResult hosted_companion_end(void);
void hosted_companion_abort(void);
