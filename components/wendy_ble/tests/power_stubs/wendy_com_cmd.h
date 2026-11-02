#include "wendy_com_msg.pb.h"
struct wcom_bluetooth_power_delegate {
    WendyComResult (*get)(WendyComBluetoothPowerStatus *);
    WendyComResult (*set)(const WendyComBluetoothPowerConfig *, WendyComBluetoothPowerStatus *,
                          uint32_t *);
    void (*reply_complete)(uint32_t);
};
void wcom_cmd_set_bluetooth_power_delegate(const struct wcom_bluetooth_power_delegate *);
