#include "wendy_app_usb.h"

#include <string.h>
#include "esp_log.h"
#include "soc/soc_caps.h"
#include "wasm_export.h"

static const char *TAG = "wendy_app_usb";

/*
 * App-facing USB CDC and HID functions.
 * Only functional on chips with USB OTG (ESP32-S2, ESP32-S3).
 * On other chips these register as stubs returning -1.
 */

#if SOC_USB_OTG_SUPPORTED

#include "tinyusb.h"
#include "tusb_cdc_acm.h"

/* usb_cdc_write(data_ptr, data_len) -> bytes written */
static int usb_cdc_write_wrapper(wasm_exec_env_t exec_env,
                                  const char *data, int len)
{
    if (!data || len <= 0) return -1;
    return tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0,
                                       (const uint8_t *)data, len);
}

/* usb_cdc_read(buf_ptr, buf_len) -> bytes read */
static int usb_cdc_read_wrapper(wasm_exec_env_t exec_env,
                                 char *buf, int len)
{
    if (!buf || len <= 0) return -1;
    size_t rx_size = 0;
    esp_err_t err = tinyusb_cdcacm_read(TINYUSB_CDC_ACM_0,
                                          (uint8_t *)buf, len, &rx_size);
    return (err == ESP_OK) ? (int)rx_size : -1;
}

/* usb_hid_send_report(report_id, data_ptr, data_len) -> 0 ok */
static int usb_hid_send_report_wrapper(wasm_exec_env_t exec_env,
                                        int report_id,
                                        const char *data, int len)
{
    /* HID requires TinyUSB HID class setup — simplified stub */
    ESP_LOGW(TAG, "usb_hid_send_report: not yet implemented");
    return -1;
}

static NativeSymbol s_app_usb_symbols[] = {
    { "usb_cdc_write",      (void *)usb_cdc_write_wrapper,      "(*~)i",  NULL },
    { "usb_cdc_read",       (void *)usb_cdc_read_wrapper,       "(*~)i",  NULL },
    { "usb_hid_send_report",(void *)usb_hid_send_report_wrapper,"(i*~)i", NULL },
};

#else /* No USB OTG */

static int usb_stub_write(wasm_exec_env_t exec_env, const char *d, int l) { return -1; }
static int usb_stub_read(wasm_exec_env_t exec_env, char *b, int l) { return -1; }
static int usb_stub_hid(wasm_exec_env_t exec_env, int id, const char *d, int l) { return -1; }

static NativeSymbol s_app_usb_symbols[] = {
    { "usb_cdc_write",      (void *)usb_stub_write, "(*~)i",  NULL },
    { "usb_cdc_read",       (void *)usb_stub_read,  "(*~)i",  NULL },
    { "usb_hid_send_report",(void *)usb_stub_hid,   "(i*~)i", NULL },
};

#endif /* SOC_USB_OTG_SUPPORTED */

int wendy_app_usb_export_init(void)
{
    if (!wasm_runtime_register_natives("wendy",
                                       s_app_usb_symbols,
                                       sizeof(s_app_usb_symbols) / sizeof(s_app_usb_symbols[0]))) {
        ESP_LOGE(TAG, "failed to register app USB natives");
        return -1;
    }
    ESP_LOGI(TAG, "app USB exports registered");
    return 0;
}
