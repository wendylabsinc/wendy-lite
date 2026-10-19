#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "bsp/esp_mosaico.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_rom_sys.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lvgl.h"
#include "diagnostics.h"
#include "usb_management.h"
#include "wendy_cloud.h"
#include "wendy_conf.h"
#include "wendy_core.h"
#include "wendy_mesh_status.h"
#include "wendy_pki.h"
#include "wendy_wifi.h"

static const char *TAG = "mosaico_dashboard";

static void restart_board(void)
{
    /* The preview S31 CPU-only restart leaves this board stalled until its
     * watchdog resets the system. Reset the peripherals as well, as the ROM
     * downloader does, so USB and PSRAM start from a clean hardware state. */
    esp_rom_software_reset_system();
}

#define COLOR_BACKGROUND 0x0B1420
#define COLOR_PANEL      0x152333
#define COLOR_LINE       0x294054
#define COLOR_TEXT       0xF0F5FA
#define COLOR_MUTED      0x9BAFC2
#define COLOR_ACCENT     0x60E6C5
#define COLOR_WARNING    0xFFD080
#define COLOR_ERROR      0xFF9B95
#define SAMPLE_PERIOD_MS 40
#define STATUS_PERIOD_US INT64_C(1000000)
#define RETRY_PERIOD_US  INT64_C(1000000)
#define PLOT_SIZE        144
#define BUBBLE_SIZE      20
#define BUBBLE_RANGE     54

typedef struct {
    float accel[3];
    float gyro[3];
} motion_sample_t;

/* The BSP's LVGL lock protects this state, including touch callbacks. */
static struct {
    lv_obj_t *pages[2];
    lv_obj_t *tabs[2];
    lv_obj_t *mesh_state;
    lv_obj_t *mesh_local;
    lv_obj_t *mesh_peer;
    lv_obj_t *mesh_link;
    lv_obj_t *mesh_carrier;
    lv_obj_t *mesh_count;
    lv_obj_t *mesh_members;
    lv_obj_t *live;
    lv_obj_t *motion_state;
    lv_obj_t *bubble;
    lv_obj_t *accel[3];
    lv_obj_t *gyro[3];
    lv_obj_t *hint;
    lv_obj_t *pause_text;
    lv_obj_t *zero_button;
    lv_obj_t *enrollment;
    lv_obj_t *wifi;
    lv_obj_t *cloud;
    lv_obj_t *footer;
    motion_sample_t sample;
    float zero_x;
    float zero_y;
    bool paused;
    bool sample_valid;
} ui;

static lv_obj_t *label(lv_obj_t *parent, const char *text, int x, int y,
                       int width, const lv_font_t *font, uint32_t color)
{
    lv_obj_t *obj = lv_label_create(parent);
    lv_label_set_text(obj, text);
    lv_label_set_long_mode(obj, LV_LABEL_LONG_CLIP);
    lv_obj_set_pos(obj, x, y);
    lv_obj_set_width(obj, width);
    lv_obj_set_style_text_font(obj, font, 0);
    lv_obj_set_style_text_color(obj, lv_color_hex(color), 0);
    return obj;
}

static lv_obj_t *box(lv_obj_t *parent, int x, int y, int width, int height,
                     uint32_t color, int radius)
{
    lv_obj_t *obj = lv_obj_create(parent);
    lv_obj_remove_style_all(obj);
    lv_obj_remove_flag(obj, LV_OBJ_FLAG_SCROLLABLE | LV_OBJ_FLAG_CLICKABLE);
    lv_obj_set_pos(obj, x, y);
    lv_obj_set_size(obj, width, height);
    lv_obj_set_style_bg_color(obj, lv_color_hex(color), 0);
    lv_obj_set_style_bg_opa(obj, LV_OPA_COVER, 0);
    lv_obj_set_style_radius(obj, radius, 0);
    return obj;
}

static void position_bubble(void)
{
    /* This is an acceleration-based tilt indicator, not an orientation filter.
     * Limit displacement radially so large movements stay inside the ring. */
    float x = ui.sample.accel[0] - ui.zero_x;
    float y = ui.sample.accel[1] - ui.zero_y;
    float length = sqrtf(x * x + y * y);
    if (length > 1.0f) {
        x /= length;
        y /= length;
    }
    const int center = (PLOT_SIZE - BUBBLE_SIZE) / 2;
    lv_obj_set_pos(ui.bubble, center + (int)lroundf(x * BUBBLE_RANGE),
                  center - (int)lroundf(y * BUBBLE_RANGE));
}

static void update_motion_state(void)
{
    lv_label_set_text(ui.live, ui.paused ? "PAUSED" : "LIVE");
    lv_obj_set_style_text_color(ui.live,
        lv_color_hex(ui.paused ? COLOR_WARNING : COLOR_ACCENT), 0);
    lv_label_set_text(ui.pause_text, ui.paused ? "Resume motion" : "Pause motion");
    lv_label_set_text(ui.motion_state, !ui.sample_valid ? "IMU unavailable" :
                      ui.paused ? "Motion paused" : "25 Hz / live");
    lv_obj_set_style_text_color(ui.motion_state,
        lv_color_hex(!ui.sample_valid ? COLOR_ERROR : COLOR_MUTED), 0);
}

static void pause_clicked(lv_event_t *event)
{
    (void)event;
    ui.paused = !ui.paused;
    update_motion_state();
}

static void zero_clicked(lv_event_t *event)
{
    (void)event;
    if (!ui.sample_valid) {
        return;
    }
    ui.zero_x = ui.sample.accel[0];
    ui.zero_y = ui.sample.accel[1];
    position_bubble();
    lv_label_set_text(ui.hint, "Tilt reference saved");
}

static lv_obj_t *button(lv_obj_t *parent, const char *text, int x,
                        bool primary, lv_event_cb_t callback, lv_obj_t **caption)
{
    lv_obj_t *obj = lv_button_create(parent);
    lv_obj_remove_style_all(obj);
    lv_obj_set_pos(obj, x, 310);
    lv_obj_set_size(obj, 216, 44);
    lv_obj_set_style_radius(obj, 12, 0);
    lv_obj_set_style_bg_opa(obj, LV_OPA_COVER, 0);
    lv_obj_set_style_bg_color(obj,
        lv_color_hex(primary ? COLOR_ACCENT : COLOR_LINE), 0);
    lv_obj_set_style_bg_opa(obj, LV_OPA_70, LV_STATE_PRESSED);
    lv_obj_set_style_opa(obj, LV_OPA_40, LV_STATE_DISABLED);
    lv_obj_add_event_cb(obj, callback, LV_EVENT_CLICKED, NULL);
    lv_obj_t *text_obj = label(obj, text, 0, 0, 216, &lv_font_montserrat_16,
                               primary ? COLOR_BACKGROUND : COLOR_TEXT);
    lv_obj_set_style_text_align(text_obj, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(text_obj);
    if (caption) {
        *caption = text_obj;
    }
    return obj;
}

static void select_page(unsigned index)
{
    for (unsigned i = 0; i < 2; ++i) {
        if (i == index) lv_obj_remove_flag(ui.pages[i], LV_OBJ_FLAG_HIDDEN);
        else lv_obj_add_flag(ui.pages[i], LV_OBJ_FLAG_HIDDEN);
        lv_obj_set_style_bg_color(ui.tabs[i],
            lv_color_hex(i == index ? COLOR_ACCENT : COLOR_LINE), 0);
        lv_obj_set_style_text_color(lv_obj_get_child(ui.tabs[i], 0),
            lv_color_hex(i == index ? COLOR_BACKGROUND : COLOR_TEXT), 0);
    }
}

static void page_clicked(lv_event_t *event)
{
    select_page((unsigned)(uintptr_t)lv_event_get_user_data(event));
}

static void create_mesh_view(lv_obj_t *parent)
{
    lv_obj_t *panel = box(parent, 16, 0, 448, 276, COLOR_PANEL, 18);
    ui.mesh_state = label(panel, "Reading mesh state", 16, 12, 416,
                          &lv_font_montserrat_16, COLOR_ACCENT);
    lv_obj_t *local = box(panel, 16, 48, 148, 68, COLOR_BACKGROUND, 12);
    label(local, "This Mosaico", 12, 10, 124, &lv_font_montserrat_16, COLOR_TEXT);
    ui.mesh_local = label(local, "--", 12, 38, 124, &lv_font_montserrat_16, COLOR_MUTED);
    lv_obj_t *peer = box(panel, 284, 48, 148, 68, COLOR_BACKGROUND, 12);
    label(peer, "Direct peer", 12, 10, 124, &lv_font_montserrat_16, COLOR_TEXT);
    ui.mesh_peer = label(peer, "Not set", 12, 38, 124, &lv_font_montserrat_16, COLOR_MUTED);
    ui.mesh_link = box(panel, 164, 86, 120, 3, COLOR_ACCENT, 0);
    lv_obj_add_flag(ui.mesh_link, LV_OBJ_FLAG_HIDDEN);
    ui.mesh_carrier = label(panel, "", 164, 60, 120, &lv_font_montserrat_16, COLOR_MUTED);
    lv_obj_set_style_text_align(ui.mesh_carrier, LV_TEXT_ALIGN_CENTER, 0);
    ui.mesh_count = label(panel, "Live signed members", 16, 130, 416,
                          &lv_font_montserrat_16, COLOR_TEXT);
    lv_obj_t *roster = box(panel, 16, 158, 416, 78, COLOR_PANEL, 0);
    lv_obj_add_flag(roster, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scroll_dir(roster, LV_DIR_VER);
    ui.mesh_members = label(roster, "No verified announcements yet.", 0, 0, 402,
                            &lv_font_montserrat_16, COLOR_MUTED);
    lv_label_set_long_mode(ui.mesh_members, LV_LABEL_LONG_WRAP);
    label(panel, "Only the observed direct link is drawn.", 16, 248, 416,
          &lv_font_montserrat_16, COLOR_MUTED);
}

static void render_mesh(const struct wendy_mesh_snapshot *snapshot)
{
    const char *status = "Mesh unavailable";
    switch (snapshot->phase) {
    case WENDY_MESH_DISABLED: status = "Mesh disabled in this firmware"; break;
    case WENDY_MESH_PEER_REQUIRED: status = "Configure a mesh peer"; break;
    case WENDY_MESH_WAITING_ENROLLMENT: status = "Waiting for enrollment"; break;
    case WENDY_MESH_WAITING_WIFI: status = "Waiting for Wi-Fi"; break;
    case WENDY_MESH_DISCOVERING: status = "Discovering mesh routers"; break;
    case WENDY_MESH_CONNECTING: status = "Connecting / authenticating"; break;
    case WENDY_MESH_QUARANTINE: status = "Connected / waiting for IP"; break;
    case WENDY_MESH_ONLINE: status = "Mesh online"; break;
    case WENDY_MESH_RETRYING: status = "Peer offline / retrying"; break;
    default: break;
    }
    if (snapshot->peer_connected && snapshot->quarantine_seconds) {
        lv_label_set_text_fmt(ui.mesh_state, "Connected / IP ready in %lu s",
            (unsigned long)snapshot->quarantine_seconds);
    } else lv_label_set_text(ui.mesh_state, status);
    lv_obj_set_style_text_color(ui.mesh_state,
        lv_color_hex(snapshot->ip_active ? COLOR_ACCENT : COLOR_WARNING), 0);
    lv_label_set_text_fmt(ui.mesh_local, "%.8s", snapshot->device[0] ?
        snapshot->device : wendy_conf_get_device_id());
    lv_label_set_text_fmt(ui.mesh_peer, "%.8s", snapshot->peer[0] ? snapshot->peer : "Not set");
    lv_label_set_text(ui.mesh_carrier, snapshot->carrier);
    if (snapshot->peer_connected) lv_obj_remove_flag(ui.mesh_link, LV_OBJ_FLAG_HIDDEN);
    else lv_obj_add_flag(ui.mesh_link, LV_OBJ_FLAG_HIDDEN);
    lv_obj_set_style_bg_color(ui.mesh_link,
        lv_color_hex(snapshot->ip_active ? COLOR_ACCENT : COLOR_WARNING), 0);
    lv_label_set_text_fmt(ui.mesh_count, "%u live signed members / scroll",
                          snapshot->member_count);
    /* Static storage keeps the bounded roster off the FreeRTOS task stack. */
    static char members[WENDY_MESH_ORIGINS_MAX * 80];
    size_t used = 0;
    for (unsigned i = 0; i < snapshot->member_count && i < WENDY_MESH_ORIGINS_MAX; ++i) {
        int n = snprintf(members + used, sizeof members - used, "%s\nLease %lu s\n",
            snapshot->members[i].device, (unsigned long)snapshot->members[i].lease_seconds);
        if (n < 0 || (size_t)n >= sizeof members - used) break;
        used += (size_t)n;
    }
    lv_label_set_text(ui.mesh_members, used ? members : "No live signed members.");
}

static void create_dashboard(lv_display_t *display)
{
    lv_obj_t *screen = lv_display_get_screen_active(display);
    lv_obj_remove_style_all(screen);
    lv_obj_remove_flag(screen, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_style_bg_color(screen, lv_color_hex(COLOR_BACKGROUND), 0);
    lv_obj_set_style_bg_opa(screen, LV_OPA_COVER, 0);

    label(screen, "Mosaico", 20, 12, 160, &lv_font_montserrat_28, COLOR_TEXT);
    ui.live = label(screen, "LIVE", 170, 22, 74, &lv_font_montserrat_16, COLOR_ACCENT);
    lv_obj_set_style_text_align(ui.live, LV_TEXT_ALIGN_RIGHT, 0);
    lv_obj_t *name = label(screen, wendy_conf_get_resolved_device_display_name(),
                           20, 49, 440, &lv_font_montserrat_16, COLOR_MUTED);
    lv_label_set_long_mode(name, LV_LABEL_LONG_DOT);

    static const char *pages[] = {"Mesh", "Motion"};
    for (unsigned i = 0; i < 2; ++i) {
        ui.pages[i] = box(screen, 0, 78, 480, 276, COLOR_BACKGROUND, 0);
        ui.tabs[i] = button(screen, pages[i], 252 + i * 108, false, page_clicked, NULL);
        lv_obj_set_pos(ui.tabs[i], 252 + i * 108, 12);
        lv_obj_set_size(ui.tabs[i], 100, 38);
        lv_obj_t *caption = lv_obj_get_child(ui.tabs[i], 0);
        lv_obj_set_width(caption, 100);
        lv_obj_center(caption);
        lv_obj_remove_event_cb(ui.tabs[i], page_clicked);
        lv_obj_add_event_cb(ui.tabs[i], page_clicked, LV_EVENT_CLICKED, (void *)(uintptr_t)i);
    }
    create_mesh_view(ui.pages[0]);
    lv_obj_t *motion = box(ui.pages[1], 16, 0, 448, 222, COLOR_PANEL, 18);
    label(motion, "Motion", 16, 12, 180, &lv_font_montserrat_20, COLOR_TEXT);
    ui.motion_state = label(motion, "Waiting for IMU", 224, 16, 208,
                             &lv_font_montserrat_16, COLOR_MUTED);
    lv_obj_set_style_text_align(ui.motion_state, LV_TEXT_ALIGN_RIGHT, 0);

    lv_obj_t *plot = box(motion, 16, 52, PLOT_SIZE, PLOT_SIZE,
                         COLOR_BACKGROUND, LV_RADIUS_CIRCLE);
    lv_obj_set_style_border_color(plot, lv_color_hex(COLOR_LINE), 0);
    lv_obj_set_style_border_width(plot, 1, 0);
    box(plot, 0, PLOT_SIZE / 2, PLOT_SIZE, 1, COLOR_LINE, 0);
    box(plot, PLOT_SIZE / 2, 0, 1, PLOT_SIZE, COLOR_LINE, 0);
    lv_obj_t *ring = box(plot, 43, 43, 58, 58, COLOR_BACKGROUND, LV_RADIUS_CIRCLE);
    lv_obj_set_style_bg_opa(ring, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(ring, 1, 0);
    lv_obj_set_style_border_color(ring, lv_color_hex(COLOR_LINE), 0);
    ui.bubble = box(plot, 62, 62, BUBBLE_SIZE, BUBBLE_SIZE, COLOR_ACCENT, LV_RADIUS_CIRCLE);
    lv_obj_add_flag(ui.bubble, LV_OBJ_FLAG_HIDDEN);

    label(motion, "ACCEL / g", 202, 52, 112, &lv_font_montserrat_16, COLOR_MUTED);
    label(motion, "GYRO / dps", 320, 52, 116, &lv_font_montserrat_16, COLOR_MUTED);
    static const char *axes[] = {"X", "Y", "Z"};
    for (int axis = 0; axis < 3; ++axis) {
        int y = 82 + 28 * axis;
        label(motion, axes[axis], 176, y, 24, &lv_font_montserrat_16, COLOR_MUTED);
        ui.accel[axis] = label(motion, "--", 202, y, 110, &lv_font_montserrat_20, COLOR_TEXT);
        ui.gyro[axis] = label(motion, "--", 320, y, 116, &lv_font_montserrat_20, COLOR_TEXT);
    }
    ui.hint = label(motion, "Hold still, tap Zero tilt", 176, 179, 256,
                     &lv_font_montserrat_16, COLOR_MUTED);

    lv_obj_t *pause = button(ui.pages[1], "Pause motion", 16, true, pause_clicked, &ui.pause_text);
    lv_obj_set_y(pause, 232);
    ui.zero_button = button(ui.pages[1], "Zero tilt", 248, false, zero_clicked, NULL);
    lv_obj_set_y(ui.zero_button, 232);
    lv_obj_add_state(ui.zero_button, LV_STATE_DISABLED);

    lv_obj_t *status = box(screen, 16, 366, 448, 78, COLOR_PANEL, 18);
    label(status, "ENROLLMENT", 14, 12, 152, &lv_font_montserrat_16, COLOR_MUTED);
    label(status, "WI-FI", 170, 12, 116, &lv_font_montserrat_16, COLOR_MUTED);
    label(status, "CLOUD", 304, 12, 130, &lv_font_montserrat_16, COLOR_MUTED);
    ui.enrollment = label(status, "Checking", 14, 40, 152, &lv_font_montserrat_16, COLOR_TEXT);
    ui.wifi = label(status, "Checking", 170, 40, 116, &lv_font_montserrat_16, COLOR_TEXT);
    ui.cloud = label(status, "Checking", 304, 40, 130, &lv_font_montserrat_16, COLOR_TEXT);
    ui.footer = label(screen, "Wendy Lite", 20, 454, 440, &lv_font_montserrat_16, COLOR_MUTED);
    select_page(0);
}

static void render_motion(const motion_sample_t *sample, bool valid)
{
    if (!valid) {
        ui.sample_valid = false;
        lv_obj_add_flag(ui.bubble, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_state(ui.zero_button, LV_STATE_DISABLED);
        for (int axis = 0; axis < 3; ++axis) {
            lv_label_set_text(ui.accel[axis], "--");
            lv_label_set_text(ui.gyro[axis], "--");
        }
    } else if (!ui.paused) {
        ui.sample = *sample;
        ui.sample_valid = true;
        char value[24];
        for (int axis = 0; axis < 3; ++axis) {
            /* Use libc formatting; LVGL's optional float formatter is not required. */
            snprintf(value, sizeof value, "%+.2f", (double)sample->accel[axis]);
            lv_label_set_text(ui.accel[axis], value);
            snprintf(value, sizeof value, "%+.1f", (double)sample->gyro[axis]);
            lv_label_set_text(ui.gyro[axis], value);
        }
        position_bubble();
        lv_obj_remove_flag(ui.bubble, LV_OBJ_FLAG_HIDDEN);
        lv_obj_remove_state(ui.zero_button, LV_STATE_DISABLED);
    }
    update_motion_state();
}

static void status_value(lv_obj_t *obj, const char *text, uint32_t color)
{
    lv_label_set_text(obj, text);
    lv_obj_set_style_text_color(obj, lv_color_hex(color), 0);
}

static void render_status(esp_err_t enrollment_result, bool enrolled, bool resetting,
                          bool wifi, wendy_cloud_state_t cloud, int64_t now)
{
    status_value(ui.enrollment,
        resetting ? "Resetting" : enrollment_result != ESP_OK ? "Unavailable" :
        enrolled ? "Enrolled" : "Not enrolled",
        resetting || enrollment_result != ESP_OK ? COLOR_WARNING :
        enrolled ? COLOR_ACCENT : COLOR_MUTED);
    status_value(ui.wifi, wifi ? "Connected" : "Offline", wifi ? COLOR_ACCENT : COLOR_MUTED);
    const char *cloud_text = "Idle";
    uint32_t cloud_color = COLOR_MUTED;
    switch (cloud) {
    case WENDY_CLOUD_STATE_CONNECTED:
        cloud_text = "Connected";
        cloud_color = COLOR_ACCENT;
        break;
    case WENDY_CLOUD_STATE_CONNECTING:
        cloud_text = "Connecting";
        cloud_color = COLOR_WARNING;
        break;
    case WENDY_CLOUD_STATE_DISCONNECTED:
        cloud_text = "Offline";
        break;
    case WENDY_CLOUD_STATE_ERROR:
        cloud_text = "Error";
        cloud_color = COLOR_ERROR;
        break;
    default:
        break;
    }
    status_value(ui.cloud, cloud_text, cloud_color);
    uint64_t seconds = (uint64_t)(now / INT64_C(1000000));
    char text[96];
    snprintf(text, sizeof text, "Up %02" PRIu64 ":%02u:%02u   |   Internal heap %u KiB",
             seconds / 3600, (unsigned)(seconds / 60 % 60), (unsigned)(seconds % 60),
             (unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT) / 1024));
    lv_label_set_text(ui.footer, text);
}

static bool read_motion(motion_sample_t *sample)
{
    if (bsp_imu_get_accel(&sample->accel[0], &sample->accel[1], &sample->accel[2]) != ESP_OK ||
        bsp_imu_get_gyro(&sample->gyro[0], &sample->gyro[1], &sample->gyro[2]) != ESP_OK) {
        return false;
    }
    for (int axis = 0; axis < 3; ++axis) {
        if (!isfinite(sample->accel[axis]) || !isfinite(sample->gyro[axis])) {
            return false;
        }
    }
    return true;
}

static void dashboard_task(void *argument)
{
    (void)argument;
    bsp_board_variant_t variant;
    esp_err_t result = bsp_board_variant_get(&variant);
    if (result != ESP_OK) {
        mosaico_diagnostics_stage("board revision unavailable", result);
        ESP_LOGE(TAG, "Board revision unavailable (%s); Wendy management remains active",
                 esp_err_to_name(result));
        vTaskDelete(NULL);
        return;
    }
    ESP_LOGI(TAG, "Starting dashboard on Mosaico v%s",
             variant == BSP_BOARD_VARIANT_V1_0 ? "1.0" : "1.1/1.2");

    lv_display_t *display = bsp_display_get();
    if (!display || !bsp_display_lock(1000)) {
        mosaico_diagnostics_stage("display unavailable", ESP_FAIL);
        ESP_LOGE(TAG, "Display unavailable; Wendy management remains active");
        vTaskDelete(NULL);
        return;
    }
    lv_obj_clean(lv_display_get_screen_active(display));
    create_dashboard(display);
    mosaico_diagnostics_stage("dashboard running", ESP_OK);
    bsp_display_unlock();

    esp_ota_img_states_t ota_state;
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running && esp_ota_get_state_partition(running, &ota_state) == ESP_OK &&
        ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
        mosaico_diagnostics_stage("confirming firmware", ESP_OK);
        result = esp_ota_mark_app_valid_cancel_rollback();
        mosaico_diagnostics_stage(result == ESP_OK ? "dashboard running" :
                                  "firmware confirmation failed", result);
    }

    result = bsp_imu_init();
    if (result == ESP_OK) {
        const bsp_imu_config_t config = BSP_IMU_CONFIG_DEFAULT();
        result = bsp_imu_start(&config);
    }
    bool imu_ready = result == ESP_OK;
    if (!imu_ready) {
        ESP_LOGW(TAG, "IMU unavailable (%s); device status remains active", esp_err_to_name(result));
    }

    static struct wendy_mesh_snapshot mesh;
    int64_t next_status = 0;
    int64_t next_motion = 0;
    bool motion_valid = false;
    motion_sample_t sample = {0};
    esp_err_t enrollment_result = ESP_FAIL;
    bool enrolled = false;
    bool resetting = false;
    bool wifi = false;
    wendy_cloud_state_t cloud = WENDY_CLOUD_STATE_IDLE;
    for (;;) {
        int64_t now = esp_timer_get_time();
        bool status_due = now >= next_status;
        bool motion_due = imu_ready && now >= next_motion;
        if (motion_due) {
            motion_valid = read_motion(&sample);
            next_motion = now + (motion_valid ? SAMPLE_PERIOD_MS * INT64_C(1000) : RETRY_PERIOD_US);
        }
        if (status_due) {
            /* Status-only does not create or replace the USB enrollment nonce. */
            char nonce[65] = {0};
            enrollment_result = wendy_pki_challenge(true, nonce, &enrolled);
            resetting = wendy_pki_reset_in_progress();
            wifi = wendy_wifi_is_connected();
            cloud = wendy_cloud_get_state();
            wendy_mesh_get_snapshot(&mesh);
            next_status = now + STATUS_PERIOD_US;
        }
        if (bsp_display_lock(100)) {
            if (motion_due || !imu_ready) {
                render_motion(&sample, motion_valid);
            }
            if (status_due) {
                render_status(enrollment_result, enrolled, resetting, wifi, cloud, now);
                render_mesh(&mesh);
            }
            bsp_display_unlock();
        }
        vTaskDelay(pdMS_TO_TICKS(SAMPLE_PERIOD_MS));
    }
}

void app_main(void)
{
    mosaico_diagnostics_start();
    ESP_ERROR_CHECK(mosaico_usb_management_start());
    ESP_ERROR_CHECK(esp_register_shutdown_handler(restart_board));
    /* Reserve the panel DMA resources before Wi-Fi and BLE fragment the heap. */
    mosaico_diagnostics_stage("starting display", ESP_OK);
    bsp_display_config_t display_config = BSP_DISPLAY_DEFAULT_CONFIG();
    /* PSRAM pixels need an internal DMA bounce buffer. Keep each flush small
     * enough to coexist with Wi-Fi, BLE and mesh task stacks. */
    display_config.tear_avoid_mode = ESP_LV_ADAPTER_TEAR_AVOID_MODE_NONE;
    display_config.buffer_height = 8;
    lv_display_t *display = bsp_display_start_with_config(&display_config);
    if (display && bsp_display_lock(1000)) {
        lv_obj_t *screen = lv_display_get_screen_active(display);
        lv_obj_set_style_bg_color(screen, lv_color_hex(COLOR_BACKGROUND), 0);
        label(screen, "Starting Wendy...", 32, 210, 416,
              &lv_font_montserrat_28, COLOR_TEXT);
        bsp_display_unlock();
    }
    mosaico_diagnostics_stage("starting Wendy services", ESP_OK);
    esp_err_t result = wendy_core_init();
    if (result != ESP_OK) {
        mosaico_diagnostics_stage("Wendy startup failed", result);
        ESP_LOGE(TAG, "Wendy startup failed: %s", esp_err_to_name(result));
        return;
    }
    mosaico_diagnostics_stage("starting dashboard", ESP_OK);
    if (xTaskCreate(dashboard_task, "mosaico_dashboard", 6144, NULL, 3, NULL) != pdPASS) {
        mosaico_diagnostics_stage("dashboard task allocation failed", ESP_ERR_NO_MEM);
        ESP_LOGE(TAG, "Cannot start dashboard task; Wendy management remains active");
    }
}
