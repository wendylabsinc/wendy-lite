#include "wendy_otel.h"

#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "wasm_export.h"

static const char *TAG = "wendy_otel";

/* ── In-memory metrics store ──────────────────────────────────────────── */

#define MAX_METRICS 16
#define MAX_NAME_LEN 32

typedef enum {
    METRIC_COUNTER,
    METRIC_GAUGE,
    METRIC_HISTOGRAM,
} metric_type_t;

typedef struct {
    char name[MAX_NAME_LEN];
    metric_type_t type;
    union {
        int64_t counter;
        double gauge;
        struct {
            double sum;
            int64_t count;
            double min;
            double max;
        } histogram;
    };
    bool used;
} metric_t;

static metric_t s_metrics[MAX_METRICS];

static metric_t *find_or_create_metric(const char *name, int name_len, metric_type_t type)
{
    int len = (name_len < MAX_NAME_LEN - 1) ? name_len : MAX_NAME_LEN - 1;

    for (int i = 0; i < MAX_METRICS; i++) {
        if (s_metrics[i].used && strncmp(s_metrics[i].name, name, len) == 0 &&
            s_metrics[i].name[len] == '\0') {
            return &s_metrics[i];
        }
    }
    for (int i = 0; i < MAX_METRICS; i++) {
        if (!s_metrics[i].used) {
            memset(&s_metrics[i], 0, sizeof(metric_t));
            memcpy(s_metrics[i].name, name, len);
            s_metrics[i].name[len] = '\0';
            s_metrics[i].type = type;
            s_metrics[i].used = true;
            if (type == METRIC_HISTOGRAM) {
                s_metrics[i].histogram.min = 1e18;
                s_metrics[i].histogram.max = -1e18;
            }
            return &s_metrics[i];
        }
    }
    return NULL;
}

/* ── Span ring buffer ─────────────────────────────────────────────────── */

#define MAX_SPANS 8
#define MAX_SPAN_NAME 32

typedef struct {
    char name[MAX_SPAN_NAME];
    int64_t start_us;
    int64_t end_us;
    int status;     /* 0=unset, 1=ok, 2=error */
    bool active;
} span_t;

static span_t s_spans[MAX_SPANS];
static int s_span_next = 0;

/* ── WASM wrappers ────────────────────────────────────────────────────── */

/* otel_log(level, msg_ptr, msg_len) -> 0 */
static int otel_log_wrapper(wasm_exec_env_t exec_env,
                             int level, const char *msg, int msg_len)
{
    if (!msg || msg_len <= 0) return -1;

    /* Map to ESP_LOG levels: 1=error, 2=warn, 3=info, 4=debug */
    switch (level) {
    case 1: ESP_LOGE("wasm_app", "%.*s", msg_len, msg); break;
    case 2: ESP_LOGW("wasm_app", "%.*s", msg_len, msg); break;
    case 3: ESP_LOGI("wasm_app", "%.*s", msg_len, msg); break;
    case 4: ESP_LOGD("wasm_app", "%.*s", msg_len, msg); break;
    default: ESP_LOGI("wasm_app", "%.*s", msg_len, msg); break;
    }
    return 0;
}

/* otel_metric_counter_add(name_ptr, name_len, value_i64) -> 0 */
static int otel_metric_counter_add_wrapper(wasm_exec_env_t exec_env,
                                            const char *name, int name_len,
                                            int64_t value)
{
    if (!name || name_len <= 0) return -1;
    metric_t *m = find_or_create_metric(name, name_len, METRIC_COUNTER);
    if (!m) return -1;
    m->counter += value;
    return 0;
}

/* otel_metric_gauge_set(name_ptr, name_len, value_f64) -> 0 */
static int otel_metric_gauge_set_wrapper(wasm_exec_env_t exec_env,
                                          const char *name, int name_len,
                                          double value)
{
    if (!name || name_len <= 0) return -1;
    metric_t *m = find_or_create_metric(name, name_len, METRIC_GAUGE);
    if (!m) return -1;
    m->gauge = value;
    return 0;
}

/* otel_metric_histogram_record(name_ptr, name_len, value_f64) -> 0 */
static int otel_metric_histogram_record_wrapper(wasm_exec_env_t exec_env,
                                                 const char *name, int name_len,
                                                 double value)
{
    if (!name || name_len <= 0) return -1;
    metric_t *m = find_or_create_metric(name, name_len, METRIC_HISTOGRAM);
    if (!m) return -1;
    m->histogram.sum += value;
    m->histogram.count++;
    if (value < m->histogram.min) m->histogram.min = value;
    if (value > m->histogram.max) m->histogram.max = value;
    return 0;
}

/* otel_span_start(name_ptr, name_len) -> span_id (>=0) */
static int otel_span_start_wrapper(wasm_exec_env_t exec_env,
                                    const char *name, int name_len)
{
    if (!name || name_len <= 0) return -1;

    int id = s_span_next;
    s_span_next = (s_span_next + 1) % MAX_SPANS;

    span_t *s = &s_spans[id];
    int len = (name_len < MAX_SPAN_NAME - 1) ? name_len : MAX_SPAN_NAME - 1;
    memcpy(s->name, name, len);
    s->name[len] = '\0';
    s->start_us = esp_timer_get_time();
    s->end_us = 0;
    s->status = 0;
    s->active = true;

    return id;
}

/* otel_span_set_attribute(span_id, key_ptr, key_len, val_ptr, val_len) -> 0 */
static int otel_span_set_attribute_wrapper(wasm_exec_env_t exec_env,
                                            int span_id,
                                            const char *key, int key_len,
                                            const char *val, int val_len)
{
    /* In-memory only — log it */
    if (span_id < 0 || span_id >= MAX_SPANS || !s_spans[span_id].active) return -1;
    ESP_LOGD(TAG, "span[%d] attr: %.*s = %.*s", span_id, key_len, key, val_len, val);
    return 0;
}

/* otel_span_set_status(span_id, status) -> 0 */
static int otel_span_set_status_wrapper(wasm_exec_env_t exec_env,
                                         int span_id, int status)
{
    if (span_id < 0 || span_id >= MAX_SPANS || !s_spans[span_id].active) return -1;
    s_spans[span_id].status = status;
    return 0;
}

/* otel_span_end(span_id) -> 0 */
static int otel_span_end_wrapper(wasm_exec_env_t exec_env, int span_id)
{
    if (span_id < 0 || span_id >= MAX_SPANS || !s_spans[span_id].active) return -1;
    s_spans[span_id].end_us = esp_timer_get_time();
    s_spans[span_id].active = false;

    int64_t duration_us = s_spans[span_id].end_us - s_spans[span_id].start_us;
    ESP_LOGI(TAG, "span '%s' ended: %lld us (status=%d)",
             s_spans[span_id].name, (long long)duration_us, s_spans[span_id].status);
    return 0;
}

static NativeSymbol s_otel_symbols[] = {
    { "otel_log",                       (void *)otel_log_wrapper,                       "(i*~)i",    NULL },
    { "otel_metric_counter_add",        (void *)otel_metric_counter_add_wrapper,        "(*~I)i",    NULL },
    { "otel_metric_gauge_set",          (void *)otel_metric_gauge_set_wrapper,          "(*~F)i",    NULL },
    { "otel_metric_histogram_record",   (void *)otel_metric_histogram_record_wrapper,   "(*~F)i",    NULL },
    { "otel_span_start",                (void *)otel_span_start_wrapper,                "(*~)i",     NULL },
    { "otel_span_set_attribute",        (void *)otel_span_set_attribute_wrapper,        "(i*~*~)i",  NULL },
    { "otel_span_set_status",           (void *)otel_span_set_status_wrapper,           "(ii)i",     NULL },
    { "otel_span_end",                  (void *)otel_span_end_wrapper,                  "(i)i",      NULL },
};

int wendy_otel_export_init(void)
{
    memset(s_metrics, 0, sizeof(s_metrics));
    memset(s_spans, 0, sizeof(s_spans));

    if (!wasm_runtime_register_natives("wendy",
                                       s_otel_symbols,
                                       sizeof(s_otel_symbols) / sizeof(s_otel_symbols[0]))) {
        ESP_LOGE(TAG, "failed to register otel natives");
        return -1;
    }
    ESP_LOGI(TAG, "OpenTelemetry exports registered");
    return 0;
}
