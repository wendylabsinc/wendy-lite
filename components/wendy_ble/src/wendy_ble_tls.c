#include "wendy_ble_tls.h"
#include "wendy_ble_l2cap.h"
#include "wendy_conf.h"
#include "wendy_pki.h"

#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
// For MBEDTLS_ERR_NET_{RECV,SEND}_FAILED, the codes mbedTLS expects a BIO to
// report a broken transport with. None of the socket helpers are used.
#include "mbedtls/net_sockets.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"


//--- literals ---//

#define TAG  "wendy_ble_tls"

// A cold ECDSA handshake over BLE is dominated by moving certificate bytes.
// Two seconds is the expectation; this is the give-up point.
#define HANDSHAKE_TIMEOUT_US  (15 * 1000 * 1000)
#define IO_WAIT               pdMS_TO_TICKS(2000)


//--- globals ---//

static bool _active;
// Session-owned snapshot of the transport's boot policy. Live configuration
// changes revoke access; they must never select a weaker backend this boot.
static bool _enrolled;
#if CONFIG_WENDY_PKI
static wendy_pki_connection *_pki;
#endif

static mbedtls_ssl_context      _ssl;
static mbedtls_ssl_config       _conf;
static mbedtls_x509_crt         _own_cert;
static mbedtls_pk_context       _own_key;
static mbedtls_entropy_context  _entropy;
static mbedtls_ctr_drbg_context _ctr_drbg;


//--- internal functions ---//

static bool _session_allowed(void)
{
    return !wendy_pki_reset_in_progress() && wendy_conf_has_enrollment() == _enrolled &&
           (!_enrolled || wendy_conf_is_current());
}

#if CONFIG_WENDY_PKI
static ssize_t _pki_recv(void *ctx, void *buf, size_t len)
{
    (void)ctx;
    return _session_allowed() ? wble_l2cap_read(buf, len) : WBLE_ERR_UNKNOWN;
}

static ssize_t _pki_send(void *ctx, const void *buf, size_t len)
{
    (void)ctx;
    return _session_allowed() ? wble_l2cap_write(buf, len) : WBLE_ERR_UNKNOWN;
}

static int _pki_wait(void *ctx, bool writing, int64_t deadline_us)
{
    (void)ctx;
    int64_t left = deadline_us - esp_timer_get_time();
    if (left <= 0 || !_session_allowed() || !wble_l2cap_session_alive())
        return -1;
    // Recheck identity and disconnect state at least every two seconds.
    int64_t wait_ms = (left + 999) / 1000;
    if (wait_ms > 2000)
        wait_ms = 2000;
    TickType_t ticks = pdMS_TO_TICKS(wait_ms);
    if (!ticks)
        ticks = 1;
    if (writing)
        wble_l2cap_wait_writable(ticks);
    else
        wble_l2cap_wait_readable(ticks);
    return _session_allowed() && wble_l2cap_session_alive() &&
           esp_timer_get_time() < deadline_us ? 0 : -1;
}

static const struct wendy_pki_stream _pki_stream = {
    .read = _pki_recv,
    .write = _pki_send,
    .wait = _pki_wait,
};
#endif

/// mbedTLS BIO. The L2CAP layer already speaks in WANT_READ / WANT_WRITE, so
/// this is a pure translation; the receive ring below it is what makes a
/// record header and its body readable as two separate calls.
static int _bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    ssize_t n = wble_l2cap_read(buf, len);
    if (n == WBLE_ERR_WANT_READ)
        return MBEDTLS_ERR_SSL_WANT_READ;
    if (n < 0)
        return MBEDTLS_ERR_NET_RECV_FAILED;
    // 0 is end of stream; mbedTLS turns it into MBEDTLS_ERR_SSL_CONN_EOF.
    return (int)n;
}

static int _bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    (void)ctx;
    ssize_t n = wble_l2cap_write(buf, len);
    if (n == WBLE_ERR_WANT_WRITE)
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    if (n < 0)
        return MBEDTLS_ERR_NET_SEND_FAILED;
    // A short write is fine: mbedtls_ssl_flush_output tracks the remainder in
    // out_left and calls back for the tail. That is what decouples the TLS
    // record size from the L2CAP MTU.
    return (int)n;
}

static void _log_mbedtls_error(const char *what, int ret)
{
#ifdef MBEDTLS_ERROR_C
    char buf[128];
    mbedtls_strerror(ret, buf, sizeof(buf));
    ESP_LOGE(TAG, "%s failed: -0x%04x (%s)", what, (unsigned)-ret, buf);
#else
    ESP_LOGE(TAG, "%s failed: -0x%04x", what, (unsigned)-ret);
#endif
}

static void _free_contexts(void)
{
    mbedtls_ssl_free(&_ssl);
    mbedtls_ssl_config_free(&_conf);
    mbedtls_x509_crt_free(&_own_cert);
    mbedtls_pk_free(&_own_key);
    mbedtls_ctr_drbg_free(&_ctr_drbg);
    mbedtls_entropy_free(&_entropy);
}


//--- public functions ---//

esp_err_t wble_tls_session_start(bool enrolled)
{
    static const char *pers = "wendy_ble_tls";
    esp_err_t result = ESP_FAIL;

    _active = false;
    _enrolled = enrolled;
    if (wendy_pki_reset_in_progress()) {
        ESP_LOGW(TAG, "identity reset in progress; BLE connection rejected");
        return ESP_ERR_INVALID_STATE;
    }
    // A physical config upload invalidates the live cache until reboot. Use
    // the policy captured before advertising, not those empty cache values.
    if (!_session_allowed()) {
        ESP_LOGW(TAG, "BLE identity changed since startup; reboot required");
        return ESP_ERR_INVALID_STATE;
    }
    if (_enrolled) {
#if CONFIG_WENDY_PKI
        // Use the enrolled identity and operator verification from LAN/Cloud.
        // A PKI failure must never fall back to anonymous TLS.
        result = wendy_pki_accept_stream(&_pki_stream, &_pki);
        if (result != ESP_OK)
            return result;
        if (!_session_allowed()) {
            wendy_pki_close(_pki);
            _pki = NULL;
            return ESP_ERR_INVALID_STATE;
        }
        _active = true;
        ESP_LOGI(TAG, "PKI operator handshake complete");
        return ESP_OK;
#else
        return ESP_ERR_INVALID_STATE;
#endif
    }

    mbedtls_ssl_init(&_ssl);
    mbedtls_ssl_config_init(&_conf);
    mbedtls_x509_crt_init(&_own_cert);
    mbedtls_pk_init(&_own_key);
    mbedtls_entropy_init(&_entropy);
    mbedtls_ctr_drbg_init(&_ctr_drbg);

#if CONFIG_WENDY_BLE_REQUIRE_MTLS
    ESP_LOGW(TAG, "BLE requires enrollment; use USB for setup");
    result = ESP_ERR_INVALID_STATE;
    goto fail;
#endif

    struct wendy_conf_span cert = wendy_conf_get_default_certificate();
    struct wendy_conf_span key = wendy_conf_get_default_private_key();

    int ret = mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy,
                                    (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        _log_mbedtls_error("ctr_drbg_seed", ret);
        goto fail;
    }

    ret = mbedtls_x509_crt_parse_der(&_own_cert, cert.data, cert.size);
    if (ret != 0) {
        _log_mbedtls_error("parsing the device certificate", ret);
        goto fail;
    }
    ret = mbedtls_pk_parse_key(&_own_key, key.data, key.size, NULL, 0,
                               mbedtls_ctr_drbg_random, &_ctr_drbg);
    if (ret != 0) {
        _log_mbedtls_error("parsing the device private key", ret);
        goto fail;
    }

    ret = mbedtls_ssl_config_defaults(&_conf, MBEDTLS_SSL_IS_SERVER,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        _log_mbedtls_error("ssl_config_defaults", ret);
        goto fail;
    }

    mbedtls_ssl_conf_authmode(&_conf, MBEDTLS_SSL_VERIFY_NONE);

    mbedtls_ssl_conf_rng(&_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

    ret = mbedtls_ssl_conf_own_cert(&_conf, &_own_cert, &_own_key);
    if (ret != 0) {
        _log_mbedtls_error("ssl_conf_own_cert", ret);
        goto fail;
    }

    ret = mbedtls_ssl_setup(&_ssl, &_conf);
    if (ret != 0) {
        _log_mbedtls_error("ssl_setup", ret);
        goto fail;
    }

    mbedtls_ssl_set_bio(&_ssl, NULL, _bio_send, _bio_recv, NULL);

    ESP_LOGI(TAG, "handshake starting (unenrolled, no client verification)");

    int64_t deadline = esp_timer_get_time() + HANDSHAKE_TIMEOUT_US;
    size_t heap_before = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    size_t heap_low = heap_before;

    for (;;) {
        if (!_session_allowed()) {
            ESP_LOGW(TAG, "credentials changed during BLE handshake; connection rejected");
            result = ESP_ERR_INVALID_STATE;
            goto fail;
        }
        ret = mbedtls_ssl_handshake(&_ssl);
        if (ret == 0)
            break;

        size_t now_free = heap_caps_get_free_size(MALLOC_CAP_8BIT);
        if (now_free < heap_low)
            heap_low = now_free;

        if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            wble_l2cap_wait_readable(IO_WAIT);
        } else if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            wble_l2cap_wait_writable(IO_WAIT);
        } else {
            _log_mbedtls_error("handshake", ret);
            goto fail;
        }

        if (!wble_l2cap_session_alive()) {
            ESP_LOGW(TAG, "peer vanished during the handshake");
            goto fail;
        }
        if (esp_timer_get_time() > deadline) {
            ESP_LOGE(TAG, "handshake timed out");
            goto fail;
        }
    }

    if (!_session_allowed()) {
        ESP_LOGW(TAG, "credentials changed during BLE handshake; connection rejected");
        result = ESP_ERR_INVALID_STATE;
        goto fail;
    }

    ESP_LOGI(TAG, "handshake done in %lld ms (%s, heap low water %u, cost %u)",
             (HANDSHAKE_TIMEOUT_US - (deadline - esp_timer_get_time())) / 1000,
             mbedtls_ssl_get_ciphersuite(&_ssl),
             (unsigned)heap_low, (unsigned)(heap_before - heap_low));

    _active = true;
    return ESP_OK;

fail:
    _free_contexts();
    return result;
}

void wble_tls_session_end(void)
{
    if (_enrolled) {
#if CONFIG_WENDY_PKI
        wendy_pki_close(_pki);
        _pki = NULL;
#endif
        _active = false;
        return;
    }
    if (_active)
        mbedtls_ssl_close_notify(&_ssl);
    _active = false;
    _free_contexts();
}

bool wble_tls_pending(void)
{
    if (!_active || !_session_allowed())
        return false;
#if CONFIG_WENDY_PKI
    if (_enrolled)
        return wendy_pki_pending(_pki);
#endif
    return mbedtls_ssl_get_bytes_avail(&_ssl) > 0;
}

ssize_t wble_tls_read(void *buf, size_t len)
{
    if (!_active || !_session_allowed())
        return WBLE_ERR_UNKNOWN;

#if CONFIG_WENDY_PKI
    if (_enrolled)
        return wendy_pki_read(_pki, buf, len);
#endif

    int ret = mbedtls_ssl_read(&_ssl, buf, len);
    if (ret > 0)
        return ret;
    if (ret == MBEDTLS_ERR_SSL_WANT_READ)
        return WBLE_ERR_WANT_READ;
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        return WBLE_ERR_WANT_WRITE;
    if (ret == 0
        || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
        || ret == MBEDTLS_ERR_SSL_CONN_EOF)
        return 0;

    _log_mbedtls_error("ssl_read", ret);
    return WBLE_ERR_UNKNOWN;
}

ssize_t wble_tls_write(const void *buf, size_t len)
{
    if (!_active || !_session_allowed())
        return WBLE_ERR_UNKNOWN;

#if CONFIG_WENDY_PKI
    if (_enrolled)
        return wendy_pki_write(_pki, buf, len);
#endif

    int ret = mbedtls_ssl_write(&_ssl, buf, len);
    if (ret > 0)
        return ret;
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        return WBLE_ERR_WANT_WRITE;
    if (ret == MBEDTLS_ERR_SSL_WANT_READ)
        return WBLE_ERR_WANT_READ;

    _log_mbedtls_error("ssl_write", ret);
    return WBLE_ERR_UNKNOWN;
}
