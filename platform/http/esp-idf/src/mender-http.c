/**
 * @file      mender-http.c
 * @brief     Mender HTTP interface for ESP-IDF platform
 *
 * MIT License
 *
 * Copyright (c) 2022-2023 joelguittet and mender-mcu-client contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <errno.h>
#include <esp_http_client.h>
#include <esp_crt_bundle.h>
#include <stdbool.h>
#include <stdint.h>
#include "mender-http.h"
#include "mender-log.h"

/* FW-306/FW-318: device-wide TLS connection-attempt gate
 * (main/modules/net/tls_gate.c). Declared extern rather than included — a
 * component cannot include main/ headers. Mender's handshake overlapping the
 * doorbell WSS or a Postbox HTTPS handshake bottomed internal min-free at 43
 * bytes on the bench (FW-306); the boot-window first attempt then died at
 * ~8KB free with the open-only hold, because the client's own rx/tx buffers
 * (internal RAM) were allocated OUTSIDE the gate (FW-318). The gate is now
 * held across the whole connection attempt — esp_http_client_init (buffer
 * allocation) through esp_http_client_open (socket + TLS handshake) — and
 * released before the body transfer, so an OTA download still cannot starve
 * the other clients. */
extern bool tls_gate_acquire(uint32_t timeout_ms);
extern void tls_gate_release(void);
#define MENDER_TLS_GATE_TIMEOUT_MS (20000)

/**
 * @brief Read timeouts in a row a transfer survives (each is the client's
 * timeout, 5 s by default) before it ends as a failure
 */
#define MENDER_HTTP_READ_STALLS_MAX (6)

/**
 * @brief Mender HTTP configuration
 */
static mender_http_config_t mender_http_config;

/**
 * @brief Convert mender HTTP method to ESP HTTP client method
 * @param method Mender HTTP method
 * @return ESP HTTP client method if the function succeeds, HTTP_METHOD_MAX otherwise
 */
static esp_http_client_method_t mender_http_method_to_esp_http_client_method(mender_http_method_t method);

mender_err_t
mender_http_init(mender_http_config_t *config) {

    assert(NULL != config);
    assert(NULL != config->host);

    /* Save configuration */
    memcpy(&mender_http_config, config, sizeof(mender_http_config_t));

    return MENDER_OK;
}

mender_err_t
mender_http_perform(char *               jwt,
                    char *               path,
                    mender_http_method_t method,
                    char *               payload,
                    char *               signature,
                    mender_err_t (*callback)(mender_http_client_event_t, void *, size_t, void *),
                    void *params,
                    int * status) {

    assert(NULL != path);
    assert(NULL != callback);
    assert(NULL != status);
    esp_err_t                err;
    mender_err_t             ret;
    esp_http_client_handle_t client   = NULL;
    char *                   url      = NULL;
    char *                   bearer   = NULL;
    bool                     tls_held = false;

    /* Compute URL if required */
    if (strncmp(path, "http", strlen("http"))) {
        if (NULL == (url = (char *)malloc(strlen(mender_http_config.host) + strlen(path) + 1))) {
            mender_log_error("Unable to allocate memory");
            ret = MENDER_FAIL;
            goto END;
        }
        sprintf(url, "%s%s", mender_http_config.host, path);
    }

    /* Configuration of the client */
    esp_http_client_config_t config = { .url = (NULL != url) ? url : path, .crt_bundle_attach = esp_crt_bundle_attach, .buffer_size_tx = 2048 };

    /* FW-318: the connection attempt starts HERE — the client's rx/tx
     * buffers are internal-RAM allocations that belong to the attempt just
     * as much as the socket and handshake do. Acquire before init, release
     * after open. Failure paths in between exit via END, which releases. */
    tls_held = tls_gate_acquire(MENDER_TLS_GATE_TIMEOUT_MS);

    /* Initialization of the client */
    if (NULL == (client = esp_http_client_init(&config))) {
        mender_log_error("Unable to allocate memory");
        ret = MENDER_FAIL;
        goto END;
    }
    esp_http_client_set_method(client, mender_http_method_to_esp_http_client_method(method));
    if (NULL != jwt) {
        if (NULL == (bearer = (char *)malloc(strlen("Bearer ") + strlen(jwt) + 1))) {
            mender_log_error("Unable to allocate memory");
            ret = MENDER_FAIL;
            goto END;
        }
        sprintf(bearer, "Bearer %s", jwt);
        esp_http_client_set_header(client, "Authorization", bearer);
    }
    if (NULL != signature) {
        esp_http_client_set_header(client, "X-MEN-Signature", signature);
    }
    if (NULL != payload) {
        esp_http_client_set_header(client, "Content-Type", "application/json");
    }

    /* Open HTTP client connection (DNS + socket + TLS handshake), then end
     * the gated window: everything past here is transfer, which must never
     * hold the device-wide gate. */
    err = esp_http_client_open(client, (NULL != payload) ? (int)strlen(payload) : 0);
    if (tls_held) {
        tls_gate_release();
        tls_held = false;
    }
    if (ESP_OK != err) {
        mender_log_error("Unable to open HTTP client connection: %s", esp_err_to_name(err));
        ret = MENDER_FAIL;
        goto END;
    }
    if (MENDER_OK != (ret = callback(MENDER_HTTP_EVENT_CONNECTED, NULL, 0, params))) {
        mender_log_error("An error occurred");
        goto END;
    }

    /* Write data if payload is defined */
    if (NULL != payload) {
        if (esp_http_client_write(client, payload, (int)strlen(payload)) < 0) {
            mender_log_error("Unable to write data");
            ret = MENDER_FAIL;
            goto END;
        }
    }

    /* Fetch headers, this returns the content length */
    if (esp_http_client_fetch_headers(client) < 0) {
        mender_log_error("Unable to fetch headers");
        ret = MENDER_FAIL;
        goto END;
    }

    /* Read data until all have been received. A read that brings nothing is
     * the transport waiting out its timeout (-ESP_ERR_HTTP_EAGAIN, tried again
     * a few times) or a connection that ended before the body did: a server
     * that closed mid-body made every later read return at once, and the
     * loop spun core 0 until the watchdog fired */
    int stalls = 0;
    while (false == esp_http_client_is_complete_data_received(client)) {
        char data[512];
        int  read_length = esp_http_client_read(client, data, sizeof(data));

        if (read_length > 0) {
            stalls = 0;
            /* Transmit data received to the upper layer */
            if (MENDER_OK != (ret = callback(MENDER_HTTP_EVENT_DATA_RECEIVED, data, (size_t)read_length, params))) {
                mender_log_error("An error occurred, stop reading data");
                goto END;
            }
        } else if (esp_http_client_is_complete_data_received(client)) {
            /* The last read held only the end of a chunked body */
            break;
        } else if ((-ESP_ERR_HTTP_EAGAIN == read_length) && (++stalls < MENDER_HTTP_READ_STALLS_MAX)) {
            continue;
        } else {
            mender_log_error("An error occurred, connection has been closed, read = %d, errno = %d", read_length, errno);
            callback(MENDER_HTTP_EVENT_ERROR, NULL, 0, params);
            ret = MENDER_FAIL;
            goto END;
        }
    }

    /* Read HTTP status code */
    *status = esp_http_client_get_status_code(client);
    if (MENDER_OK != (ret = callback(MENDER_HTTP_EVENT_DISCONNECTED, NULL, 0, params))) {
        mender_log_error("An error occurred");
        goto END;
    }

END:

    /* A failure between the gate acquire and the post-open release (client
     * init or bearer allocation) lands here still holding — a leaked hold
     * would starve every TLS connection attempt on the device. */
    if (tls_held) {
        tls_gate_release();
    }

    /* Release memory */
    if (NULL != client) {
        esp_http_client_cleanup(client);
    }
    if (NULL != bearer) {
        free(bearer);
    }
    if (NULL != url) {
        free(url);
    }

    return ret;
}

mender_err_t
mender_http_exit(void) {

    /* Nothing to do */
    return MENDER_OK;
}

static esp_http_client_method_t
mender_http_method_to_esp_http_client_method(mender_http_method_t method) {

    /* Convert method */
    if (MENDER_HTTP_GET == method) {
        return HTTP_METHOD_GET;
    } else if (MENDER_HTTP_POST == method) {
        return HTTP_METHOD_POST;
    } else if (MENDER_HTTP_PUT == method) {
        return HTTP_METHOD_PUT;
    } else if (MENDER_HTTP_PATCH == method) {
        return HTTP_METHOD_PATCH;
    }

    return HTTP_METHOD_MAX;
}
