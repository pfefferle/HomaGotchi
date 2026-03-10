/**
 * HomaGotchi Companion – WiFi promiscuous sniffer
 *
 * Detects:
 *   - Deauth frames (subtype 0x0C)
 *   - Disassoc frames (subtype 0x0A)
 *   - Pwnagotchi beacons (vendor IE containing "pwnd" / "pwnagotchi")
 *   - Evil twin APs (same SSID from different BSSIDs)
 *
 * SPDX-License-Identifier: MIT
 */

#include "wifi_sniffer.h"
#include "config.h"

#include <string.h>
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"

static const char *TAG = "sniffer";

/* ── 802.11 management frame subtypes ─────────────────────────────────────── */

#define SUBTYPE_BEACON    0x08
#define SUBTYPE_DISASSOC  0x0A
#define SUBTYPE_DEAUTH    0x0C

/* Beacon: 24-byte MAC header + 12-byte fixed params = tagged IEs at offset 36 */
#define BEACON_IE_OFFSET  (24 + 12)
#define IE_TAG_SSID       0
#define IE_TAG_VENDOR     221

/* ── Counters (protected by spinlock) ─────────────────────────────────────── */

static portMUX_TYPE s_counter_mux = portMUX_INITIALIZER_UNLOCKED;

static uint16_t s_deauth;
static uint16_t s_disassoc;
static uint8_t  s_pwnagotchi;
static uint8_t  s_evil_twin;

/* ── Evil-twin AP table ───────────────────────────────────────────────────── */

typedef struct {
    char    ssid[HG_MAX_SSID_LEN + 1];
    uint8_t bssid[6];
    bool    used;
} ap_entry_t;

static ap_entry_t s_ap_table[HG_MAX_AP_ENTRIES];

/* ── Channel state ────────────────────────────────────────────────────────── */

static uint8_t s_channel = 1;
static uint32_t s_collect_count;  /* number of collect() calls, for periodic AP reset */

/* ── Beacon helpers ───────────────────────────────────────────────────────── */

/** Return true if needle appears anywhere in [haystack, haystack+len). */
static bool mem_contains(const uint8_t *haystack, uint16_t len,
                         const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen > len) {
        return false;
    }
    for (uint16_t i = 0; i <= len - nlen; i++) {
        if (memcmp(&haystack[i], needle, nlen) == 0) {
            return true;
        }
    }
    return false;
}

/** Walk tagged IEs looking for a pwnagotchi vendor IE. */
static bool ie_has_pwnagotchi(const uint8_t *ie, uint16_t ie_len)
{
    uint16_t pos = 0;
    while (pos + 2 <= ie_len) {
        uint8_t tag = ie[pos];
        uint8_t len = ie[pos + 1];
        pos += 2;
        if (pos + len > ie_len) {
            break;
        }
        if (tag == IE_TAG_VENDOR && len > 4) {
            if (mem_contains(&ie[pos], len, "pwnd") ||
                mem_contains(&ie[pos], len, "pwnagotchi")) {
                return true;
            }
        }
        pos += len;
    }
    return false;
}

/** Extract the SSID from tagged IEs. Returns length, 0 if hidden/absent. */
static uint8_t ie_get_ssid(const uint8_t *ie, uint16_t ie_len,
                           char *out, uint8_t out_size)
{
    uint16_t pos = 0;
    while (pos + 2 <= ie_len) {
        uint8_t tag = ie[pos];
        uint8_t len = ie[pos + 1];
        pos += 2;
        if (pos + len > ie_len) {
            break;
        }
        if (tag == IE_TAG_SSID && len > 0 && len < out_size) {
            memcpy(out, &ie[pos], len);
            out[len] = '\0';
            return len;
        }
        pos += len;
    }
    return 0;
}

/**
 * Record an SSID/BSSID pair.
 * Returns true when the same SSID is already known from a *different* BSSID.
 */
static bool ap_table_track(const char *ssid, const uint8_t *bssid)
{
    int free_slot = -1;
    bool ssid_seen = false;

    for (int i = 0; i < HG_MAX_AP_ENTRIES; i++) {
        if (!s_ap_table[i].used) {
            if (free_slot < 0) {
                free_slot = i;
            }
            continue;
        }
        if (strcmp(s_ap_table[i].ssid, ssid) != 0) {
            continue;
        }
        if (memcmp(s_ap_table[i].bssid, bssid, 6) == 0) {
            return false;  /* Same AP, nothing new */
        }
        ssid_seen = true;
    }

    if (free_slot >= 0) {
        strncpy(s_ap_table[free_slot].ssid, ssid, HG_MAX_SSID_LEN);
        s_ap_table[free_slot].ssid[HG_MAX_SSID_LEN] = '\0';
        memcpy(s_ap_table[free_slot].bssid, bssid, 6);
        s_ap_table[free_slot].used = true;
    }

    return ssid_seen;
}

/* ── Promiscuous callback (runs in WiFi task context) ─────────────────────── */

static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT) {
        return;
    }

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t frame_len = pkt->rx_ctrl.sig_len;
    uint8_t subtype = (frame[0] >> 4) & 0x0F;

    if (subtype == SUBTYPE_DEAUTH) {
        portENTER_CRITICAL_ISR(&s_counter_mux);
        s_deauth++;
        portEXIT_CRITICAL_ISR(&s_counter_mux);
        return;
    }
    if (subtype == SUBTYPE_DISASSOC) {
        portENTER_CRITICAL_ISR(&s_counter_mux);
        s_disassoc++;
        portEXIT_CRITICAL_ISR(&s_counter_mux);
        return;
    }

    if (subtype != SUBTYPE_BEACON || frame_len <= BEACON_IE_OFFSET) {
        return;
    }

    const uint8_t *bssid    = &frame[16];
    const uint8_t *ie_start = &frame[BEACON_IE_OFFSET];
    uint16_t       ie_len   = frame_len - BEACON_IE_OFFSET;

    if (ie_has_pwnagotchi(ie_start, ie_len)) {
        portENTER_CRITICAL_ISR(&s_counter_mux);
        s_pwnagotchi = 1;
        portEXIT_CRITICAL_ISR(&s_counter_mux);
    }

    char ssid[HG_MAX_SSID_LEN + 1] = {0};
    if (ie_get_ssid(ie_start, ie_len, ssid, sizeof(ssid)) > 0) {
        if (ap_table_track(ssid, bssid)) {
            portENTER_CRITICAL_ISR(&s_counter_mux);
            s_evil_twin = 1;
            portEXIT_CRITICAL_ISR(&s_counter_mux);
        }
    }
}

/* ── Public API ───────────────────────────────────────────────────────────── */

void wifi_sniffer_init(void)
{
    memset(s_ap_table, 0, sizeof(s_ap_table));

    esp_netif_init();
    esp_event_loop_create_default();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(sniffer_cb);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT,
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);

    ESP_LOGI(TAG, "Promiscuous mode active on channel %d", s_channel);
}

void wifi_sniffer_hop(void)
{
    s_channel = (s_channel % HG_MAX_CHANNEL) + 1;
    esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
}

wifi_report_t wifi_sniffer_collect(void)
{
    wifi_report_t r;

    portENTER_CRITICAL(&s_counter_mux);
    r.deauth     = s_deauth;
    r.disassoc   = s_disassoc;
    r.pwnagotchi = s_pwnagotchi != 0;
    r.evil_twin  = s_evil_twin  != 0;
    s_deauth     = 0;
    s_disassoc   = 0;
    s_pwnagotchi = 0;
    s_evil_twin  = 0;
    portEXIT_CRITICAL(&s_counter_mux);

    /*
     * Periodically clear the AP table to prevent stale entries from blocking
     * new APs and to reduce false positives from roaming/mesh environments.
     * Reset every ~5 minutes (30 collect cycles at 10 s each).
     */
    s_collect_count++;
    if (s_collect_count >= 30) {
        s_collect_count = 0;
        memset(s_ap_table, 0, sizeof(s_ap_table));
        ESP_LOGI(TAG, "AP table reset (periodic)");
    }

    return r;
}
