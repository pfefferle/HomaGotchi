/**
 * HomaGotchi Companion – WiFi promiscuous sniffer
 *
 * Detects:
 *   - Deauth frames (subtype 0x0C)
 *   - Disassoc frames (subtype 0x0A)
 *   - Pwnagotchi beacons (MAC DE:AD:BE:EF:DE:AD + JSON fallback)
 *   - Evil twin APs (same SSID from different BSSIDs)
 *   - Beacon spam (many unique source MACs broadcasting beacons)
 *   - Probe request floods (high rate of probe requests)
 *   - Karma / multi-SSID devices (one BSSID advertising 3+ SSIDs)
 *   - Pineapple devices (suspicious OUI in beacon source)
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

#define SUBTYPE_ASSOC_REQ 0x00
#define SUBTYPE_PROBE_REQ 0x04
#define SUBTYPE_BEACON    0x08
#define SUBTYPE_DISASSOC  0x0A
#define SUBTYPE_DEAUTH    0x0C

/* Beacon: 24-byte MAC header + 12-byte fixed params = tagged IEs at offset 36 */
#define BEACON_IE_OFFSET  (24 + 12)
#define IE_TAG_SSID       0
#define IE_TAG_VENDOR     221

/* Pwnagotchi broadcasts from this well-known source MAC */
static const uint8_t PWNAGOTCHI_MAC[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD};

/* Our own beacon MAC — ignore to avoid self-detection */
static const uint8_t SELF_MAC[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};

/* ── Suspicious OUIs (first 3 bytes of MAC) for pineapple detection ───────── */

typedef struct {
    uint8_t oui[3];
} oui_entry_t;

static const oui_entry_t PINEAPPLE_OUIS[] = {
    {{0x00, 0x13, 0x37}},  /* Hak5 WiFi Pineapple MK7 */
    {{0x02, 0xC0, 0xCA}},  /* Hak5 variant */
    {{0x02, 0x13, 0x37}},  /* Hak5 variant */
    {{0x00, 0xC0, 0xCA}},  /* Alfa Inc */
    {{0x1C, 0xBF, 0xCE}},  /* Shenzhen Century (common pineapple clone) */
    {{0xDE, 0xAD, 0xBE}},  /* Spoofed/unassigned MAC prefix */
};

#define NUM_PINEAPPLE_OUIS (sizeof(PINEAPPLE_OUIS) / sizeof(PINEAPPLE_OUIS[0]))

/* ── Counters (protected by spinlock) ─────────────────────────────────────── */

static portMUX_TYPE s_counter_mux = portMUX_INITIALIZER_UNLOCKED;

static uint16_t s_deauth;
static uint16_t s_disassoc;
static uint16_t s_probe_requests;
static uint16_t s_flags;  /* bitmask of HG_FLAG_* */

/* ── Evil-twin / karma AP table ───────────────────────────────────────────── */

typedef struct {
    char    ssid[HG_MAX_SSID_LEN + 1];
    uint8_t bssid[6];
    bool    used;
} ap_entry_t;

static ap_entry_t s_ap_table[HG_MAX_AP_ENTRIES];

/* ── Beacon spam: unique source MAC tracker ───────────────────────────────── */

static uint8_t s_beacon_macs[HG_MAX_BEACON_MACS][6];
static uint16_t s_beacon_mac_count;

/* ── Channel state ────────────────────────────────────────────────────────── */

static uint8_t s_channel = 1;
static uint32_t s_collect_count;

/* ── Helpers ──────────────────────────────────────────────────────────────── */

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

/** Check if a MAC OUI matches any known pineapple device. */
static bool is_pineapple_oui(const uint8_t *mac)
{
    for (int i = 0; i < NUM_PINEAPPLE_OUIS; i++) {
        if (memcmp(mac, PINEAPPLE_OUIS[i].oui, 3) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * Check whether a management frame is from a pwnagotchi.
 *
 * Detection methods:
 *   1. Well-known source MAC DE:AD:BE:EF:DE:AD.
 *   2. pwngrid custom IE tags 222-226 (0xDE-0xE2) — unique to pwnagotchi.
 *      The payload is gzip-compressed, so raw JSON string search won't work.
 *   3. Uncompressed JSON fallback for forks that don't use pwngrid.
 */
static bool is_pwnagotchi_beacon(const uint8_t *src_mac,
                                  const uint8_t *ie, uint16_t ie_len)
{
    /* Method 1: well-known pwnagotchi MAC */
    if (memcmp(src_mac, PWNAGOTCHI_MAC, 6) == 0) {
        return true;
    }

    /* Method 2: pwngrid custom IE tags (222=payload, 223=compression,
     * 224=identity, 225=signature, 226=stream header) */
    uint16_t pos = 0;
    while (pos + 2 <= ie_len) {
        uint8_t tag = ie[pos];
        uint8_t len = ie[pos + 1];
        pos += 2;
        if (pos + len > ie_len) {
            break;
        }
        if (tag >= 222 && tag <= 226) {
            return true;  /* pwngrid-specific IE found */
        }
        pos += len;
    }

    /* Method 3: plaintext JSON fallback (older or non-pwngrid forks) */
    if (mem_contains(ie, ie_len, "pwnd_tot") ||
        mem_contains(ie, ie_len, "\"identity\"")) {
        return true;
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
 * Record an SSID/BSSID pair.  Sets flags via out parameters:
 *   - evil_twin: same SSID seen from a different BSSID
 *   - karma: same BSSID seen with HG_KARMA_SSID_THRESHOLD+ different SSIDs
 */
static void ap_table_track(const char *ssid, const uint8_t *bssid,
                           bool *evil_twin, bool *karma)
{
    int free_slot = -1;
    bool ssid_from_other_bssid = false;
    int ssids_from_this_bssid = 0;

    for (int i = 0; i < HG_MAX_AP_ENTRIES; i++) {
        if (!s_ap_table[i].used) {
            if (free_slot < 0) {
                free_slot = i;
            }
            continue;
        }
        /* Same SSID + same BSSID = known AP, nothing new */
        if (strcmp(s_ap_table[i].ssid, ssid) == 0 &&
            memcmp(s_ap_table[i].bssid, bssid, 6) == 0) {
            *evil_twin = false;
            *karma = false;
            return;
        }
        /* Same SSID, different BSSID → evil twin */
        if (strcmp(s_ap_table[i].ssid, ssid) == 0) {
            ssid_from_other_bssid = true;
        }
        /* Same BSSID, different SSID → count for karma */
        if (memcmp(s_ap_table[i].bssid, bssid, 6) == 0) {
            ssids_from_this_bssid++;
        }
    }

    /* Insert the new entry */
    if (free_slot >= 0) {
        strncpy(s_ap_table[free_slot].ssid, ssid, HG_MAX_SSID_LEN);
        s_ap_table[free_slot].ssid[HG_MAX_SSID_LEN] = '\0';
        memcpy(s_ap_table[free_slot].bssid, bssid, 6);
        s_ap_table[free_slot].used = true;
        ssids_from_this_bssid++;  /* count the one we just added */
    }

    *evil_twin = ssid_from_other_bssid;
    *karma = (ssids_from_this_bssid >= HG_KARMA_SSID_THRESHOLD);
}

/** Track a beacon source MAC for spam detection. Returns new unique count. */
static uint16_t beacon_mac_track(const uint8_t *mac)
{
    for (int i = 0; i < s_beacon_mac_count; i++) {
        if (memcmp(s_beacon_macs[i], mac, 6) == 0) {
            return s_beacon_mac_count;  /* already known */
        }
    }
    if (s_beacon_mac_count < HG_MAX_BEACON_MACS) {
        memcpy(s_beacon_macs[s_beacon_mac_count], mac, 6);
        s_beacon_mac_count++;
    }
    return s_beacon_mac_count;
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

    /* ── Deauth ───────────────────────────────────────────────────────────── */
    if (subtype == SUBTYPE_DEAUTH) {
        portENTER_CRITICAL_ISR(&s_counter_mux);
        s_deauth++;
        portEXIT_CRITICAL_ISR(&s_counter_mux);
        return;
    }

    /* ── Disassoc ─────────────────────────────────────────────────────────── */
    if (subtype == SUBTYPE_DISASSOC) {
        portENTER_CRITICAL_ISR(&s_counter_mux);
        s_disassoc++;
        portEXIT_CRITICAL_ISR(&s_counter_mux);
        return;
    }

    /* ── Probe request flood ──────────────────────────────────────────────── */
    if (subtype == SUBTYPE_PROBE_REQ) {
        portENTER_CRITICAL_ISR(&s_counter_mux);
        s_probe_requests++;
        portEXIT_CRITICAL_ISR(&s_counter_mux);
        return;
    }

    /* ── Pwnagotchi scan across ALL management frame types ──────────────── */
    /* Pwnagotchi identity might arrive as beacon, probe response, or other.
     * Scan any management frame large enough to have an IE section. */
    if (frame_len > BEACON_IE_OFFSET) {
        const uint8_t *any_src = &frame[10];
        /* Skip our own frames */
        if (memcmp(any_src, SELF_MAC, 6) != 0) {
            const uint8_t *any_ie = &frame[BEACON_IE_OFFSET];
            uint16_t any_ie_len = frame_len - BEACON_IE_OFFSET;
            if (is_pwnagotchi_beacon(any_src, any_ie, any_ie_len)) {
                ESP_LOGW(TAG, "PWNAGOTCHI in mgmt subtype=0x%02X from "
                         "%02X:%02X:%02X:%02X:%02X:%02X",
                         subtype, any_src[0], any_src[1], any_src[2],
                         any_src[3], any_src[4], any_src[5]);
                portENTER_CRITICAL_ISR(&s_counter_mux);
                s_flags |= HG_FLAG_PWNAGOTCHI;
                portEXIT_CRITICAL_ISR(&s_counter_mux);
            }
        }
    }

    /* ── Beacon analysis ──────────────────────────────────────────────────── */
    if (subtype != SUBTYPE_BEACON || frame_len <= BEACON_IE_OFFSET) {
        return;
    }

    const uint8_t *src_addr = &frame[10];
    const uint8_t *bssid    = &frame[16];
    const uint8_t *ie_start = &frame[BEACON_IE_OFFSET];
    uint16_t       ie_len   = frame_len - BEACON_IE_OFFSET;

    /* Skip our own beacons to avoid self-detection */
    if (memcmp(src_addr, SELF_MAC, 6) == 0) {
        return;
    }

    char ssid[HG_MAX_SSID_LEN + 1] = {0};
    uint8_t ssid_len = ie_get_ssid(ie_start, ie_len, ssid, sizeof(ssid));

    /* Pwnagotchi detection (already handled above for all mgmt frames,
     * but we still need the is_pwn flag to skip pineapple OUI check) */
    bool is_pwn = is_pwnagotchi_beacon(src_addr, ie_start, ie_len);

    /* Pineapple OUI detection — skip if already identified as pwnagotchi,
     * since the well-known pwnagotchi MAC (DE:AD:BE:...) matches the
     * spoofed/unassigned OUI entry. */
    if (!is_pwn && is_pineapple_oui(src_addr)) {
        portENTER_CRITICAL_ISR(&s_counter_mux);
        s_flags |= HG_FLAG_PINEAPPLE;
        portEXIT_CRITICAL_ISR(&s_counter_mux);
    }

    /* Beacon spam: track unique source MACs */
    beacon_mac_track(src_addr);

    /* Evil twin + karma detection */
    if (ssid_len > 0) {
        bool evil_twin = false;
        bool karma = false;
        ap_table_track(ssid, bssid, &evil_twin, &karma);

        if (evil_twin || karma) {
            portENTER_CRITICAL_ISR(&s_counter_mux);
            if (evil_twin) s_flags |= HG_FLAG_EVIL_TWIN;
            if (karma)     s_flags |= HG_FLAG_KARMA;
            portEXIT_CRITICAL_ISR(&s_counter_mux);
        }
    }
}

/* ── Public API ───────────────────────────────────────────────────────────── */

void wifi_sniffer_init(void)
{
    memset(s_ap_table, 0, sizeof(s_ap_table));
    memset(s_beacon_macs, 0, sizeof(s_beacon_macs));
    s_beacon_mac_count = 0;

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

uint8_t wifi_sniffer_hop(void)
{
    s_channel = (s_channel % HG_MAX_CHANNEL) + 1;
    esp_wifi_set_channel(s_channel, WIFI_SECOND_CHAN_NONE);
    return s_channel;
}

uint8_t wifi_sniffer_channel(void)
{
    return s_channel;
}

bool wifi_sniffer_has_alert(void)
{
    portENTER_CRITICAL(&s_counter_mux);
    bool alert = (s_flags != 0) ||
                 ((s_deauth + s_disassoc) >= HG_ATTACK_THRESHOLD) ||
                 (s_probe_requests >= HG_PROBE_FLOOD_THRESHOLD);
    portEXIT_CRITICAL(&s_counter_mux);

    if (s_beacon_mac_count >= HG_BEACON_SPAM_THRESHOLD) {
        alert = true;
    }
    return alert;
}

uint16_t wifi_sniffer_peek_flags(void)
{
    portENTER_CRITICAL(&s_counter_mux);
    uint16_t flags = s_flags;
    if ((s_deauth + s_disassoc) >= HG_ATTACK_THRESHOLD) {
        flags |= HG_FLAG_DEAUTH;
    }
    if (s_probe_requests >= HG_PROBE_FLOOD_THRESHOLD) {
        flags |= HG_FLAG_PROBE_FLOOD;
    }
    portEXIT_CRITICAL(&s_counter_mux);

    if (s_beacon_mac_count >= HG_BEACON_SPAM_THRESHOLD) {
        flags |= HG_FLAG_BEACON_SPAM;
    }
    return flags;
}

wifi_report_t wifi_sniffer_collect(bool full_reset)
{
    wifi_report_t r;

    portENTER_CRITICAL(&s_counter_mux);
    r.deauth         = s_deauth;
    r.disassoc       = s_disassoc;
    r.probe_requests = s_probe_requests;
    r.flags          = s_flags;

    /* Evaluate threshold-based flags before resetting counters */
    if ((s_deauth + s_disassoc) >= HG_ATTACK_THRESHOLD) {
        r.flags |= HG_FLAG_DEAUTH;
    }
    if (s_probe_requests >= HG_PROBE_FLOOD_THRESHOLD) {
        r.flags |= HG_FLAG_PROBE_FLOOD;
    }
    if (s_beacon_mac_count >= HG_BEACON_SPAM_THRESHOLD) {
        r.flags |= HG_FLAG_BEACON_SPAM;
    }

    s_deauth         = 0;
    s_disassoc       = 0;
    s_probe_requests = 0;
    s_flags          = 0;
    portEXIT_CRITICAL(&s_counter_mux);

    if (full_reset) {
        /* Reset beacon MAC tracker on the regular interval */
        s_beacon_mac_count = 0;
        memset(s_beacon_macs, 0, sizeof(s_beacon_macs));

        /* Periodically clear the AP table */
        s_collect_count++;
        if (s_collect_count >= 30) {
            s_collect_count = 0;
            memset(s_ap_table, 0, sizeof(s_ap_table));
            ESP_LOGI(TAG, "AP table reset (periodic)");
        }
    }

    return r;
}
