/**
 * HomaGotchi Companion – WiFi promiscuous sniffer
 *
 * Detects:
 *   - Deauth frames (subtype 0x0C) with broadcast + reason code analysis
 *   - Disassoc frames (subtype 0x0A)
 *   - Auth floods (subtype 0x0B)
 *   - Pwnagotchi beacons (MAC DE:AD:BE:EF:DE:AD + JSON fallback)
 *   - Evil twin APs (same SSID from different BSSIDs, RSSI-weighted)
 *   - Beacon spam (many unique source MACs, known attack SSIDs, entropy)
 *   - Probe request floods (high rate + MAC churn detection)
 *   - Karma / multi-SSID devices (probe-beacon correlation)
 *   - Pineapple devices (suspicious OUI in beacon source)
 *   - Cross-detector correlation (deauth+evil twin, probe+karma, etc.)
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
#define SUBTYPE_PROBE_RESP 0x05
#define SUBTYPE_BEACON    0x08
#define SUBTYPE_DISASSOC  0x0A
#define SUBTYPE_AUTH      0x0B
#define SUBTYPE_DEAUTH    0x0C

/* Beacon: 24-byte MAC header + 12-byte fixed params = tagged IEs at offset 36 */
#define BEACON_IE_OFFSET  (24 + 12)
#define IE_TAG_SSID       0
#define IE_TAG_VENDOR     221

/* Minimum deauth/disassoc frame length (24 hdr + 2 reason code) */
#define DEAUTH_MIN_LEN    26

/* Pwnagotchi broadcasts from this well-known source MAC */
static const uint8_t PWNAGOTCHI_MAC[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD};

/* Broadcast MAC for deauth target detection */
static const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* Debug: total management frame counter for diagnostics */
static uint32_t s_mgmt_frame_count;
static uint32_t s_dead_frames;  /* frames with DE:AD prefix in source MAC */

/* ── Known attack SSIDs (instant beacon spam flag) ─────────────────────────── */
/* Commonly hardcoded in Marauder, Flipper, Evil-M5, and similar tools.
 * We use substring matching — if the beacon SSID contains one of these
 * strings, flag beacon spam immediately without waiting for threshold. */

static const char *ATTACK_SSID_SUBSTRINGS[] = {
    "Never gonna ",       /* Marauder rick_roll[] */
    "Abraham Linksys",    /* Marauder funny_beacon[] */
    "Benjamin FrankLAN",
    "FBI Surveillance",
    "Martin Router King",
    "404 Wi-Fi Unavailable",
    "Test Wi-Fi Please Ignore",
    "Titanic Syncing",
    "Winternet is Coming",
    "Loading...",
    "Pretty Fly for a Wi-Fi",
    "Wu-Tang LAN",
    "Bill Wi the Science Fi",
    "Drop It Like Its Hotspot",
};
#define NUM_ATTACK_SSIDS (sizeof(ATTACK_SSID_SUBSTRINGS) / sizeof(ATTACK_SSID_SUBSTRINGS[0]))

/* ── Suspicious OUIs for pineapple detection ─────────────────────────────── */
/* Suspicion levels (from ESP32Marauder pineScanSnifferCallback):
 *   ALWAYS    — flag regardless of encryption state
 *   WHEN_OPEN — flag only if beacon has no privacy bit (open network)
 */

#define SUSPICION_ALWAYS    0
#define SUSPICION_WHEN_OPEN 1

typedef struct {
    uint8_t oui[3];
    uint8_t suspicion;
} oui_entry_t;

static const oui_entry_t PINEAPPLE_OUIS[] = {
    /* Hak5 WiFi Pineapple — always suspicious */
    {{0x00, 0x13, 0x37}, SUSPICION_ALWAYS},   /* Hak5 / Orient Power MK7 */
    {{0x02, 0xC0, 0xCA}, SUSPICION_ALWAYS},   /* Hak5 locally-administered */
    {{0x02, 0x13, 0x37}, SUSPICION_ALWAYS},   /* Hak5 locally-administered */
    /* Alfa Inc — common in pentest kits, suspicious when open */
    {{0x00, 0xC0, 0xCA}, SUSPICION_WHEN_OPEN},
    /* Shenzhen Century — pineapple clone hardware */
    {{0x1C, 0xBF, 0xCE}, SUSPICION_ALWAYS},
    /* MediaTek — used in many pentest devices (from Marauder) */
    {{0x00, 0x0C, 0x43}, SUSPICION_WHEN_OPEN},  /* MediaTek Inc */
    {{0x00, 0x0C, 0xE7}, SUSPICION_WHEN_OPEN},  /* MediaTek Inc */
    {{0x00, 0x17, 0xA5}, SUSPICION_WHEN_OPEN},  /* MediaTek Inc */
    /* Panda Wireless — common pentest adapters (from Marauder) */
    {{0x9C, 0xEF, 0xD5}, SUSPICION_ALWAYS},
    {{0x9C, 0xE5, 0xD5}, SUSPICION_ALWAYS},
    /* IEEE registered — used in some attack devices */
    {{0x0C, 0xEF, 0xAF}, SUSPICION_WHEN_OPEN},
    /* Spoofed/unassigned MAC prefix */
    {{0xDE, 0xAD, 0xBE}, SUSPICION_ALWAYS},
    /* GL.iNet — popular portable pentest routers */
    {{0x94, 0x83, 0xC4}, SUSPICION_WHEN_OPEN},
    /* Realtek — RTL8812AU/BU common in pentest USB adapters */
    {{0x00, 0xE0, 0x4C}, SUSPICION_WHEN_OPEN},
    /* Ralink/MediaTek — common in cheap pentest adapters */
    {{0x00, 0x0E, 0x8E}, SUSPICION_WHEN_OPEN},
};

#define NUM_PINEAPPLE_OUIS (sizeof(PINEAPPLE_OUIS) / sizeof(PINEAPPLE_OUIS[0]))

/* ── Counters (protected by spinlock) ─────────────────────────────────────── */

static portMUX_TYPE s_counter_mux = portMUX_INITIALIZER_UNLOCKED;

static uint16_t s_deauth;
static uint16_t s_disassoc;
static uint16_t s_probe_requests;
static uint16_t s_auth_frames;   /* authentication frame counter */
static uint16_t s_flags;  /* bitmask of HG_FLAG_* */

/* ── Evil-twin / karma AP table ───────────────────────────────────────────── */

typedef struct {
    char    ssid[HG_MAX_SSID_LEN + 1];
    uint8_t bssid[6];
    int8_t  rssi;         /* strongest RSSI seen for this SSID/BSSID pair */
    bool    used;
} ap_entry_t;

static ap_entry_t s_ap_table[HG_MAX_AP_ENTRIES];

/* ── Beacon spam: unique source MAC tracker ───────────────────────────────── */

static uint8_t s_beacon_macs[HG_MAX_BEACON_MACS][6];
static uint16_t s_beacon_mac_count;
static uint16_t s_locally_admin_count;  /* MACs with locally-administered bit */

/* ── Beacon spam: unique SSID tracker ─────────────────────────────────────── */
/* Evil-M5 style attacks use softAP with random SSIDs on each iteration.
 * Channel hopping means we miss many MACs, but the same SSID is broadcast
 * on every channel so we're more likely to catch unique SSIDs. */

static char    s_beacon_ssids[HG_MAX_BEACON_SSIDS][HG_MAX_SSID_LEN + 1];
static uint16_t s_beacon_ssid_count;

/* ── Probe flood: unique source MAC tracker (MAC churn detection) ─────────── */

static uint8_t s_probe_macs[HG_MAX_PROBE_MACS][6];
static uint16_t s_probe_mac_count;

/* ── Karma correlation: recent probe SSIDs ring buffer ────────────────────── */
/* Tracks SSIDs from recent probe requests. If a beacon appears with an SSID
 * that was recently probed, it's a strong signal for karma/evil twin. */

static char    s_probe_ssids[HG_MAX_PROBE_SSIDS][HG_MAX_SSID_LEN + 1];
static uint8_t s_probe_ssid_head;   /* next write position */
static uint8_t s_probe_ssid_count;  /* entries used (up to HG_MAX_PROBE_SSIDS) */

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

/**
 * Check if an SSID matches a known attack tool wordlist.
 * Uses substring matching to catch numbered variants ("01 Never gonna...").
 */
static bool is_known_attack_ssid(const char *ssid)
{
    for (int i = 0; i < NUM_ATTACK_SSIDS; i++) {
        if (strstr(ssid, ATTACK_SSID_SUBSTRINGS[i]) != NULL) {
            return true;
        }
    }
    return false;
}

/**
 * Heuristic check for high-entropy (random-looking) SSIDs.
 * Attack tools like Evil-M5 generate random 32-char base62 SSIDs.
 * Returns true if the SSID looks randomly generated.
 *
 * Criteria: length >= HG_ENTROPY_MIN_SSID_LEN, no spaces, and uses
 * at least 3 character classes (upper, lower, digit).
 */
static bool is_high_entropy_ssid(const char *ssid, uint8_t len)
{
    if (len < HG_ENTROPY_MIN_SSID_LEN) {
        return false;
    }

    bool has_upper = false, has_lower = false, has_digit = false;
    bool has_space = false;

    for (uint8_t i = 0; i < len; i++) {
        char c = ssid[i];
        if (c >= 'A' && c <= 'Z') has_upper = true;
        else if (c >= 'a' && c <= 'z') has_lower = true;
        else if (c >= '0' && c <= '9') has_digit = true;
        else if (c == ' ') has_space = true;
    }

    /* Random SSIDs use mixed alphanumeric without spaces */
    int classes = (int)has_upper + (int)has_lower + (int)has_digit;
    return !has_space && classes >= 3;
}

/**
 * Check if a MAC OUI matches any known pineapple device.
 *
 * @param mac        Source MAC address (6 bytes)
 * @param capab_info Capability info from beacon fixed params (bytes 34-35)
 * @param ie         Pointer to tagged IEs
 * @param ie_len     Length of tagged IEs
 * @return true if suspicious device detected
 */
static bool is_pineapple_device(const uint8_t *mac, uint16_t capab_info,
                                const uint8_t *ie, uint16_t ie_len)
{
    bool is_open = !(capab_info & 0x0010);  /* bit 4 = privacy (WEP/WPA) */

    /* Check OUI with suspicion level */
    for (int i = 0; i < NUM_PINEAPPLE_OUIS; i++) {
        if (memcmp(mac, PINEAPPLE_OUIS[i].oui, 3) != 0) {
            continue;
        }
        if (PINEAPPLE_OUIS[i].suspicion == SUSPICION_ALWAYS) {
            return true;
        }
        if (PINEAPPLE_OUIS[i].suspicion == SUSPICION_WHEN_OPEN && is_open) {
            return true;
        }
    }

    /* Capability + tagged parameter minimalism check (from Marauder).
     * Real APs have many IEs (supported rates, HT capabilities, RSN, etc.).
     * Attack devices often have only SSID + DS Parameter Set (2 tags).
     * Combined with minimal capability (0x0001) = high-confidence pineapple. */
    if (capab_info == 0x0001) {
        int ie_count = 0;
        uint16_t pos = 0;
        while (pos + 2 <= ie_len) {
            uint8_t len = ie[pos + 1];
            pos += 2;
            if (pos + len > ie_len) break;
            ie_count++;
            pos += len;
        }
        if (ie_count <= 3) {  /* SSID + DS + maybe one more */
            return true;
        }
    }

    return false;
}

/**
 * Check whether a management frame is from a pwnagotchi.
 *
 * Detection methods (combined from Marauder, minigotchi, and pwngrid source):
 *   1. Well-known source MAC DE:AD:BE:EF:DE:AD (pwngrid BPF filter key).
 *   2. pwngrid IE tag 222 (0xDE) with payload — single tag is sufficient
 *      since no legitimate AP uses this vendor-specific tag number.
 *      Multiple tags (222-226) increase confidence for non-MAC matches.
 *   3. Raw JSON content scan (Marauder approach) — searches for pwnagotchi
 *      JSON fields anywhere in the frame data, regardless of IE structure.
 */
static bool is_pwnagotchi_beacon(const uint8_t *src_mac,
                                  const uint8_t *ie, uint16_t ie_len)
{
    /* Method 1: well-known pwnagotchi MAC — definitive match */
    if (memcmp(src_mac, PWNAGOTCHI_MAC, 6) == 0) {
        return true;
    }

    /* Method 2: pwngrid IE tags (222=payload, 223=compression,
     * 224=identity, 225=signature, 226=stream header).
     * A single IE 222 (payload) is sufficient — this tag is not used by
     * any legitimate AP. For other tags (223-226), require 2+ distinct. */
    uint8_t pwngrid_tags_seen = 0;
    uint8_t pwngrid_tag_mask = 0;  /* bits 0-4 for tags 222-226 */
    uint16_t pos = 0;
    while (pos + 2 <= ie_len) {
        uint8_t tag = ie[pos];
        uint8_t len = ie[pos + 1];
        pos += 2;
        if (pos + len > ie_len) {
            break;
        }
        if (tag >= 222 && tag <= 226) {
            /* IE 222 (payload) alone is definitive */
            if (tag == 222 && len > 10) {
                return true;
            }
            uint8_t bit = 1 << (tag - 222);
            if (!(pwngrid_tag_mask & bit)) {
                pwngrid_tag_mask |= bit;
                pwngrid_tags_seen++;
            }
            if (pwngrid_tags_seen >= 2) {
                return true;
            }
        }
        pos += len;
    }

    /* Method 3: raw JSON content scan (Marauder approach).
     * Only useful if the caller passes correct IE data (beacon/probe resp
     * with ie_offset=36). For other subtypes the "IE" data is actually
     * fixed fields which can contain random byte matches.
     * Requires multiple distinctive keys to reduce false positives. */
    if (ie_len > 50 &&
        mem_contains(ie, ie_len, "pwnd_tot") &&
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
 *   - rssi_suspect: new BSSID has stronger RSSI than original for same SSID
 */
static void ap_table_track(const char *ssid, const uint8_t *bssid, int8_t rssi,
                           bool *evil_twin, bool *karma, bool *rssi_suspect)
{
    int free_slot = -1;
    bool ssid_from_other_bssid = false;
    int ssids_from_this_bssid = 0;
    int8_t original_rssi = -127;  /* RSSI of first BSSID seen with this SSID */

    for (int i = 0; i < HG_MAX_AP_ENTRIES; i++) {
        if (!s_ap_table[i].used) {
            if (free_slot < 0) {
                free_slot = i;
            }
            continue;
        }
        /* Same SSID + same BSSID = known AP, update RSSI */
        if (strcmp(s_ap_table[i].ssid, ssid) == 0 &&
            memcmp(s_ap_table[i].bssid, bssid, 6) == 0) {
            /* Update RSSI to strongest seen */
            if (rssi > s_ap_table[i].rssi) {
                s_ap_table[i].rssi = rssi;
            }
            *evil_twin = false;
            *karma = false;
            *rssi_suspect = false;
            return;
        }
        /* Same SSID, different BSSID → evil twin */
        if (strcmp(s_ap_table[i].ssid, ssid) == 0) {
            ssid_from_other_bssid = true;
            if (s_ap_table[i].rssi > original_rssi) {
                original_rssi = s_ap_table[i].rssi;
            }
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
        s_ap_table[free_slot].rssi = rssi;
        s_ap_table[free_slot].used = true;
        ssids_from_this_bssid++;  /* count the one we just added */
    }

    *evil_twin = ssid_from_other_bssid;
    *karma = (ssids_from_this_bssid >= HG_KARMA_SSID_THRESHOLD);
    /* New BSSID with stronger signal than original = suspicious */
    *rssi_suspect = ssid_from_other_bssid && (rssi > original_rssi + 5);
}

/**
 * Track a beacon source MAC for spam detection.
 * Also tracks locally-administered MACs — attack tools (beacon spam, Flipper,
 * Marauder) use random locally-administered MACs (bit 1 of byte 0 set),
 * while real APs use globally-assigned OUIs.
 * Returns new unique count.
 */
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
        if (mac[0] & 0x02) {  /* locally-administered bit */
            s_locally_admin_count++;
        }
    }
    return s_beacon_mac_count;
}

/**
 * Track a beacon SSID for spam detection.
 * Returns new unique SSID count.
 */
static uint16_t beacon_ssid_track(const char *ssid)
{
    for (int i = 0; i < s_beacon_ssid_count; i++) {
        if (strcmp(s_beacon_ssids[i], ssid) == 0) {
            return s_beacon_ssid_count;  /* already known */
        }
    }
    if (s_beacon_ssid_count < HG_MAX_BEACON_SSIDS) {
        strncpy(s_beacon_ssids[s_beacon_ssid_count], ssid, HG_MAX_SSID_LEN);
        s_beacon_ssids[s_beacon_ssid_count][HG_MAX_SSID_LEN] = '\0';
        s_beacon_ssid_count++;
    }
    return s_beacon_ssid_count;
}

/**
 * Track a probe request source MAC for churn detection.
 * Returns new unique count.
 */
static uint16_t probe_mac_track(const uint8_t *mac)
{
    for (int i = 0; i < s_probe_mac_count; i++) {
        if (memcmp(s_probe_macs[i], mac, 6) == 0) {
            return s_probe_mac_count;
        }
    }
    if (s_probe_mac_count < HG_MAX_PROBE_MACS) {
        memcpy(s_probe_macs[s_probe_mac_count], mac, 6);
        s_probe_mac_count++;
    }
    return s_probe_mac_count;
}

/**
 * Record a probe request SSID into the ring buffer for karma correlation.
 * Called from ISR context — no allocation, just overwrites oldest entry.
 */
static void probe_ssid_record(const char *ssid)
{
    /* Don't record empty/broadcast probes */
    if (ssid[0] == '\0') {
        return;
    }
    /* Check for duplicate */
    for (uint8_t i = 0; i < s_probe_ssid_count; i++) {
        if (strcmp(s_probe_ssids[i], ssid) == 0) {
            return;
        }
    }
    strncpy(s_probe_ssids[s_probe_ssid_head], ssid, HG_MAX_SSID_LEN);
    s_probe_ssids[s_probe_ssid_head][HG_MAX_SSID_LEN] = '\0';
    s_probe_ssid_head = (s_probe_ssid_head + 1) % HG_MAX_PROBE_SSIDS;
    if (s_probe_ssid_count < HG_MAX_PROBE_SSIDS) {
        s_probe_ssid_count++;
    }
}

/**
 * Check if an SSID was recently seen in a probe request.
 * Used for karma correlation: beacon appearing for a recently-probed SSID
 * is a strong indicator of a karma/rogue AP.
 */
static bool probe_ssid_was_seen(const char *ssid)
{
    for (uint8_t i = 0; i < s_probe_ssid_count; i++) {
        if (strcmp(s_probe_ssids[i], ssid) == 0) {
            return true;
        }
    }
    return false;
}

/* ── Promiscuous callback (runs in WiFi task context) ─────────────────────── */

static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t frame_len = pkt->rx_ctrl.sig_len;
    int8_t rssi = pkt->rx_ctrl.rssi;

    /* Debug: scan ENTIRE frame for DE:AD:BE:EF 4-byte pattern.
     * If found at any offset, it means the frame arrived but may be
     * at a different offset than expected (e.g., extra headers). */
    if (frame_len >= 4) {
        for (uint16_t i = 0; i <= frame_len - 4; i++) {
            if (frame[i]   == 0xDE && frame[i+1] == 0xAD &&
                frame[i+2] == 0xBE && frame[i+3] == 0xEF) {
                s_dead_frames++;
                break;  /* count frame only once */
            }
        }
    }

    if (type != WIFI_PKT_MGMT) {
        return;
    }

    uint8_t subtype = (frame[0] >> 4) & 0x0F;

    /* ── Deauth ───────────────────────────────────────────────────────────── */
    if (subtype == SUBTYPE_DEAUTH) {
        portENTER_CRITICAL_ISR(&s_counter_mux);
        s_deauth++;

        /* Broadcast deauths (destination FF:FF:FF:FF:FF:FF) are almost
         * always malicious — legitimate APs deauth specific stations.
         * Flag immediately with a very low threshold. */
        if (frame_len >= 10 &&
            memcmp(&frame[4], BROADCAST_MAC, 6) == 0 &&
            s_deauth >= HG_BROADCAST_DEAUTH_THRESHOLD) {
            s_flags |= HG_FLAG_DEAUTH;
        }

        /* Reason code analysis: attack tools typically use reason 1
         * (unspecified) or 2 (previous auth no longer valid).
         * Legitimate deauths use specific codes like 3, 4, 5, 8.
         * When we see suspicious reason codes, lower the effective
         * threshold by counting them with extra weight. */
        if (frame_len >= DEAUTH_MIN_LEN) {
            uint16_t reason = (uint16_t)frame[24] | ((uint16_t)frame[25] << 8);
            if (reason <= 2) {
                /* Double-count suspicious reason codes */
                s_deauth++;
            }
        }

        portEXIT_CRITICAL_ISR(&s_counter_mux);
        return;
    }

    /* ── Disassoc ─────────────────────────────────────────────────────────── */
    if (subtype == SUBTYPE_DISASSOC) {
        portENTER_CRITICAL_ISR(&s_counter_mux);
        s_disassoc++;

        /* Same broadcast + reason code analysis as deauth */
        if (frame_len >= 10 &&
            memcmp(&frame[4], BROADCAST_MAC, 6) == 0 &&
            (s_deauth + s_disassoc) >= HG_BROADCAST_DEAUTH_THRESHOLD) {
            s_flags |= HG_FLAG_DEAUTH;
        }
        if (frame_len >= DEAUTH_MIN_LEN) {
            uint16_t reason = (uint16_t)frame[24] | ((uint16_t)frame[25] << 8);
            if (reason <= 2) {
                s_disassoc++;
            }
        }

        portEXIT_CRITICAL_ISR(&s_counter_mux);
        return;
    }

    /* ── Auth flood ───────────────────────────────────────────────────────── */
    if (subtype == SUBTYPE_AUTH) {
        portENTER_CRITICAL_ISR(&s_counter_mux);
        s_auth_frames++;
        portEXIT_CRITICAL_ISR(&s_counter_mux);
        return;
    }

    /* ── Probe request: count + MAC churn + SSID recording ────────────────── */
    if (subtype == SUBTYPE_PROBE_REQ) {
        const uint8_t *src = &frame[10];  /* SA */

        portENTER_CRITICAL_ISR(&s_counter_mux);
        s_probe_requests++;
        portEXIT_CRITICAL_ISR(&s_counter_mux);

        /* Track unique source MACs for churn detection */
        probe_mac_track(src);

        /* Record SSID from probe for karma correlation.
         * Probe req IE offset is 24 (no fixed params like beacons). */
        if (frame_len > 24) {
            char probe_ssid[HG_MAX_SSID_LEN + 1] = {0};
            ie_get_ssid(&frame[24], frame_len - 24, probe_ssid, sizeof(probe_ssid));
            if (probe_ssid[0] != '\0') {
                probe_ssid_record(probe_ssid);
            }
        }

        return;
    }

    /* Count total management frames for debug diagnostics */
    s_mgmt_frame_count++;

    /* ── Pwnagotchi scan: beacons and probe responses only ───────────────── */
    /* pwngrid uses beacon frames (subtype 0x08) with IE tags 222-226.
     * Only scan frames where we know the correct IE offset (36 for beacons
     * and probe responses). Scanning other subtypes (auth, action, etc.)
     * causes false positives because their fixed fields have different
     * lengths and the "IE" data is actually something else. */
    if (subtype == SUBTYPE_BEACON || subtype == SUBTYPE_PROBE_RESP) {
        if (frame_len > BEACON_IE_OFFSET) {
            const uint8_t *any_src   = &frame[10];
            const uint8_t *any_bssid = &frame[16];
            const uint8_t *ie = &frame[BEACON_IE_OFFSET];
            uint16_t ie_len = frame_len - BEACON_IE_OFFSET;

            if (is_pwnagotchi_beacon(any_src, ie, ie_len) ||
                is_pwnagotchi_beacon(any_bssid, ie, ie_len)) {
                ESP_LOGW(TAG, "PWNAGOTCHI subtype=0x%02X sa=%02X:%02X:%02X:%02X:%02X:%02X "
                         "bssid=%02X:%02X:%02X:%02X:%02X:%02X",
                         subtype,
                         any_src[0], any_src[1], any_src[2],
                         any_src[3], any_src[4], any_src[5],
                         any_bssid[0], any_bssid[1], any_bssid[2],
                         any_bssid[3], any_bssid[4], any_bssid[5]);
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

    /* No self-filter: our funny-SSID beacons use random MACs (won't collide)
     * and our pwngrid beacons use PWNGRID_MAC (we want to detect real
     * pwnagotchis with the same MAC). ESP32 can't RX during TX anyway. */

    char ssid[HG_MAX_SSID_LEN + 1] = {0};
    uint8_t ssid_len = ie_get_ssid(ie_start, ie_len, ssid, sizeof(ssid));

    /* Pwnagotchi detection (already handled above for all mgmt frames,
     * but we still need the is_pwn flag to skip pineapple OUI check) */
    bool is_pwn = is_pwnagotchi_beacon(src_addr, ie_start, ie_len) ||
                  is_pwnagotchi_beacon(bssid, ie_start, ie_len);

    /* Pineapple detection — OUI check with suspicion levels + capability
     * and tagged parameter analysis (from Marauder pineScanSnifferCallback).
     * Skip if already identified as pwnagotchi. */
    if (!is_pwn) {
        uint16_t capab_info = (uint16_t)frame[34] | ((uint16_t)frame[35] << 8);
        if (is_pineapple_device(src_addr, capab_info, ie_start, ie_len)) {
            portENTER_CRITICAL_ISR(&s_counter_mux);
            s_flags |= HG_FLAG_PINEAPPLE;
            portEXIT_CRITICAL_ISR(&s_counter_mux);
        }
    }

    /* Beacon spam: track unique source MACs and SSIDs.
     * Multiple independent triggers:
     *   1. Many unique MACs with high locally-administered ratio
     *      (Marauder-style: raw beacon injection with random MACs)
     *   2. Many unique SSIDs regardless of MAC count
     *      (Evil-M5 style: softAP rotation with random SSIDs + random MACs
     *       per channel — channel hopping means we miss most MACs but
     *       the same SSID is broadcast on all channels)
     *   3. Known attack SSID from wordlist (instant flag)
     *   4. High-entropy (random-looking) SSID lowers MAC threshold */
    beacon_mac_track(src_addr);
    bool ssid_spam = false;
    if (ssid_len > 0) {
        beacon_ssid_track(ssid);

        /* Instant flag: known attack tool SSID */
        if (is_known_attack_ssid(ssid)) {
            ssid_spam = true;
            ESP_LOGW(TAG, "Known attack SSID: %s", ssid);
        }

        /* High-entropy SSIDs lower the effective MAC threshold.
         * If we see many random-looking SSIDs even with fewer MACs,
         * that's still beacon spam. Use half the normal MAC threshold. */
        if (is_high_entropy_ssid(ssid, ssid_len) &&
            s_beacon_mac_count >= HG_BEACON_SPAM_THRESHOLD / 2) {
            ssid_spam = true;
        }
    }
    if (ssid_spam ||
        (s_beacon_mac_count >= HG_BEACON_SPAM_THRESHOLD &&
         s_locally_admin_count > s_beacon_mac_count / 2) ||
        s_beacon_ssid_count >= HG_BEACON_SSID_SPAM_THRESHOLD) {
        portENTER_CRITICAL_ISR(&s_counter_mux);
        s_flags |= HG_FLAG_BEACON_SPAM;
        portEXIT_CRITICAL_ISR(&s_counter_mux);
    }

    /* Evil twin + karma detection */
    if (ssid_len > 0) {
        bool evil_twin = false;
        bool karma = false;
        bool rssi_suspect = false;
        ap_table_track(ssid, bssid, rssi, &evil_twin, &karma, &rssi_suspect);

        /* Karma correlation: beacon for a recently-probed SSID is suspicious.
         * This catches karma attacks that haven't yet hit the multi-SSID
         * threshold (e.g., responding to probes one at a time). */
        if (!karma && probe_ssid_was_seen(ssid)) {
            /* Only flag if this BSSID has at least 2 SSIDs —
             * a single match could be a legitimate AP. */
            int ssid_count = 0;
            for (int i = 0; i < HG_MAX_AP_ENTRIES; i++) {
                if (s_ap_table[i].used &&
                    memcmp(s_ap_table[i].bssid, bssid, 6) == 0) {
                    ssid_count++;
                }
            }
            if (ssid_count >= 2) {
                karma = true;
                ESP_LOGW(TAG, "Karma correlation: beacon SSID '%s' was recently probed", ssid);
            }
        }

        if (evil_twin || karma) {
            portENTER_CRITICAL_ISR(&s_counter_mux);
            if (evil_twin) {
                s_flags |= HG_FLAG_EVIL_TWIN;
                if (rssi_suspect) {
                    ESP_LOGW(TAG, "Evil twin RSSI suspect: '%s' stronger from new BSSID", ssid);
                }
            }
            if (karma) s_flags |= HG_FLAG_KARMA;
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
    s_locally_admin_count = 0;
    memset(s_beacon_ssids, 0, sizeof(s_beacon_ssids));
    s_beacon_ssid_count = 0;
    memset(s_probe_macs, 0, sizeof(s_probe_macs));
    s_probe_mac_count = 0;
    memset(s_probe_ssids, 0, sizeof(s_probe_ssids));
    s_probe_ssid_head = 0;
    s_probe_ssid_count = 0;

    esp_netif_init();
    esp_event_loop_create_default();

    /* Match Marauder's custom cfg2 for single-band ESP32-S3 boards.
     * Key differences from WIFI_INIT_CONFIG_DEFAULT():
     *   - ampdu_rx/tx disabled (avoids frame aggregation issues)
     *   - nano format enabled (optimized frame encoding)
     *   - nvs disabled (RAM-only storage)
     *   - csi disabled (not needed for monitoring)
     * See ESP32Marauder WiFiScan.h lines 728-752 */
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    cfg.ampdu_rx_enable = 0;
    cfg.ampdu_tx_enable = 0;
    cfg.amsdu_tx_enable = 0;
    cfg.nvs_enable = 0;
    cfg.nano_enable = WIFI_NANO_FORMAT_ENABLED;
    cfg.csi_enable = 0;
    cfg.static_rx_buf_num = 6;
    cfg.dynamic_rx_buf_num = 6;
    cfg.rx_ba_win = 6;
    cfg.static_tx_buf_num = 1;
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);  /* STA mode needed for esp_wifi_80211_tx() */
    esp_wifi_start();

    esp_wifi_set_promiscuous_rx_cb(sniffer_cb);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA,
    };
    esp_wifi_set_promiscuous_filter(&filter);

    esp_wifi_set_promiscuous(true);
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
                 (s_probe_requests >= HG_PROBE_FLOOD_THRESHOLD) ||
                 (s_auth_frames >= HG_AUTH_FLOOD_THRESHOLD);
    portEXIT_CRITICAL(&s_counter_mux);

    if (s_beacon_mac_count >= HG_BEACON_SPAM_THRESHOLD ||
        s_beacon_ssid_count >= HG_BEACON_SSID_SPAM_THRESHOLD) {
        alert = true;
    }
    if (s_probe_mac_count >= HG_PROBE_MAC_CHURN_THRESHOLD) {
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
    if (s_auth_frames >= HG_AUTH_FLOOD_THRESHOLD) {
        flags |= HG_FLAG_AUTH_FLOOD;
    }
    portEXIT_CRITICAL(&s_counter_mux);

    if (s_beacon_mac_count >= HG_BEACON_SPAM_THRESHOLD ||
        s_beacon_ssid_count >= HG_BEACON_SSID_SPAM_THRESHOLD) {
        flags |= HG_FLAG_BEACON_SPAM;
    }
    if (s_probe_mac_count >= HG_PROBE_MAC_CHURN_THRESHOLD) {
        flags |= HG_FLAG_PROBE_FLOOD;
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
    if (s_auth_frames >= HG_AUTH_FLOOD_THRESHOLD) {
        r.flags |= HG_FLAG_AUTH_FLOOD;
    }
    if (s_beacon_mac_count >= HG_BEACON_SPAM_THRESHOLD ||
        s_beacon_ssid_count >= HG_BEACON_SSID_SPAM_THRESHOLD) {
        r.flags |= HG_FLAG_BEACON_SPAM;
    }
    /* MAC churn in probes also triggers probe flood */
    if (s_probe_mac_count >= HG_PROBE_MAC_CHURN_THRESHOLD) {
        r.flags |= HG_FLAG_PROBE_FLOOD;
    }

    /* ── Cross-detector correlation ──────────────────────────────────────── */
    /* Certain flag combinations are much more suspicious together.
     * When correlated attacks appear, ensure all constituent flags are set
     * even if individual thresholds are marginal.
     *
     * Deauth + Evil Twin = active attack (deauth clients, clone AP)
     * Probe flood + Karma = karma attack in progress
     * Pwnagotchi + Deauth = pwnagotchi actively hunting */
    if ((r.flags & HG_FLAG_DEAUTH) && (r.flags & HG_FLAG_EVIL_TWIN)) {
        ESP_LOGW(TAG, "CORRELATED: deauth + evil twin = active AP attack");
    }
    if ((r.flags & HG_FLAG_PROBE_FLOOD) && (r.flags & HG_FLAG_KARMA)) {
        ESP_LOGW(TAG, "CORRELATED: probe flood + karma = karma attack");
    }
    if ((r.flags & HG_FLAG_PWNAGOTCHI) && (r.flags & HG_FLAG_DEAUTH)) {
        ESP_LOGW(TAG, "CORRELATED: pwnagotchi + deauth = active hunting");
    }

    uint32_t mgmt_total = s_mgmt_frame_count;
    uint32_t dead_total = s_dead_frames;

    s_deauth         = 0;
    s_disassoc       = 0;
    s_probe_requests = 0;
    s_auth_frames    = 0;
    s_flags          = 0;
    s_mgmt_frame_count = 0;
    s_dead_frames    = 0;
    portEXIT_CRITICAL(&s_counter_mux);

    ESP_LOGI(TAG, "collect: mgmt=%lu dead=%lu beaconMACs=%u localAdmin=%u "
             "beaconSSIDs=%u probeMACs=%u ch=%u",
             (unsigned long)mgmt_total, (unsigned long)dead_total,
             s_beacon_mac_count, s_locally_admin_count,
             s_beacon_ssid_count, s_probe_mac_count, s_channel);

    if (full_reset) {
        /* Reset beacon MAC and SSID trackers on the regular interval */
        s_beacon_mac_count = 0;
        s_locally_admin_count = 0;
        memset(s_beacon_macs, 0, sizeof(s_beacon_macs));
        s_beacon_ssid_count = 0;
        memset(s_beacon_ssids, 0, sizeof(s_beacon_ssids));

        /* Reset probe MAC churn tracker */
        s_probe_mac_count = 0;
        memset(s_probe_macs, 0, sizeof(s_probe_macs));

        /* Periodically clear the AP table and probe SSID ring buffer */
        s_collect_count++;
        if (s_collect_count >= 30) {
            s_collect_count = 0;
            memset(s_ap_table, 0, sizeof(s_ap_table));
            memset(s_probe_ssids, 0, sizeof(s_probe_ssids));
            s_probe_ssid_head = 0;
            s_probe_ssid_count = 0;
            ESP_LOGI(TAG, "AP table + probe SSID buffer reset (periodic)");
        }
    }

    return r;
}
