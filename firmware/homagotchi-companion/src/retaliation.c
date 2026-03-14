/**
 * HomaGotchi Companion – Defensive retaliation
 *
 * Broadcasts beacon frames with funny SSIDs and a pwnagotchi identity
 * as a visible, non-destructive deterrent when attacks are detected.
 *
 * Uses esp_wifi_80211_tx() to inject raw management frames while
 * promiscuous mode stays active for monitoring.
 *
 * SPDX-License-Identifier: MIT
 */

#include "retaliation.h"
#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"

static const char *TAG = "retaliate";

/* ── Gotchi identity beacon ────────────────────────────────────────────────── */

/*
 * pwngrid peer advertisement format:
 *   - Beacon frame (0x80) with Address2 = DE:AD:BE:EF:DE:AD
 *   - Address3 = our unique session ID
 *   - Beacon interval 100, capability 0x0411
 *   - IE tag 222 (0xDE) with uncompressed JSON payload chunks (max 255 bytes)
 *   - No compression, no signature, no IE 224/225/226 for broadcasts
 */

/* Well-known pwnagotchi MAC — pwngrid filters on this in Address2 */
static const uint8_t PWNGRID_MAC[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD};

/* Our unique session ID (Address3) */
static const uint8_t SESSION_MAC[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};

/* pwngrid IE tag for JSON payload chunks */
#define IE_PWNGRID_PAYLOAD  222  /* 0xDE */

/* JSON identity template (pwngrid format).
 * Fields match what real pwngrid advertises:
 *   name, version, identity (64-char hex fingerprint), session_id,
 *   grid_version, epoch, pwnd_run, pwnd_tot, uptime, face, timestamp
 * The timestamp is set at runtime. */
static const char GOTCHI_IDENTITY_FMT[] =
    "{\"name\":\"HomaGotchi\",\"version\":\"0.5.0\","
    "\"identity\":\"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\","
    "\"session_id\":\"de:ad:be:ef:ca:fe\","
    "\"grid_version\":\"1.10.6\","
    "\"epoch\":1,\"pwnd_run\":0,\"pwnd_tot\":0,"
    "\"uptime\":%lu,\"face\":\"(◕‿‿◕)\","
    "\"timestamp\":%lu}";

/* ── Funny SSID pools (picked by threat type) ─────────────────────────────── */

static const char *SSIDS_DEAUTH[] = {
    "Stop deauthing me >:(",
    "Deauth this, nerd",
    "I see your deauths",
    "Gotchi is watching you",
    "Nice deauth bro",
    "WiFi police: stand down",
};
#define NUM_SSIDS_DEAUTH (sizeof(SSIDS_DEAUTH) / sizeof(SSIDS_DEAUTH[0]))

static const char *SSIDS_FLIPPER[] = {
    "Flipper detected lol",
    "Nice dolphin you got there",
    "Flipper go home",
    "I see your Flipper Zero",
    "Dolphins belong in the sea",
};
#define NUM_SSIDS_FLIPPER (sizeof(SSIDS_FLIPPER) / sizeof(SSIDS_FLIPPER[0]))

static const char *SSIDS_PWNAGOTCHI[] = {
    "Hello fren! (o_o)",
    "Gotchi handshake?",
    "Peers: +1",
    "HomaGotchi says hi",
    "pwn buddies 4ever",
};
#define NUM_SSIDS_PWNAGOTCHI (sizeof(SSIDS_PWNAGOTCHI) / sizeof(SSIDS_PWNAGOTCHI[0]))

static const char *SSIDS_EVIL_TWIN[] = {
    "The real AP is here ->",
    "Trust issues detected",
    "Evil twin spotted",
    "Nice try, rogue AP",
};
#define NUM_SSIDS_EVIL_TWIN (sizeof(SSIDS_EVIL_TWIN) / sizeof(SSIDS_EVIL_TWIN[0]))

static const char *SSIDS_AUTH_FLOOD[] = {
    "Auth flood detected!",
    "Stop brute forcing me",
    "Your auth attempts are logged",
    "EAPOL? More like E-A-NO-L",
};
#define NUM_SSIDS_AUTH_FLOOD (sizeof(SSIDS_AUTH_FLOOD) / sizeof(SSIDS_AUTH_FLOOD[0]))

static const char *SSIDS_EAPOL[] = {
    "EAPOL logoff? Really?",
    "802.1X says NO",
    "Your logoff is logged",
    "Enterprise WiFi fights back",
};
#define NUM_SSIDS_EAPOL (sizeof(SSIDS_EAPOL) / sizeof(SSIDS_EAPOL[0]))

static const char *SSIDS_RTS_CTS[] = {
    "CTS denied, punk",
    "Channel is mine, not yours",
    "NAV abuse detected",
    "Virtual carrier sense attack? LOL",
};
#define NUM_SSIDS_RTS_CTS (sizeof(SSIDS_RTS_CTS) / sizeof(SSIDS_RTS_CTS[0]))

static const char *SSIDS_SAE[] = {
    "WPA3 DoS? Nice try",
    "Dragonblood detected",
    "SAE commit spam logged",
    "Your dragon has been slain",
};
#define NUM_SSIDS_SAE (sizeof(SSIDS_SAE) / sizeof(SSIDS_SAE[0]))

static const char *SSIDS_GENERIC[] = {
    "HomaGotchi is watching",
    "Nothing to see here",
    "This network fights back",
    "Monitored by HomaGotchi",
    "Get off my LAN",
    "Hack somewhere else",
};
#define NUM_SSIDS_GENERIC (sizeof(SSIDS_GENERIC) / sizeof(SSIDS_GENERIC[0]))

/* ── Raw 802.11 beacon frame builder ──────────────────────────────────────── */

/**
 * Build and transmit a beacon frame with a given SSID.
 * Uses a random BSSID for each beacon to avoid polluting AP tables.
 */
static void send_beacon(const char *ssid, const uint8_t *src_mac)
{
    uint8_t ssid_len = (uint8_t)strlen(ssid);
    if (ssid_len > 32) {
        ssid_len = 32;
    }

    /*
     * Beacon frame layout:
     *   [0..1]   Frame control (0x80 0x00 = beacon)
     *   [2..3]   Duration
     *   [4..9]   Destination (broadcast)
     *   [10..15] Source address
     *   [16..21] BSSID
     *   [22..23] Sequence control
     *   [24..31] Timestamp (8 bytes, zeroed)
     *   [32..33] Beacon interval (100 TU = 0x0064)
     *   [34..35] Capability info
     *   [36..]   Tagged parameters (SSID IE + DS parameter set)
     */

    uint8_t frame[128];
    memset(frame, 0, sizeof(frame));

    /* Frame control: beacon */
    frame[0] = 0x80;
    frame[1] = 0x00;

    /* Destination: broadcast */
    memset(&frame[4], 0xFF, 6);

    /* Source address */
    memcpy(&frame[10], src_mac, 6);

    /* BSSID = source */
    memcpy(&frame[16], src_mac, 6);

    /* Beacon interval: 100 TU */
    frame[32] = 0x64;
    frame[33] = 0x00;

    /* Capability: ESS */
    frame[34] = 0x01;
    frame[35] = 0x00;

    uint8_t pos = 36;

    /* SSID IE */
    frame[pos++] = 0x00;       /* IE tag: SSID */
    frame[pos++] = ssid_len;
    memcpy(&frame[pos], ssid, ssid_len);
    pos += ssid_len;

    /* DS parameter set (channel 1) */
    frame[pos++] = 0x03;  /* IE tag: DS Parameter Set */
    frame[pos++] = 0x01;
    frame[pos++] = 0x01;  /* channel */

    esp_wifi_80211_tx(WIFI_IF_STA, frame, pos, false);
}

/**
 * Build and transmit a pwngrid-compatible beacon frame.
 *
 * pwngrid's BPF filter: "type mgt subtype beacon and ether src de:ad:be:ef:de:ad"
 * So we MUST use a beacon frame (0x80) with Address2 = DE:AD:BE:EF:DE:AD.
 * Address3 carries our unique session ID for peer differentiation.
 * The JSON identity is sent as one or more IE 222 (0xDE) chunks (max 255 bytes).
 */
void retaliation_send_gotchi_beacon(void)
{
    /* Build JSON payload with dynamic uptime and timestamp.
     * pwngrid adds "timestamp" at send time; real pwnagotchis
     * also send uptime in seconds. */
    char json_buf[384];
    unsigned long uptime_s = (unsigned long)(esp_timer_get_time() / 1000000ULL);
    unsigned long timestamp = uptime_s;  /* no RTC — use uptime as epoch proxy */
    int json_total = snprintf(json_buf, sizeof(json_buf), GOTCHI_IDENTITY_FMT,
                              uptime_s, timestamp);
    if (json_total < 0 || json_total >= (int)sizeof(json_buf)) {
        ESP_LOGE(TAG, "JSON overflow");
        return;
    }

    /*
     * Beacon frame layout:
     *   [0..1]   Frame control (0x80 0x00 = beacon)
     *   [2..3]   Duration
     *   [4..9]   Address1 = destination (broadcast)
     *   [10..15] Address2 = source (MUST be DE:AD:BE:EF:DE:AD for pwngrid BPF)
     *   [16..21] Address3 = BSSID (our session ID, per pwngrid protocol)
     *   [22..23] Sequence control
     *   [24..31] Timestamp (8 bytes, zeroed — filled by hardware)
     *   [32..33] Beacon interval (100 TU)
     *   [34..35] Capability info (0x0411 = ESS + short preamble + short slot)
     *   [36..]   Tagged parameters
     */

    uint8_t frame[512];
    memset(frame, 0, sizeof(frame));

    /* Frame control: beacon */
    frame[0] = 0x80;
    frame[1] = 0x00;

    /* Address1: broadcast */
    memset(&frame[4], 0xFF, 6);

    /* Address2: well-known pwngrid MAC (BPF filter matches on this) */
    memcpy(&frame[10], PWNGRID_MAC, 6);

    /* Address3: our unique session ID (per pwngrid protocol).
     * pwngrid uses Address3 as the peer's SessionID for differentiation.
     * It skips frames where Address3 == own SessionID (self-filter). */
    memcpy(&frame[16], SESSION_MAC, 6);

    /* Beacon interval: 100 TU */
    frame[32] = 0x64;
    frame[33] = 0x00;

    /* Capability: 0x0411 (matches real pwnagotchi beacons) */
    frame[34] = 0x11;
    frame[35] = 0x04;

    uint16_t pos = 36;

    /* SSID IE: empty (hidden network — pwngrid ignores SSID) */
    frame[pos++] = 0x00;  /* IE tag: SSID */
    frame[pos++] = 0x00;  /* length: 0 */

    /* IE 222 (0xDE): JSON payload chunks, max 255 bytes each.
     * pwngrid reassembles multiple IE 222 tags in order. */
    int offset = 0;
    while (offset < json_total) {
        int chunk = json_total - offset;
        if (chunk > 255) {
            chunk = 255;
        }
        frame[pos++] = IE_PWNGRID_PAYLOAD;   /* 0xDE */
        frame[pos++] = (uint8_t)chunk;
        memcpy(&frame[pos], json_buf + offset, chunk);
        pos += (uint16_t)chunk;
        offset += chunk;
    }

    esp_wifi_80211_tx(WIFI_IF_STA, frame, pos, false);
}

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static const char *pick_ssid(const char **pool, int count)
{
    return pool[esp_random() % count];
}

static void random_mac(uint8_t *mac)
{
    uint32_t r1 = esp_random();
    uint32_t r2 = esp_random();
    mac[0] = (uint8_t)((r1 >> 0) & 0xFE) | 0x02;  /* locally administered */
    mac[1] = (uint8_t)(r1 >> 8);
    mac[2] = (uint8_t)(r1 >> 16);
    mac[3] = (uint8_t)(r1 >> 24);
    mac[4] = (uint8_t)(r2 >> 0);
    mac[5] = (uint8_t)(r2 >> 8);
}

/* ── Public API ───────────────────────────────────────────────────────────── */

void retaliation_init(void)
{
    ESP_LOGI(TAG, "Retaliation subsystem ready");
}

void retaliation_fire(uint16_t flags)
{
    if (flags == 0) {
        return;
    }

    uint8_t mac[6];
    const char *ssid;
    int burst = HG_RETALIATION_BURST;

    /* Always send a gotchi identity beacon when retaliating */
    retaliation_send_gotchi_beacon();

    /* Pick SSIDs based on what was detected.
     * More specific flags (pwnagotchi, evil twin) are checked before
     * generic ones (deauth) so they aren't shadowed by co-occurring flags. */
    for (int i = 0; i < burst; i++) {
        random_mac(mac);

        if (flags & HG_FLAG_PWNAGOTCHI) {
            ssid = pick_ssid(SSIDS_PWNAGOTCHI, NUM_SSIDS_PWNAGOTCHI);
        } else if (flags & HG_FLAG_EVIL_TWIN) {
            ssid = pick_ssid(SSIDS_EVIL_TWIN, NUM_SSIDS_EVIL_TWIN);
        } else if (flags & HG_FLAG_PINEAPPLE) {
            ssid = pick_ssid(SSIDS_FLIPPER, NUM_SSIDS_FLIPPER);
        } else if (flags & HG_FLAG_SAE_FLOOD) {
            ssid = pick_ssid(SSIDS_SAE, NUM_SSIDS_SAE);
        } else if (flags & HG_FLAG_EAPOL_LOGOFF) {
            ssid = pick_ssid(SSIDS_EAPOL, NUM_SSIDS_EAPOL);
        } else if (flags & HG_FLAG_RTS_CTS) {
            ssid = pick_ssid(SSIDS_RTS_CTS, NUM_SSIDS_RTS_CTS);
        } else if (flags & HG_FLAG_AUTH_FLOOD) {
            ssid = pick_ssid(SSIDS_AUTH_FLOOD, NUM_SSIDS_AUTH_FLOOD);
        } else if (flags & HG_FLAG_DEAUTH) {
            ssid = pick_ssid(SSIDS_DEAUTH, NUM_SSIDS_DEAUTH);
        } else {
            ssid = pick_ssid(SSIDS_GENERIC, NUM_SSIDS_GENERIC);
        }

        send_beacon(ssid, mac);
    }

    ESP_LOGI(TAG, "Fired %d beacons (flags=0x%04X)", burst + 1, flags);
}
