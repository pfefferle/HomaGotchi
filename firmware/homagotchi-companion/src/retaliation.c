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
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_random.h"

static const char *TAG = "retaliate";

/* ── Gotchi identity beacon ────────────────────────────────────────────────── */

/* Source MAC for our pwnagotchi-style beacon */
static const uint8_t GOTCHI_MAC[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};

/* JSON identity payload embedded in a vendor-specific IE */
static const char GOTCHI_IDENTITY[] =
    "{\"name\":\"HomaGotchi\",\"identity\":\"homagotchi\","
    "\"pwnd_tot\":0,\"version\":\"0.5.0\"}";

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
 * Build and transmit a pwnagotchi-style beacon with a vendor IE
 * containing a JSON identity payload.
 */
void retaliation_send_gotchi_beacon(void)
{
    const char *ssid = "HomaGotchi";
    uint8_t ssid_len = (uint8_t)strlen(ssid);
    uint8_t json_len = (uint8_t)strlen(GOTCHI_IDENTITY);

    uint8_t frame[256];
    memset(frame, 0, sizeof(frame));

    frame[0] = 0x80;
    frame[1] = 0x00;
    memset(&frame[4], 0xFF, 6);
    memcpy(&frame[10], GOTCHI_MAC, 6);
    memcpy(&frame[16], GOTCHI_MAC, 6);
    frame[32] = 0x64;
    frame[33] = 0x00;
    frame[34] = 0x01;
    frame[35] = 0x00;

    uint8_t pos = 36;

    /* SSID IE */
    frame[pos++] = 0x00;
    frame[pos++] = ssid_len;
    memcpy(&frame[pos], ssid, ssid_len);
    pos += ssid_len;

    /* DS parameter set */
    frame[pos++] = 0x03;
    frame[pos++] = 0x01;
    frame[pos++] = 0x01;

    /* Vendor-specific IE with JSON identity */
    frame[pos++] = 0xDD;      /* IE tag: vendor specific */
    frame[pos++] = json_len + 3; /* OUI (3) + payload */
    frame[pos++] = 0xDE;      /* OUI bytes (custom) */
    frame[pos++] = 0xAD;
    frame[pos++] = 0x00;
    memcpy(&frame[pos], GOTCHI_IDENTITY, json_len);
    pos += json_len;

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
        } else if (flags & HG_FLAG_DEAUTH) {
            ssid = pick_ssid(SSIDS_DEAUTH, NUM_SSIDS_DEAUTH);
        } else {
            ssid = pick_ssid(SSIDS_GENERIC, NUM_SSIDS_GENERIC);
        }

        send_beacon(ssid, mac);
    }

    ESP_LOGI(TAG, "Fired %d beacons (flags=0x%04X)", burst + 1, flags);
}
