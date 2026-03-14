/**
 * HomaGotchi Companion – configuration
 * SPDX-License-Identifier: MIT
 */

#pragma once

/* BLE device name – must start with "Gotchi" for HomaGotchi to recognise it */
#define HG_DEVICE_NAME        "Gotchi"

/* How often (ms) to broadcast a BTHome report */
#define HG_REPORT_INTERVAL_MS 10000

/* How often (ms) to hop to the next WiFi channel */
#define HG_CHANNEL_HOP_MS     500

/* Max WiFi channel to scan (13 for most regions, 11 for US) */
#define HG_MAX_CHANNEL        13

/* Deauth + disassoc frames per interval to flag an attack */
#define HG_ATTACK_THRESHOLD   5

/* Broadcast deauths (to FF:FF:FF:FF:FF:FF) are almost always malicious.
 * Flag immediately when this many broadcast deauths are seen. */
#define HG_BROADCAST_DEAUTH_THRESHOLD 2

/* Probe requests per interval to flag a probe flood */
#define HG_PROBE_FLOOD_THRESHOLD 50

/* Unique probe source MACs per interval — high churn means MAC randomization
 * attack (Evil-M5 changes MAC every 500ms).  Lower threshold than probe count
 * because MAC diversity is a stronger signal. */
#define HG_PROBE_MAC_CHURN_THRESHOLD 20

/* Max probe source MACs to track per interval */
#define HG_MAX_PROBE_MACS     32

/* Unique beacon source MACs per interval to flag beacon spam */
#define HG_BEACON_SPAM_THRESHOLD 30

/* Unique SSIDs from one BSSID to flag karma / multi-SSID device */
#define HG_KARMA_SSID_THRESHOLD  3

/* Number of beacon frames per retaliation burst */
#define HG_RETALIATION_BURST  5

/* Number of SSID/BSSID pairs tracked for evil-twin detection */
#define HG_MAX_AP_ENTRIES     64

/* Number of unique beacon MACs tracked for beacon spam detection */
#define HG_MAX_BEACON_MACS    64

/* Number of unique beacon SSIDs tracked for beacon spam detection */
#define HG_MAX_BEACON_SSIDS   64

/* Unique beacon SSIDs per interval to flag beacon spam (lower than MAC
 * threshold because channel hopping means we miss many MACs, but SSIDs
 * repeat across channels — catches Evil-M5 style softAP spam) */
#define HG_BEACON_SSID_SPAM_THRESHOLD 15

/* Maximum SSID length (IEEE 802.11) */
#define HG_MAX_SSID_LEN      32

/* Auth frames per interval to flag authentication flood */
#define HG_AUTH_FLOOD_THRESHOLD 20

/* Association requests per interval to flag association flood */
#define HG_ASSOC_FLOOD_THRESHOLD 20

/* EAPOL Logoff frames per interval — extremely rare in normal traffic,
 * so even 1-2 is suspicious.  GhostESP uses these to disconnect 802.1X
 * clients. */
#define HG_EAPOL_LOGOFF_THRESHOLD 2

/* CTS-to-self frames with large NAV per interval to flag RTS/CTS attack.
 * Normal CTS traffic is low-rate and short-duration.  Attack tools flood
 * CTS frames with high duration values to silence the channel. */
#define HG_RTS_CTS_THRESHOLD  5

/* NAV/duration value in microseconds above which a CTS frame is suspicious.
 * Normal CTS-to-self uses ~5ms.  Attack tools set 30ms+ to reserve channel. */
#define HG_RTS_CTS_NAV_THRESHOLD 15000

/* SAE authentication commit frames per interval — flood targets WPA3 APs
 * with expensive elliptic curve computations (Dragonblood attack). */
#define HG_SAE_FLOOD_THRESHOLD 10

/* Recent probe SSIDs to track for karma correlation (ring buffer) */
#define HG_MAX_PROBE_SSIDS    16

/* Minimum SSID length to evaluate for entropy (random-looking SSIDs) */
#define HG_ENTROPY_MIN_SSID_LEN 15

/* ── Detection flag bits (shared with HA integration) ─────────────────────── */

#define HG_FLAG_DEAUTH        (1 << 0)
#define HG_FLAG_PWNAGOTCHI    (1 << 1)
#define HG_FLAG_EVIL_TWIN     (1 << 2)
#define HG_FLAG_BEACON_SPAM   (1 << 3)
#define HG_FLAG_PROBE_FLOOD   (1 << 4)
#define HG_FLAG_KARMA         (1 << 5)
#define HG_FLAG_PINEAPPLE     (1 << 6)
#define HG_FLAG_RETALIATION   (1 << 7)
#define HG_FLAG_AUTH_FLOOD    (1 << 8)
#define HG_FLAG_ASSOC_FLOOD   (1 << 9)
#define HG_FLAG_EAPOL_LOGOFF  (1 << 10)
#define HG_FLAG_RTS_CTS       (1 << 11)
#define HG_FLAG_SAE_FLOOD     (1 << 12)
