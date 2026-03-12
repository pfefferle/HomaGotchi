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

/* Probe requests per interval to flag a probe flood */
#define HG_PROBE_FLOOD_THRESHOLD 50

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

/* Maximum SSID length (IEEE 802.11) */
#define HG_MAX_SSID_LEN      32

/* ── Detection flag bits (shared with HA integration) ─────────────────────── */

#define HG_FLAG_DEAUTH        (1 << 0)
#define HG_FLAG_PWNAGOTCHI    (1 << 1)
#define HG_FLAG_EVIL_TWIN     (1 << 2)
#define HG_FLAG_BEACON_SPAM   (1 << 3)
#define HG_FLAG_PROBE_FLOOD   (1 << 4)
#define HG_FLAG_KARMA         (1 << 5)
#define HG_FLAG_PINEAPPLE     (1 << 6)
#define HG_FLAG_RETALIATION   (1 << 7)
