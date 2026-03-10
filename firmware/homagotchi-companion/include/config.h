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

/* Number of SSID/BSSID pairs tracked for evil-twin detection */
#define HG_MAX_AP_ENTRIES     64

/* Maximum SSID length (IEEE 802.11) */
#define HG_MAX_SSID_LEN      32
