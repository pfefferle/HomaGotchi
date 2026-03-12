/**
 * HomaGotchi Companion – WiFi promiscuous sniffer
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/** Snapshot of detections since the last report. */
typedef struct {
    uint16_t deauth;
    uint16_t disassoc;
    uint16_t probe_requests;
    uint16_t flags;  /* bitmask of HG_FLAG_* from config.h */
} wifi_report_t;

/** Initialise WiFi in promiscuous mode on channel 1. */
void wifi_sniffer_init(void);

/** Hop to the next channel (wraps at HG_MAX_CHANNEL). Returns new channel. */
uint8_t wifi_sniffer_hop(void);

/** Return the current WiFi channel. */
uint8_t wifi_sniffer_channel(void);

/**
 * Collect accumulated detections and reset the counters.
 * Thread-safe: uses a spinlock to synchronise with the promiscuous callback.
 *
 * @param full_reset  If true, also resets the beacon MAC tracker and advances
 *                    the AP table aging counter.  Pass true for the regular
 *                    interval, false for urgent mid-interval collects.
 */
wifi_report_t wifi_sniffer_collect(bool full_reset);

/**
 * Check whether any attack flags have been set since last collect.
 * Non-destructive read — does not reset counters.
 */
bool wifi_sniffer_has_alert(void);

/** Peek at the current flags bitmask without resetting. */
uint16_t wifi_sniffer_peek_flags(void);
