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
    bool     pwnagotchi;
    bool     evil_twin;
} wifi_report_t;

/** Initialise WiFi in promiscuous mode on channel 1. */
void wifi_sniffer_init(void);

/** Hop to the next channel (wraps at HG_MAX_CHANNEL). */
void wifi_sniffer_hop(void);

/**
 * Collect accumulated detections and reset the counters.
 * Thread-safe: uses a spinlock to synchronise with the promiscuous callback.
 */
wifi_report_t wifi_sniffer_collect(void);
