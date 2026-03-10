/**
 * HomaGotchi Companion – BTHome v2 BLE advertiser
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include "wifi_sniffer.h"

/** Initialise BLE and prepare for non-connectable advertising. */
void bthome_init(void);

/** Broadcast a BTHome v2 advertisement with the given report data. */
void bthome_broadcast(const wifi_report_t *report);
