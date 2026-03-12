/**
 * HomaGotchi Companion – Defensive retaliation
 *
 * When attacks are detected, broadcasts pwnagotchi-style beacons and
 * funny SSID beacons as a visible deterrent.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

/** Initialise retaliation subsystem (call after wifi_sniffer_init). */
void retaliation_init(void);

/**
 * Fire a defensive burst based on the current threat flags.
 * Call from the monitor loop when an attack is detected.
 *
 * @param flags  Current HG_FLAG_* bitmask.
 */
void retaliation_fire(uint16_t flags);
