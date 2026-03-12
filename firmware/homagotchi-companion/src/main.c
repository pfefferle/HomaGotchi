/**
 * HomaGotchi Companion – entry point
 *
 * Passive WiFi monitor that reports attacks via BTHome v2 BLE advertisements.
 * Broadcasts immediately when an attack is detected, otherwise every 10 s.
 *
 * SPDX-License-Identifier: MIT
 */

#include "config.h"
#include "wifi_sniffer.h"
#include "bthome.h"
#include "retaliation.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"

static const char *TAG = "main";

static void monitor_task(void *arg)
{
    (void)arg;

    TickType_t last_report = xTaskGetTickCount();
    TickType_t last_urgent = 0;
    TickType_t last_hop    = last_report;
    uint16_t   prev_flags  = 0;

    /* Initial broadcast with zeroed report */
    wifi_report_t empty = {0};
    bthome_broadcast(&empty);

    for (;;) {
        TickType_t now = xTaskGetTickCount();

        if ((now - last_hop) * portTICK_PERIOD_MS >= HG_CHANNEL_HOP_MS) {
            last_hop = now;
            wifi_sniffer_hop();

            /* Send our pwngrid identity on every channel hop so peers
             * can discover us regardless of what channel they're on. */
            retaliation_send_gotchi_beacon();
        }

        bool interval_elapsed =
            (now - last_report) * portTICK_PERIOD_MS >= HG_REPORT_INTERVAL_MS;

        /*
         * Urgent broadcast: only when a NEW flag appears that wasn't in the
         * previous report, and at most once per second to avoid flooding.
         */
        bool urgent = false;
        if (!interval_elapsed && wifi_sniffer_has_alert()) {
            uint16_t new_flags = wifi_sniffer_peek_flags();
            uint16_t fresh = new_flags & ~prev_flags;
            if (fresh && (now - last_urgent) * portTICK_PERIOD_MS >= 1000) {
                urgent = true;
                last_urgent = now;
            }
        }

        if (interval_elapsed || urgent) {
            last_report = now;

            wifi_report_t r = wifi_sniffer_collect(interval_elapsed);

            /* Always broadcast our pwnagotchi identity so peers see us */
            retaliation_send_gotchi_beacon();

            /* Defensive retaliation: broadcast funny beacons when attacked */
            if (r.flags) {
                retaliation_fire(r.flags);
                r.flags |= HG_FLAG_RETALIATION;
            }

            prev_flags = r.flags;
            bthome_broadcast(&r);

            if (r.flags) {
                ESP_LOGW(TAG,
                    "deauth=%u disassoc=%u probes=%u flags=0x%04X%s",
                    r.deauth, r.disassoc, r.probe_requests, r.flags,
                    urgent ? " [URGENT]" : "");
            }
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }

    ESP_LOGI(TAG, "HomaGotchi Companion starting");

    wifi_sniffer_init();
    bthome_init();
    retaliation_init();

    xTaskCreatePinnedToCore(monitor_task, "monitor", 4096, NULL, 5, NULL, 1);

    ESP_LOGI(TAG, "Monitoring active – reports every %d ms", HG_REPORT_INTERVAL_MS);
}
