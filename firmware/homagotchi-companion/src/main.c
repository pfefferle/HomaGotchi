/**
 * HomaGotchi Companion – entry point
 *
 * Passive WiFi monitor that reports deauth attacks, pwnagotchi beacons,
 * and evil twin APs via BTHome v2 BLE advertisements.
 *
 * SPDX-License-Identifier: MIT
 */

#include "config.h"
#include "wifi_sniffer.h"
#include "bthome.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"

static const char *TAG = "main";

static void monitor_task(void *arg)
{
    (void)arg;

    TickType_t last_report = xTaskGetTickCount();
    TickType_t last_hop    = last_report;

    /* Initial broadcast with zeroed report */
    wifi_report_t empty = {0};
    bthome_broadcast(&empty);

    for (;;) {
        TickType_t now = xTaskGetTickCount();

        if ((now - last_hop) * portTICK_PERIOD_MS >= HG_CHANNEL_HOP_MS) {
            last_hop = now;
            wifi_sniffer_hop();
        }

        if ((now - last_report) * portTICK_PERIOD_MS >= HG_REPORT_INTERVAL_MS) {
            last_report = now;

            wifi_report_t r = wifi_sniffer_collect();
            bthome_broadcast(&r);

            if (r.deauth || r.disassoc || r.pwnagotchi || r.evil_twin) {
                ESP_LOGW(TAG, "deauth=%u disassoc=%u pwn=%d twin=%d%s",
                         r.deauth, r.disassoc, r.pwnagotchi, r.evil_twin,
                         (r.deauth + r.disassoc >= HG_ATTACK_THRESHOLD)
                             ? " ATTACK!" : "");
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

    xTaskCreatePinnedToCore(monitor_task, "monitor", 4096, NULL, 5, NULL, 1);

    ESP_LOGI(TAG, "Monitoring active – reports every %d ms", HG_REPORT_INTERVAL_MS);
}
