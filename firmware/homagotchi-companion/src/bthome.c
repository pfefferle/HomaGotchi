/**
 * HomaGotchi Companion – BTHome v2 BLE advertiser
 *
 * Builds and broadcasts non-connectable BLE advertisements in the
 * BTHome v2 format so that Home Assistant (and HomaGotchi) can
 * consume the WiFi monitoring data.
 *
 * SPDX-License-Identifier: MIT
 */

#include "bthome.h"
#include "config.h"

#include <string.h>
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_log.h"

static const char *TAG = "bthome";

/* ── BTHome v2 object IDs ─────────────────────────────────────────────────── */

#define UUID_BTHOME       0xFCD2
#define DEVINFO_V2        0x40   /* version 2, no encryption, no trigger */
#define OBJ_PACKET_ID     0x00   /* uint8  */
#define OBJ_COUNT_U16     0x3D   /* uint16 */
#define OBJ_BOOL          0x0F   /* uint8  */

/* ── Advertising parameters ───────────────────────────────────────────────── */

static esp_ble_adv_params_t s_adv_params = {
    .adv_int_min        = 0x0100,   /* 160 ms */
    .adv_int_max        = 0x0100,
    .adv_type           = ADV_TYPE_NONCONN_IND,
    .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
    .channel_map        = ADV_CHNL_ALL,
    .adv_filter_policy  = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

static uint8_t s_packet_id;

static void gap_cb(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    (void)event;
    (void)param;
}

/* ── Public API ───────────────────────────────────────────────────────────── */

void bthome_init(void)
{
    esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT);

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    esp_bt_controller_init(&bt_cfg);
    esp_bt_controller_enable(ESP_BT_MODE_BLE);

    esp_bluedroid_init();
    esp_bluedroid_enable();
    esp_ble_gap_register_callback(gap_cb);

    ESP_LOGI(TAG, "BLE ready, device name: " HG_DEVICE_NAME);
}

void bthome_broadcast(const wifi_report_t *r)
{
    uint8_t attack = (r->deauth + r->disassoc) >= HG_ATTACK_THRESHOLD ? 1 : 0;
    s_packet_id++;

    /*
     * BTHome v2 service data:
     *   devinfo(1) + packet_id(2) +
     *   deauth count_u16(3) + disassoc count_u16(3) +
     *   bool:attack(2) + bool:pwnagotchi(2) + bool:evil_twin(2)
     *   = 15 bytes
     *
     * Full advertisement: flags(3) + name(9) + svc_header(4) + payload(15) = 31
     */
    uint8_t payload[] = {
        DEVINFO_V2,
        OBJ_PACKET_ID, s_packet_id,
        OBJ_COUNT_U16, (uint8_t)(r->deauth  & 0xFF), (uint8_t)(r->deauth  >> 8),
        OBJ_COUNT_U16, (uint8_t)(r->disassoc & 0xFF), (uint8_t)(r->disassoc >> 8),
        OBJ_BOOL, attack,
        OBJ_BOOL, r->pwnagotchi ? 1 : 0,
        OBJ_BOOL, r->evil_twin  ? 1 : 0,
    };

    const char *name = HG_DEVICE_NAME;
    uint8_t name_len = (uint8_t)strlen(name);

    uint8_t adv[31];
    uint8_t pos = 0;

    /* AD: Flags – general discoverable, BR/EDR not supported */
    adv[pos++] = 0x02;
    adv[pos++] = 0x01;
    adv[pos++] = 0x06;

    /* AD: Complete Local Name */
    adv[pos++] = name_len + 1;
    adv[pos++] = 0x09;
    memcpy(&adv[pos], name, name_len);
    pos += name_len;

    /* AD: Service Data (BTHome UUID + payload) */
    uint8_t svc_len = 2 + sizeof(payload);
    adv[pos++] = svc_len + 1;
    adv[pos++] = 0x16;
    adv[pos++] = (uint8_t)(UUID_BTHOME & 0xFF);
    adv[pos++] = (uint8_t)(UUID_BTHOME >> 8);
    memcpy(&adv[pos], payload, sizeof(payload));
    pos += sizeof(payload);

    esp_ble_gap_stop_advertising();
    esp_ble_gap_config_adv_data_raw(adv, pos);
    esp_ble_gap_start_advertising(&s_adv_params);
}
