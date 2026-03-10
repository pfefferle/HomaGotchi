"""Constants for the HomaGotchi integration."""

DOMAIN = "homagotchi"

# Configuration options - BLE
CONF_INTENSITY_THRESHOLD = "intensity_threshold"
CONF_INTENSITY_WINDOW = "intensity_window"
CONF_AUTO_RESET_TIMEOUT = "auto_reset_timeout"

# Default values - BLE defensive detection
DEFAULT_INTENSITY_THRESHOLD = 10
DEFAULT_INTENSITY_WINDOW = 30
DEFAULT_AUTO_RESET_TIMEOUT = 60

# Pwnagotchi faces for the optional text entity
PWNAGOTCHI_FACES = [
    "(⇀‿‿↼)",  # sleeping
    "(≖‿‿≖)",  # awakening
    "(◕‿‿◕)",  # awake / normal
    "( ⚆⚆)",   # observing (neutral mood)
    "(☉☉ )",   # observing (neutral mood)
    "( ◕‿◕)",  # observing (happy)
    "(◕‿◕ )",  # observing (happy)
    "(°▃▃°)",  # intense
    "(⌐■_■)",  # cool
    "(•‿‿•)",  # happy
    "(^‿‿^)",  # grateful
    "(ᵔ◡◡ᵔ)",  # excited
    "(✜‿‿✜)",  # smart
    "(♥‿‿♥)",  # friendly
    "(☼‿‿☼)",  # motivated
    "(≖__≖)",  # demotivated
    "(-__-)",  # bored
    "(╥☁╥ )",  # sad
    "(ب__ب)",  # lonely
    "(☓‿‿☓)",  # broken
    "(#__#)",  # debugging
]

# Heuristics for suspicious advertisement behavior
RAPID_ADVERTISEMENT_INTERVAL = 1.0
AIRTAG_RAPID_INTERVAL = 0.5
MAX_AIRTAG_MINIMAL_PAYLOAD_LENGTH = 4

# FlipperZero signatures (Wall of Flippers + common spoof payload patterns)
FLIPPER_SERVICE_UUIDS = {
    "00003081-0000-1000-8000-00805F9B34FB": "Black",
    "00003082-0000-1000-8000-00805F9B34FB": "White",
    "00003083-0000-1000-8000-00805F9B34FB": "Transparent/Orange",
}

FLIPPER_PAYLOAD_PATTERNS = {
    b"\x81\x30": "Black",
    b"\x82\x30": "White",
    b"\x83\x30": "Transparent/Orange",
}

APPLE_COMPANY_ID = 0x004C
MICROSOFT_COMPANY_ID = 0x0006
SAMSUNG_COMPANY_ID = 0x0075

APPLE_CONTINUITY_PREFIXES = [b"\x0F", b"\x07", b"\x10"]
AIRTAG_PREFIX = b"\x12"
APPLE_JUICE_PREFIX = b"\x07\x19\x07"
APPLE_JUICE_CORE = b"\x20\x75\xAA\x30"
APPLE_POPUP_PREFIX = b"\x07\x0F\x00"
APPLE_POPUP_CORE = b"\xAC\x90\x85\x75\x94\x65"
APPLE_SETUP_PREFIX = b"\x04\x04\x2A\x00\x00\x00\x0F\x05\xC1"
SOURAPPLE_PREFIXES = (b"\x0F\x05\xC0", b"\x0F\x05\xC1")
SOURAPPLE_TAIL_MARKER = b"\x00\x00\x10"
APPLE_CUSTOM_CRASH_PREFIX = b"\x0F\x05"

MICROSOFT_SWIFT_PAIR_PAYLOAD_PREFIX = b"\x03\x00\x80"
SAMSUNG_WATCH_PAYLOAD_PREFIX = b"\x01\x00\x02\x00\x01\x01\xFF\x00\x00\x43"
SAMSUNG_BUDS_PAYLOAD_PREFIX = b"\x42\x09\x81\x02\x14\x15\x03\x21\x01\x09"
GOOGLE_FAST_PAIR_PAYLOAD_TAIL = b"\x02\x0A"

GOOGLE_FAST_PAIR_MARKER = "FE2C"
TILE_MARKER = "FEED"

# WiFi monitor companion device detection thresholds
WIFI_MONITOR_NAME_PREFIX = "Gotchi"
CONF_WIFI_DEAUTH_THRESHOLD = "wifi_deauth_threshold"
DEFAULT_WIFI_DEAUTH_THRESHOLD = 5

# BTHome boolean object indices (must match firmware payload order in bthome.c)
BOOL_IDX_DEAUTH = 0
BOOL_IDX_PWNAGOTCHI = 1
BOOL_IDX_EVIL_TWIN = 2

# Human-friendly descriptions used in state attributes
BLE_SIGNATURES = {
    "flipper_zero_service_uuid": {
        "family": "flipper_zero",
        "description": "FlipperZero BLE service UUID signature",
        "sources": ["Wall of Flippers"],
    },
    "flipper_zero_payload": {
        "family": "flipper_zero",
        "description": "FlipperZero/ESP32 Marauder payload signature",
        "sources": ["Wall of Flippers", "BruceDevices/firmware"],
    },
    "apple_juice_spoofing": {
        "family": "spoofing",
        "description": "AppleJuice-style Apple popup payload signature",
        "sources": [
            "n0xa/m5stick-nemo",
            "BruceDevices/firmware",
            "justcallmekoko/ESP32Marauder",
        ],
    },
    "apple_popup_spoofing": {
        "family": "spoofing",
        "description": "Marauder-style Apple popup payload signature",
        "sources": ["justcallmekoko/ESP32Marauder"],
    },
    "apple_setup_spoofing": {
        "family": "spoofing",
        "description": "Apple setup popup payload signature",
        "sources": ["n0xa/m5stick-nemo", "BruceDevices/firmware"],
    },
    "sourapple_spoofing": {
        "family": "spoofing",
        "description": "SourApple continuity payload signature",
        "sources": ["BruceDevices/firmware", "justcallmekoko/ESP32Marauder"],
    },
    "apple_custom_crash_spoofing": {
        "family": "spoofing",
        "description": "Apple continuity custom-crash payload signature",
        "sources": ["jaylikesbunda/Ghost_ESP"],
    },
    "apple_continuity_spoofing": {
        "family": "spoofing",
        "description": "Spoofed Apple Continuity/AirDrop advertisement signature",
        "sources": ["jaylikesbunda/Ghost_ESP"],
    },
    "airtag_spoofing": {
        "family": "spoofing",
        "description": "Spoofed AirTag/Find My advertisement signature",
    },
    "google_fast_pair_spoofing": {
        "family": "spoofing",
        "description": "Spoofed Google Fast Pair advertisement signature",
    },
    "google_fast_pair_payload": {
        "family": "spoofing",
        "description": "Google Fast Pair payload-frame signature",
        "sources": [
            "BruceDevices/firmware",
            "justcallmekoko/ESP32Marauder",
            "jaylikesbunda/Ghost_ESP",
        ],
    },
    "microsoft_swift_pair_spoofing": {
        "family": "spoofing",
        "description": "Spoofed Microsoft Swift Pair advertisement signature",
    },
    "microsoft_swift_pair_payload": {
        "family": "spoofing",
        "description": "Microsoft Swift Pair payload signature",
        "sources": [
            "BruceDevices/firmware",
            "justcallmekoko/ESP32Marauder",
            "jaylikesbunda/Ghost_ESP",
        ],
    },
    "samsung_smarttag_spoofing": {
        "family": "spoofing",
        "description": "Spoofed Samsung SmartTag advertisement signature",
    },
    "samsung_watch_payload": {
        "family": "spoofing",
        "description": "Samsung watch-pair payload signature",
        "sources": [
            "BruceDevices/firmware",
            "justcallmekoko/ESP32Marauder",
            "jaylikesbunda/Ghost_ESP",
        ],
    },
    "samsung_buds_payload": {
        "family": "spoofing",
        "description": "Samsung buds EasySetup payload signature",
        "sources": ["jaylikesbunda/Ghost_ESP"],
    },
    "tile_spoofing": {
        "family": "spoofing",
        "description": "Spoofed Tile advertisement signature",
    },
}
