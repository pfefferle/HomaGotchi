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
    "(⇀‿‿↼)",  # 0  sleeping
    "(≖‿‿≖)",  # 1  awakening
    "(◕‿‿◕)",  # 2  awake / normal
    "( ⚆⚆)",   # 3  observing (neutral mood)
    "(☉☉ )",   # 4  observing (neutral mood)
    "( ◕‿◕)",  # 5  observing (happy)
    "(◕‿◕ )",  # 6  observing (happy)
    "(°▃▃°)",  # 7  intense
    "(⌐■_■)",  # 8  cool
    "(•‿‿•)",  # 9  happy
    "(^‿‿^)",  # 10 grateful
    "(ᵔ◡◡ᵔ)",  # 11 excited
    "(✜‿‿✜)",  # 12 smart
    "(♥‿‿♥)",  # 13 friendly
    "(☼‿‿☼)",  # 14 motivated
    "(≖__≖)",  # 15 demotivated
    "(-__-)",  # 16 bored
    "(╥☁╥ )",  # 17 sad
    "(ب__ب)",  # 18 lonely
    "(☓‿‿☓)",  # 19 broken
    "(#__#)",  # 20 debugging
]

# Face indices by mood (referencing PWNAGOTCHI_FACES above)
FACE_IDLE = [0, 16, 18]              # sleeping, bored, lonely
FACE_MONITORING = [2, 5, 6, 8, 9, 14]  # awake, observing, cool, happy, motivated
FACE_ALERT_BLE_SPAM = [7, 12, 3, 4]  # intense, smart, observing
FACE_ALERT_FLIPPER = [15, 8, 20]     # demotivated, cool, debugging
FACE_ALERT_DEAUTH = [17, 19, 7]      # sad, broken, intense
FACE_ALERT_EVIL_TWIN = [15, 4, 20]   # demotivated, wide-eyed, debugging
FACE_ALERT_PWNAGOTCHI = [10, 13, 11] # grateful, friendly, excited
FACE_ALERT_AUTH_FLOOD = [7, 20, 15]   # intense, debugging, demotivated
FACE_ALERT_MULTI = [7, 19, 20, 15]   # intense, broken, debugging, demotivated

# Status quips by detection type
QUIPS_IDLE = [
    "all quiet on the wireless front",
    "nothing to see here, move along",
    "zzz... monitoring...",
    "scanning the void",
    "so peaceful... too peaceful",
]
QUIPS_BLE_SPAM = [
    "someone is having a BLE party",
    "popup storm incoming!",
    "advertisements everywhere, like black friday",
    "my bluetooth is tingling",
]
QUIPS_FLIPPER = [
    "someone brought a flipper to the party",
    "a wild hacker dolphin appears!",
    "flipper detected - act natural",
    "nice dolphin, would be a shame if someone logged it",
]
QUIPS_DEAUTH = [
    "the wifi police have arrived",
    "someone is kicking everyone off the network",
    "deauth storm, grab an umbrella!",
    "rude. very rude.",
]
QUIPS_EVIL_TWIN = [
    "your AP has an evil doppelganger",
    "trust issues: AP edition",
    "the call is coming from inside the network",
    "seeing double, and not the fun kind",
]
QUIPS_PWNAGOTCHI = [
    "a wild pwnagotchi appears!",
    "fren! (o_o)",
    "another gotchi wants to play",
    "peer detected - exchanging handshakes",
    "new friend or old rival?",
]
QUIPS_BEACON_SPAM = [
    "it's raining SSIDs, hallelujah",
    "someone opened the beacon floodgates",
    "fake APs everywhere, trust nothing",
]
QUIPS_KARMA = [
    "a honey trap has been set",
    "karma is a device, apparently",
    "someone is answering all the probes",
]
QUIPS_PINEAPPLE = [
    "who lives in a pineapple under the LAN?",
    "hak5 vibes detected",
    "that AP smells... fruity",
]
QUIPS_PROBE_FLOOD = [
    "someone is asking ALL the questions",
    "probe request overload!",
    "nosy device alert",
]
QUIPS_AUTH_FLOOD = [
    "someone is brute forcing the door",
    "auth requests off the charts!",
    "knock knock knock knock knock...",
    "credential stuffing in progress",
]
QUIPS_MULTI = [
    "it's a full-on cyber apocalypse out here",
    "multiple threats, maximum paranoia!",
    "they came in waves",
    "this is fine. everything is fine.",
]

# Quip mapping keyed by sensor suffix
QUIP_MAP = {
    "ble_spam": QUIPS_BLE_SPAM,
    "pentest": QUIPS_FLIPPER,
    "deauth": QUIPS_DEAUTH,
    "evil_twin": QUIPS_EVIL_TWIN,
    "pwnagotchi": QUIPS_PWNAGOTCHI,
    "beacon_spam": QUIPS_BEACON_SPAM,
    "probe_flood": QUIPS_PROBE_FLOOD,
    "karma": QUIPS_KARMA,
    "pineapple": QUIPS_PINEAPPLE,
    "auth_flood": QUIPS_AUTH_FLOOD,
}

# XP level thresholds (cumulative detections -> level name)
XP_LEVELS = [
    (0, "Newborn"),
    (10, "Script Kiddie Bait"),
    (50, "Watchful"),
    (150, "Paranoid"),
    (500, "Battle-Hardened"),
    (1500, "War-Scarred Veteran"),
    (5000, "Legendary Sentinel"),
]

# Shared state keys for hass.data[DOMAIN]["state"]
STATE_TOTAL_XP = "total_xp"
STATE_FRIEND_COUNT = "friend_count"
STATE_FRIEND_ENCOUNTERS = "friend_encounters"
STATE_STARTED_AT = "started_at"
STATE_LAST_INCIDENT = "last_incident"

# Custom event fired by binary sensors when detection state changes
EVENT_DETECTION = f"{DOMAIN}_detection"

# Heuristics for suspicious advertisement behavior
RAPID_ADVERTISEMENT_INTERVAL = 0.3
AIRTAG_RAPID_INTERVAL = 0.3
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

# LightBlue BLE Explorer app (commonly used for BLE reconnaissance)
LIGHTBLUE_SERVICE_UUID = "deadf154-0000-0000-0000-0000deadf154"

# CatHack / Apple Juice BLE attack service UUIDs
CATHACK_SERVICE_UUIDS = {
    "d0611e78-bbb4-4591-a5f8-487910ae4366": "CatHack variant 0",
    "9fa480e0-4967-4542-9390-d343dc5d04ae": "CatHack variant 1",
    "7905f431-b5ce-4e99-a40f-4b1e122d00d0": "CatHack variant 2",
    "89d3502b-0f36-433a-8ef4-c502ad55f8dc": "CatHack variant 3",
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

# BTHome flags bitmask (must match HG_FLAG_* in firmware config.h)
# The 4th count_u16 in the BTHome payload is a bitmask of these flags.
FLAG_DEAUTH = 1 << 0
FLAG_PWNAGOTCHI = 1 << 1
FLAG_EVIL_TWIN = 1 << 2
FLAG_BEACON_SPAM = 1 << 3
FLAG_PROBE_FLOOD = 1 << 4
FLAG_KARMA = 1 << 5
FLAG_PINEAPPLE = 1 << 6
FLAG_RETALIATION = 1 << 7
FLAG_AUTH_FLOOD = 1 << 8

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
    "lightblue_recon": {
        "family": "pentest_tool",
        "description": "LightBlue BLE Explorer app (recon tool)",
        "sources": ["GhostBLE"],
    },
    "cathack_apple_juice": {
        "family": "spoofing",
        "description": "CatHack / Apple Juice BLE attack tool",
        "sources": ["GhostBLE"],
    },
}
