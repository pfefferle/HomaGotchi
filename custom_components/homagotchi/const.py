"""Constants for the HomaGotchi integration."""

DOMAIN = "homagotchi"

# Configuration options
CONF_INTENSITY_THRESHOLD = "intensity_threshold"
CONF_INTENSITY_WINDOW = "intensity_window"
CONF_AUTO_RESET_TIMEOUT = "auto_reset_timeout"
CONF_FLIPPER_INTENSITY_THRESHOLD = "flipper_intensity_threshold"
CONF_FLIPPER_INTENSITY_WINDOW = "flipper_intensity_window"

# Default values - More conservative to reduce false positives
# BLE spam typically generates 100+ packets per minute, so we need sustained attacks
DEFAULT_INTENSITY_THRESHOLD = 10  # Increased from 5 to require more events
DEFAULT_INTENSITY_WINDOW = 30  # 30 second window
DEFAULT_AUTO_RESET_TIMEOUT = 60  # Auto-reset after 60 seconds of no detections
DEFAULT_FLIPPER_INTENSITY_THRESHOLD = 5  # Increased from 3 for FlipperZero
DEFAULT_FLIPPER_INTENSITY_WINDOW = 20  # 20 second window

# Detection thresholds for rapid advertising
# Real BLE spam attacks send packets very rapidly (often 10-100+ per second)
# Legitimate devices typically advertise every 1-5 seconds
RAPID_MAC_THRESHOLD = 1.0  # Seconds - devices advertising faster than once per second are suspicious
AIRTAG_RAPID_THRESHOLD = 0.5  # Seconds - AirTag spoofing is even more aggressive

# ASCII faces for the Pwnagotchi-style display
FACES = [
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

# Known BLE spam patterns for detection
SPAM_PATTERNS = {
    # Apple-based spam (SourApple, etc.)
    "apple_continuity": {
        "company_id": 0x004C,  # Apple Inc
        "type_prefixes": [
            b"\x0F",  # AirDrop/Continuity spam (SourApple uses this)
            b"\x07",  # AirPods spam
            b"\x10",  # Nearby Info spam
        ],
        "description": "Apple Continuity/AirDrop spam (including SourApple)",
    },
    # Google Fast Pair spam
    "google_fast_pair": {
        "service_uuid": "0000FE2C-0000-1000-8000-00805F9B34FB",
        "description": "Google Fast Pair spam",
    },
    # Microsoft Swift Pair spam
    "microsoft_swift_pair": {
        "company_id": 0x0006,  # Microsoft
        "description": "Microsoft Swift Pair spam",
    },
    # Samsung spam
    "samsung_spam": {
        "company_id": 0x0075,  # Samsung
        "type_prefixes": [
            b"\x01",  # SmartTag spam
            b"\x02",  # SmartTag Plus spam
        ],
        "description": "Samsung device spam",
    },
    # Tile tracker spam
    "tile_spam": {
        "service_uuid": "0000FEED-0000-1000-8000-00805F9B34FB",
        "description": "Tile tracker spam",
    },
    # FlipperZero BLE spam (from Wall of Flippers patterns)
    "flipper_zero": {
        # PRIMARY DETECTION: Service UUIDs (Real FlipperZero device identification)
        # Source: https://github.com/K3YOMI/Wall-of-Flippers
        "service_uuids": {
            "00003081-0000-1000-8000-00805F9B34FB": "Black",  # FlipperZero Black
            "00003082-0000-1000-8000-00805F9B34FB": "White",  # FlipperZero White
            "00003083-0000-1000-8000-00805F9B34FB": "Transparent/Orange",  # FlipperZero Transparent
        },
        # FALLBACK: Manufacturer data patterns (ESP32 Marauder spam method)
        "payload_patterns": [
            b"\x81\x30",  # FlipperZero Black (ESP32 Marauder)
            b"\x82\x30",  # FlipperZero White (ESP32 Marauder)
            b"\x83\x30",  # FlipperZero Orange (ESP32 Marauder)
        ],
        "description": "FlipperZero BLE spam attack or real device detection",
    },
    # AirTag spoofing (fake AirTags)
    "airtag_spoof": {
        "company_id": 0x004C,  # Apple Inc
        "type_prefixes": [
            b"\x12",  # FindMy network (AirTag)
        ],
        "check_rapid_mac": True,  # AirTag spoofing often uses rapid MAC changes
        "description": "Fake AirTag spoofing",
    },
    # nyanBOX detection (https://github.com/jbohack/nyanBOX)
    "nyanbox": {
        "service_uuid": "6e79616e-424f-582d-7365-727669636521",
        "description": "nyanBOX BLE device detection",
    },
}

