# 🐬 HomaGotchi

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/custom-components/hacs)
[![GitHub Release](https://img.shields.io/github/release/pfefferle/homagotchi.svg)](https://github.com/pfefferle/homagotchi/releases)
[![License](https://img.shields.io/github/license/pfefferle/homagotchi.svg)](LICENSE)

A Pwnagotchi-inspired Home Assistant integration with BLE spam detection and FlipperZero monitoring.

## Features

🎭 **ASCII Face Display** - Animated Pwnagotchi-style faces that change every 30 seconds  
🚨 **BLE Spam Detection** - Detects various Bluetooth Low Energy spam attacks  
🐬 **FlipperZero Detection** - Specialized detector for FlipperZero devices and ESP32 Marauder attacks  
🛡️ **Smart Filtering** - Distinguishes between legitimate devices and actual attacks

### Detected Attack Types

- **FlipperZero/ESP32 Marauder** - Via Service UUIDs (00003081/82/83) and manufacturer data patterns
- **Apple Continuity Spam** - SourApple attacks with rapid MAC changes
- **Samsung BLE Spam** - SmartTag spoofing attacks
- **Google Fast Pair Spam** - Fake pairing requests
- **Microsoft Swift Pair** - Windows device spam
- **AirTag Spoofing** - Fake FindMy broadcasts
- **Tile Tracker Spam** - Fake Tile devices

## Installation

### HACS (Recommended)

1. Open HACS in Home Assistant
2. Click on "Integrations"
3. Click the three dots in the top right corner
4. Select "Custom repositories"
5. Add `https://github.com/pfefferle/homagotchi` as a repository with category "Integration"
6. Click "Install"
7. Restart Home Assistant
8. Add the integration via Settings → Devices & Services → Add Integration → HomaGotchi

### Manual Installation

1. Copy the `custom_components/homagotchi` folder to your Home Assistant `custom_components` directory
2. Restart Home Assistant
3. Add the integration via Settings → Devices & Services → Add Integration → HomaGotchi

## Usage

Once installed, HomaGotchi provides:

### Entities

- **Text Sensor**: `text.homagotchi_face` - Displays ASCII face (changes every 30s)
- **Binary Sensor**: `binary_sensor.ble_spam_detected` - General BLE spam detector
- **Binary Sensor**: `binary_sensor.flipper_zero_detected` - FlipperZero-specific detector

### Services

- `homagotchi.set_face` - Manually set the ASCII face

### Attributes

Both binary sensors provide rich attributes including:
- Detection counts and types
- Device information (MAC, RSSI, name)
- Spam pattern details
- Threat level assessment (for FlipperZero)
- Color identification (Black/White/Orange FlipperZero)

## Detection Methods

### FlipperZero Detection

Based on [Wall of Flippers](https://github.com/K3YOMI/Wall-of-Flippers) detection methods:

**Primary Method**: Service UUIDs
- `00003081-0000-1000-8000-00805F9B34FB` (Black)
- `00003082-0000-1000-8000-00805F9B34FB` (White)
- `00003083-0000-1000-8000-00805F9B34FB` (Transparent/Orange)

**Fallback Method**: Manufacturer data patterns
- `0x8130`, `0x8230`, `0x8330` (ESP32 Marauder)

### Smart Filtering

HomaGotchi distinguishes between legitimate devices and attacks by checking:
- Rapid MAC address changes (< 1 second = attack)
- Device names (legitimate vs. spoofed)
- Data pattern anomalies
- Advertisement frequency

Your HomePod, iPhone, Apple Watch, and Samsung TV won't trigger false alarms! ✅

## Development

### Quick Start (Local Testing)

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run Home Assistant with the test environment:
   ```bash
   ./run_dev.sh
   ```

3. The test environment loads your custom integration from `custom_components/homagotchi/`

### Project Structure

```
homagotchi/
├── custom_components/homagotchi/
│   ├── __init__.py          # Integration setup
│   ├── binary_sensor.py     # BLE spam detectors
│   ├── config_flow.py       # Configuration UI
│   ├── const.py             # Constants and patterns
│   ├── manifest.json        # Integration metadata
│   ├── sensor.py            # Text sensor (unused)
│   ├── strings.json         # UI strings
│   ├── text.py              # ASCII face entity
│   └── translations/        # Localization
├── hacs.json                # HACS configuration
├── README.md                # This file
└── test_env/                # Development environment
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details

## Credits

- Detection methods based on [Wall of Flippers](https://github.com/K3YOMI/Wall-of-Flippers) by @K3YOMI
- Inspired by [Pwnagotchi](https://pwnagotchi.ai/)

## Support

If you find this integration useful, consider:
- ⭐ Starring the repository
- 🐛 Reporting issues
- 💡 Suggesting features
- 🔀 Contributing code

---

**Note**: This integration is for educational and security awareness purposes. Always respect privacy and local laws when monitoring Bluetooth traffic.
