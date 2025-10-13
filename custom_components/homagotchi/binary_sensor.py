"""The HomaGotchi binary sensor platform."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    BinarySensorDeviceClass,
)
from homeassistant.components.bluetooth import (
    BluetoothServiceInfo,
    async_get_scanner,
    async_register_callback,
    BluetoothScanningMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.event import async_track_time_interval

from .const import DOMAIN, SPAM_PATTERNS, RAPID_AD_THRESHOLD

_LOGGER = logging.getLogger(__name__)

# Auto-reset timeout (seconds) - sensor resets if no spam detected for this duration
AUTO_RESET_TIMEOUT = 60


class BLESpamDetector(BinarySensorEntity):
    """Binary sensor that detects BLE spam attacks."""

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_icon = "mdi:bluetooth-connect" \
    ""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the BLE spam detector."""
        self.hass = hass
        self._attr_name = "BLE Spam Detected"
        self._attr_unique_id = f"{DOMAIN}_ble_spam_detector"
        self._attr_is_on = False
        self._callback = None
        self._scanner = None

        # Spam tracking
        self._spam_devices: dict[str, dict[str, Any]] = {}
        self._spam_count = 0
        self._spam_types: set[str] = set()
        self._last_spam_time = None
        self._device_last_seen: dict[str, datetime] = {}
        self._reset_timer = None

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="HomaGotchi",
            manufacturer="HomaGotchi",
            model="BLE Spam Detector",
        )

    async def async_added_to_hass(self) -> None:
        """Set up BLE spam detection when added to hass."""
        try:
            self._scanner = async_get_scanner(self.hass)
            if self._scanner is None:
                _LOGGER.error("Bluetooth scanner not available for spam detection")
                return

            # Register callback for BLE advertisements
            self._callback = async_register_callback(
                self.hass,
                self._handle_bluetooth_advertisement,
                {},  # No filter, receive all advertisements
                BluetoothScanningMode.ACTIVE,
            )

            # Set up auto-reset timer
            self._reset_timer = async_track_time_interval(
                self.hass,
                self._check_auto_reset,
                timedelta(seconds=10),  # Check every 10 seconds
            )

            _LOGGER.info("BLE spam detector initialized and monitoring")
        except Exception as e:
            _LOGGER.error("Error setting up BLE spam detector: %s", str(e))

    async def async_will_remove_from_hass(self) -> None:
        """Clean up when removed from hass."""
        if self._callback is not None:
            self._callback()
            self._callback = None
        if self._reset_timer is not None:
            self._reset_timer()
            self._reset_timer = None
        _LOGGER.info("BLE spam detector stopped")

    @callback
    def _handle_bluetooth_advertisement(
        self, service_info: BluetoothServiceInfo, change
    ) -> None:
        """Handle discovered BLE advertisement and check for spam."""
        address = service_info.address
        now = datetime.now()

        spam_detected = False
        spam_type = None
        spam_details = {}

        # Track last seen time (used for composite detection, not standalone spam detection)
        self._device_last_seen[address] = now

        # Check manufacturer data for spam patterns
        if service_info.manufacturer_data:
            for company_id, data in service_info.manufacturer_data.items():
                # Check Apple spam (SourApple attacks only - requires rapid MAC changes + anomalies)
                if company_id == SPAM_PATTERNS["apple_continuity"]["company_id"]:
                    if len(data) >= 1:
                        # Only flag as spam if it shows attack characteristics:
                        # 1. Rapid MAC address changes (device appearing with different MACs quickly)
                        # 2. Random/unknown device names (not legitimate Apple devices)
                        # 3. Anomalous patterns (very short data, unusual formats)

                        is_suspicious = False

                        # Check for rapid MAC changes (SourApple characteristic)
                        if address in self._device_last_seen:
                            time_diff = (now - self._device_last_seen[address]).total_seconds()
                            if time_diff < 1.0:  # Very rapid changes suggest spoofing
                                is_suspicious = True

                        # Check for random/spoofed device (no name or random MAC)
                        has_legitimate_name = service_info.name and not service_info.name.startswith(address[:8])

                        # Check for anomalous data patterns (legitimate Apple devices have consistent patterns)
                        is_anomalous = len(data) < 3 or (data[0] == 0x12 and len(data) == 4)  # Fake AirTag pattern

                        # Only flag if multiple suspicious indicators
                        if (is_suspicious and not has_legitimate_name) or is_anomalous:
                            for prefix in SPAM_PATTERNS["apple_continuity"]["type_prefixes"]:
                                if data[: len(prefix)] == prefix:
                                    spam_detected = True
                                    spam_type = "apple_continuity"
                                    spam_details = {
                                        "company_id": hex(company_id),
                                        "data_prefix": data[:2].hex(),
                                        "data_length": len(data),
                                        "likely": "SourApple attack",
                                        "has_name": has_legitimate_name,
                                    }
                                    _LOGGER.warning(
                                        "Apple BLE spam attack detected from %s: %s (likely SourApple)",
                                        address,
                                        data.hex(),
                                    )
                                    break

                # Check Microsoft spam
                elif company_id == SPAM_PATTERNS["microsoft_swift_pair"]["company_id"]:
                    spam_detected = True
                    spam_type = "microsoft_swift_pair"
                    spam_details = {
                        "company_id": hex(company_id),
                        "data": data.hex(),
                    }
                    _LOGGER.warning("Microsoft Swift Pair spam detected from %s", address)

                # Check Samsung spam (only flag obvious attack patterns)
                elif company_id == SPAM_PATTERNS["samsung_spam"]["company_id"]:
                    if len(data) >= 1:
                        # Only flag Samsung spam if showing attack characteristics:
                        # - Rapid MAC changes without legitimate device name
                        # - SmartTag spam patterns with spoofed identifiers

                        is_rapid = False
                        if address in self._device_last_seen:
                            time_diff = (now - self._device_last_seen[address]).total_seconds()
                            is_rapid = time_diff < 1.0

                        has_legitimate_name = service_info.name and "Samsung" in service_info.name

                        # Only flag if rapid changes without legitimate name (spam attack)
                        if is_rapid and not has_legitimate_name:
                            for prefix in SPAM_PATTERNS["samsung_spam"]["type_prefixes"]:
                                if data[: len(prefix)] == prefix:
                                    spam_detected = True
                                    spam_type = "samsung_spam"
                                    spam_details = {
                                        "company_id": hex(company_id),
                                        "data_prefix": data[:2].hex(),
                                    }
                                    _LOGGER.warning("Samsung BLE spam attack detected from %s", address)
                                    break

        # Check service data for spam patterns
        if service_info.service_data:
            for uuid_str, data in service_info.service_data.items():
                uuid_upper = uuid_str.upper()

                # Check Google Fast Pair spam
                if "FE2C" in uuid_upper or "0000FE2C" in uuid_upper:
                    spam_detected = True
                    spam_type = "google_fast_pair"
                    spam_details = {
                        "service_uuid": uuid_str,
                        "data": data.hex() if isinstance(data, bytes) else str(data),
                    }
                    _LOGGER.warning("Google Fast Pair spam detected from %s", address)

                # Check Tile spam
                elif "FEED" in uuid_upper:
                    spam_detected = True
                    spam_type = "tile_spam"
                    spam_details = {
                        "service_uuid": uuid_str,
                    }
                    _LOGGER.warning("Tile tracker spam detected from %s", address)

        # Check for FlipperZero BLE spam by Service UUIDs (primary detection method)
        if service_info.service_uuids:
            _LOGGER.debug(
                "Checking Service UUIDs from %s: %s",
                address,
                service_info.service_uuids,
            )
            for service_uuid in service_info.service_uuids:
                service_uuid_upper = service_uuid.upper()
                # Check against FlipperZero service UUIDs
                for uuid_pattern, color_name in SPAM_PATTERNS["flipper_zero"]["service_uuids"].items():
                    if uuid_pattern.upper() in service_uuid_upper or service_uuid_upper == uuid_pattern.upper():
                        spam_detected = True
                        spam_type = "flipper_zero"
                        spam_details = {
                            "service_uuid": service_uuid,
                            "flipper_color": color_name,
                            "detection_method": "service_uuid",
                        }
                        _LOGGER.warning(
                            "FlipperZero detected from %s via Service UUID (Color: %s, UUID: %s)",
                            address,
                            color_name,
                            service_uuid,
                        )
                        break
                if spam_detected:
                    break

        # Fallback: Check for FlipperZero BLE spam patterns (in manufacturer data for ESP32 Marauder)
        if not spam_detected and service_info.manufacturer_data:
            for company_id, data in service_info.manufacturer_data.items():
                # Check all data for FlipperZero patterns
                data_bytes = bytes(data) if not isinstance(data, bytes) else data

                for pattern in SPAM_PATTERNS["flipper_zero"]["payload_patterns"]:
                    # Search for pattern anywhere in the data
                    for i in range(len(data_bytes) - len(pattern) + 1):
                        if data_bytes[i:i+len(pattern)] == pattern:
                            spam_detected = True
                            spam_type = "flipper_zero"
                            color = "Black" if pattern == b"\x81\x30" else "White" if pattern == b"\x82\x30" else "Orange/Other"
                            spam_details = {
                                "company_id": hex(company_id),
                                "pattern": pattern.hex(),
                                "flipper_color": color,
                                "data": data_bytes.hex(),
                                "detection_method": "manufacturer_data",
                            }
                            _LOGGER.warning(
                                "FlipperZero BLE spam detected from %s (Color: %s)",
                                address,
                                color,
                            )
                            break

        # Check for AirTag spoofing (fake AirTag broadcasts)
        # Only flag if showing clear attack pattern: rapid MAC changes + minimal data
        if service_info.manufacturer_data:
            for company_id, data in service_info.manufacturer_data.items():
                if company_id == SPAM_PATTERNS["airtag_spoof"]["company_id"]:
                    if len(data) >= 1:
                        for prefix in SPAM_PATTERNS["airtag_spoof"]["type_prefixes"]:
                            if data[: len(prefix)] == prefix:
                                # Only flag as spoofing attack if BOTH conditions met:
                                # 1. Very rapid MAC address changes (< 0.5s)
                                # 2. Minimal data payload (typical of spam attacks)
                                if address in self._device_last_seen and len(data) <= 4:
                                    time_diff = (now - self._device_last_seen.get(address, now)).total_seconds()
                                    if time_diff < 0.5:  # Very rapid = attack
                                        spam_detected = True
                                        spam_type = "airtag_spoof"
                                        spam_details = {
                                            "company_id": hex(company_id),
                                            "data_prefix": data[:2].hex(),
                                            "rapid_mac_change": True,
                                            "interval": f"{time_diff:.2f}s",
                                        }
                                        _LOGGER.warning(
                                            "AirTag spoofing attack detected from %s (rapid MAC changes)",
                                            address,
                                        )
                                        break

        # Update spam tracking if spam was detected
        if spam_detected and spam_type:
            self._spam_count += 1
            self._spam_types.add(spam_type)
            self._last_spam_time = now

            # Store spam device info
            self._spam_devices[address] = {
                "type": spam_type,
                "name": service_info.name or "Unknown",
                "rssi": service_info.rssi,
                "first_seen": self._spam_devices.get(address, {}).get(
                    "first_seen", now
                ),
                "last_seen": now,
                "count": self._spam_devices.get(address, {}).get("count", 0) + 1,
                "details": spam_details,
            }

            # Set binary sensor to ON (spam detected)
            if not self._attr_is_on:
                self._attr_is_on = True
                _LOGGER.warning(
                    "BLE spam alert activated! Type: %s from %s",
                    spam_type,
                    address,
                )

            self.async_write_ha_state()

    @callback
    def _check_auto_reset(self, now: datetime) -> None:
        """Check if sensor should auto-reset due to no recent spam."""
        if not self._attr_is_on:
            return  # Already off, nothing to do

        if self._last_spam_time is None:
            return  # No spam ever detected

        time_since_last_spam = (datetime.now() - self._last_spam_time).total_seconds()

        if time_since_last_spam > AUTO_RESET_TIMEOUT:
            _LOGGER.info(
                "Auto-resetting BLE spam detector - no spam detected for %d seconds",
                int(time_since_last_spam)
            )
            self._attr_is_on = False
            self._spam_count = 0
            self._spam_types.clear()
            self._spam_devices.clear()
            self.async_write_ha_state()

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes."""
        spam_devices_list = []
        for addr, info in self._spam_devices.items():
            spam_devices_list.append({
                "address": addr,
                "type": info["type"],
                "name": info["name"],
                "rssi": info["rssi"],
                "count": info["count"],
                "first_seen": info["first_seen"].isoformat(),
                "last_seen": info["last_seen"].isoformat(),
                "details": info["details"],
            })

        return {
            "spam_detected": self._attr_is_on,
            "total_spam_count": self._spam_count,
            "unique_spam_devices": len(self._spam_devices),
            "spam_types_detected": list(self._spam_types),
            "last_spam_time": self._last_spam_time.isoformat() if self._last_spam_time else None,
            "spam_devices": spam_devices_list,
            "known_spam_patterns": {
                k: v["description"] for k, v in SPAM_PATTERNS.items()
            },
        }


class FlipperZeroDetector(BinarySensorEntity):
    """Binary sensor that specifically detects FlipperZero BLE spam."""

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_icon = "mdi:dolphin"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the FlipperZero detector."""
        self.hass = hass
        self._attr_name = "FlipperZero Detected"
        self._attr_unique_id = f"{DOMAIN}_flipper_zero_detector"
        self._attr_is_on = False
        self._callback = None
        self._scanner = None

        # FlipperZero tracking
        self._flipper_devices: dict[str, dict[str, Any]] = {}
        self._total_detections = 0
        self._last_detection_time = None
        self._device_last_seen: dict[str, datetime] = {}
        self._reset_timer = None

        # Detection statistics
        self._color_counts = {
            "Black": 0,
            "White": 0,
            "Orange": 0,
        }

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name="HomaGotchi",
            manufacturer="HomaGotchi",
            model="FlipperZero Detector",
        )

    async def async_added_to_hass(self) -> None:
        """Set up FlipperZero detection when added to hass."""
        try:
            self._scanner = async_get_scanner(self.hass)
            if self._scanner is None:
                _LOGGER.error("Bluetooth scanner not available for FlipperZero detection")
                return

            # Register callback for BLE advertisements
            self._callback = async_register_callback(
                self.hass,
                self._handle_bluetooth_advertisement,
                {},  # No filter, receive all advertisements
                BluetoothScanningMode.ACTIVE,
            )

            # Set up auto-reset timer
            self._reset_timer = async_track_time_interval(
                self.hass,
                self._check_auto_reset,
                timedelta(seconds=10),
            )

            _LOGGER.info("FlipperZero detector initialized and monitoring")
        except Exception as e:
            _LOGGER.error("Error setting up FlipperZero detector: %s", str(e))

    async def async_will_remove_from_hass(self) -> None:
        """Clean up when removed from hass."""
        if self._reset_timer is not None:
            self._reset_timer()
            self._reset_timer = None

        if self._callback is not None:
            self._callback()
            self._callback = None
            _LOGGER.info("FlipperZero detector stopped")

    @callback
    def _handle_bluetooth_advertisement(
        self, service_info: BluetoothServiceInfo, change
    ) -> None:
        """Handle discovered BLE advertisement and check for FlipperZero patterns."""
        address = service_info.address
        now = datetime.now()

        flipper_detected = False
        flipper_color = None
        detection_details = {}

        # PRIMARY: Check Service UUIDs for FlipperZero (most reliable method)
        if service_info.service_uuids:
            for service_uuid in service_info.service_uuids:
                service_uuid_upper = service_uuid.upper()
                # Check against FlipperZero service UUIDs from Wall of Flippers
                for uuid_pattern, color_name in SPAM_PATTERNS["flipper_zero"]["service_uuids"].items():
                    if uuid_pattern.upper() in service_uuid_upper or service_uuid_upper == uuid_pattern.upper():
                        flipper_detected = True
                        flipper_color = color_name
                        detection_details = {
                            "service_uuid": service_uuid,
                            "color": color_name,
                            "detection_method": "service_uuid",
                            "rssi": service_info.rssi,
                            "name": service_info.name or "Unknown",
                        }
                        _LOGGER.warning(
                            "🐬 FlipperZero detected! Address: %s, Color: %s, Service UUID: %s",
                            address,
                            color_name,
                            service_uuid,
                        )
                        break
                if flipper_detected:
                    break

        # FALLBACK: Check manufacturer data for FlipperZero patterns (ESP32 Marauder method)
        if not flipper_detected and service_info.manufacturer_data:
            for company_id, data in service_info.manufacturer_data.items():
                data_bytes = bytes(data) if not isinstance(data, bytes) else data

                # Check for FlipperZero patterns
                for pattern in SPAM_PATTERNS["flipper_zero"]["payload_patterns"]:
                    for i in range(len(data_bytes) - len(pattern) + 1):
                        if data_bytes[i:i+len(pattern)] == pattern:
                            flipper_detected = True

                            # Identify color
                            if pattern == b"\x81\x30":
                                flipper_color = "Black"
                            elif pattern == b"\x82\x30":
                                flipper_color = "White"
                            elif pattern == b"\x83\x30":
                                flipper_color = "Orange"

                            detection_details = {
                                "company_id": hex(company_id),
                                "pattern": pattern.hex(),
                                "color": flipper_color,
                                "data_full": data_bytes.hex(),
                                "data_length": len(data_bytes),
                                "detection_method": "manufacturer_data",
                                "rssi": service_info.rssi,
                                "name": service_info.name or "Unknown",
                            }

                            _LOGGER.warning(
                                "FlipperZero detected! Address: %s, Color: %s, Pattern: %s",
                                address,
                                flipper_color,
                                pattern.hex(),
                            )
                            break
                    if flipper_detected:
                        break
                if flipper_detected:
                    break

        # Update tracking if FlipperZero was detected
        if flipper_detected:
            self._total_detections += 1
            self._last_detection_time = now

            if flipper_color:
                self._color_counts[flipper_color] += 1

            # Store or update device info
            if address not in self._flipper_devices:
                self._flipper_devices[address] = {
                    "first_seen": now,
                    "last_seen": now,
                    "detection_count": 1,
                    "color": flipper_color,
                    "details": detection_details,
                }
            else:
                self._flipper_devices[address]["last_seen"] = now
                self._flipper_devices[address]["detection_count"] += 1
                self._flipper_devices[address]["details"] = detection_details

            # Set binary sensor to ON (FlipperZero detected)
            if not self._attr_is_on:
                self._attr_is_on = True
                _LOGGER.warning(
                    "🐬 FlipperZero alert activated! Color: %s from %s",
                    flipper_color,
                    address,
                )

            self.async_write_ha_state()

        # Update last seen time
        self._device_last_seen[address] = now

    @callback
    def _check_auto_reset(self, now: datetime) -> None:
        """Check if sensor should auto-reset due to no recent FlipperZero detection."""
        if not self._attr_is_on:
            return  # Already off, nothing to do

        if self._last_detection_time is None:
            return  # No detection ever

        time_since_last_detection = (datetime.now() - self._last_detection_time).total_seconds()

        if time_since_last_detection > AUTO_RESET_TIMEOUT:
            _LOGGER.info(
                "Auto-resetting FlipperZero detector - no detection for %d seconds",
                int(time_since_last_detection)
            )
            self._attr_is_on = False
            self._total_detections = 0
            self._flipper_devices.clear()
            self._color_counts = {"Black": 0, "White": 0, "Orange": 0}
            self.async_write_ha_state()

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes with rich JSON context."""
        flipper_devices_list = []
        for addr, info in self._flipper_devices.items():
            flipper_devices_list.append({
                "address": addr,
                "color": info["color"],
                "first_seen": info["first_seen"].isoformat(),
                "last_seen": info["last_seen"].isoformat(),
                "detection_count": info["detection_count"],
                "details": {
                    "company_id": info["details"].get("company_id"),
                    "pattern": info["details"].get("pattern"),
                    "rssi": info["details"].get("rssi"),
                    "name": info["details"].get("name"),
                    "data_length": info["details"].get("data_length"),
                },
            })

        return {
            "flipper_detected": self._attr_is_on,
            "total_detections": self._total_detections,
            "unique_devices": len(self._flipper_devices),
            "last_detection": self._last_detection_time.isoformat() if self._last_detection_time else None,
            "color_statistics": {
                "black": self._color_counts["Black"],
                "white": self._color_counts["White"],
                "orange": self._color_counts["Orange"],
                "most_common": max(self._color_counts, key=self._color_counts.get) if any(self._color_counts.values()) else None,
            },
            "devices": flipper_devices_list,
            "threat_level": self._calculate_threat_level(),
            "detection_summary": self._generate_summary(),
        }

    def _calculate_threat_level(self) -> str:
        """Calculate threat level based on detection count."""
        if self._total_detections == 0:
            return "none"
        elif self._total_detections < 10:
            return "low"
        elif self._total_detections < 50:
            return "medium"
        elif self._total_detections < 100:
            return "high"
        else:
            return "critical"

    def _generate_summary(self) -> str:
        """Generate human-readable summary."""
        if not self._attr_is_on:
            return "No FlipperZero activity detected"

        device_count = len(self._flipper_devices)
        most_common_color = max(self._color_counts, key=self._color_counts.get) if any(self._color_counts.values()) else "Unknown"

        return (
            f"{device_count} FlipperZero device(s) detected. "
            f"Total: {self._total_detections} spam packets. "
            f"Most common: {most_common_color} edition."
        )


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the binary sensor from a config entry."""
    entities = [
        BLESpamDetector(hass, entry),
        FlipperZeroDetector(hass, entry),
    ]
    async_add_entities(entities)
    _LOGGER.info("BLE spam detector and FlipperZero detector setup completed")
