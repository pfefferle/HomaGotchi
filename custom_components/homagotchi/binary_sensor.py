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

from .const import (
    DOMAIN,
    SPAM_PATTERNS,
    RAPID_MAC_THRESHOLD,
    AIRTAG_RAPID_THRESHOLD,
    CONF_INTENSITY_THRESHOLD,
    CONF_INTENSITY_WINDOW,
    CONF_AUTO_RESET_TIMEOUT,
    CONF_FLIPPER_INTENSITY_THRESHOLD,
    CONF_FLIPPER_INTENSITY_WINDOW,
    DEFAULT_INTENSITY_THRESHOLD,
    DEFAULT_INTENSITY_WINDOW,
    DEFAULT_AUTO_RESET_TIMEOUT,
    DEFAULT_FLIPPER_INTENSITY_THRESHOLD,
    DEFAULT_FLIPPER_INTENSITY_WINDOW,
)

_LOGGER = logging.getLogger(__name__)


class BLESpamDetector(BinarySensorEntity):
    """Binary sensor that detects BLE spam attacks."""

    _attr_has_entity_name = True
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_icon = "mdi:bluetooth-connect"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Initialize the BLE spam detector."""
        self.hass = hass
        self._entry = entry
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

        # Intensity tracking - detect spam patterns over time
        self._suspicious_events: list[tuple[datetime, str, str]] = []  # (timestamp, address, type)
        # Get configuration options with defaults
        self._intensity_threshold = entry.options.get(
            CONF_INTENSITY_THRESHOLD, DEFAULT_INTENSITY_THRESHOLD
        )
        self._intensity_window = entry.options.get(
            CONF_INTENSITY_WINDOW, DEFAULT_INTENSITY_WINDOW
        )
        self._auto_reset_timeout = entry.options.get(
            CONF_AUTO_RESET_TIMEOUT, DEFAULT_AUTO_RESET_TIMEOUT
        )

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

        # Debug: Log ALL BLE advertisements to see what's being missed
        if service_info.manufacturer_data or service_info.service_data:
            _LOGGER.debug(
                "BLE Ad from %s: mfg=%s, svc=%s, name=%s",
                address,
                {hex(k): v.hex() if isinstance(v, bytes) else str(v) for k, v in service_info.manufacturer_data.items()} if service_info.manufacturer_data else "None",
                list(service_info.service_data.keys()) if service_info.service_data else "None",
                service_info.name or "None"
            )

        spam_detected = False
        spam_type = None
        spam_details = {}

        # Check if this is a rapid MAC address change (before updating last seen time)
        time_since_last_seen = None
        if address in self._device_last_seen:
            time_since_last_seen = (now - self._device_last_seen[address]).total_seconds()

        # Update last seen time for this address
        self._device_last_seen[address] = now

        # Check manufacturer data for spam patterns
        if service_info.manufacturer_data:
            for company_id, data in service_info.manufacturer_data.items():
                # Check Apple spam (SourApple/AppleJuice attacks)
                if company_id == SPAM_PATTERNS["apple_continuity"]["company_id"]:
                    if len(data) >= 1:
                        _LOGGER.debug(
                            "Apple manufacturer data from %s: %s (name: %s, time_since_last: %s)",
                            address,
                            data.hex(),
                            service_info.name,
                            f"{time_since_last_seen:.3f}s" if time_since_last_seen else "first_seen"
                        )
                        # Only flag as spam if it shows attack characteristics:
                        # 1. Rapid MAC address changes (same device seen multiple times very quickly)
                        # 2. Random/unknown device names (not legitimate Apple devices)
                        # 3. Anomalous patterns (very short data, unusual formats)

                        is_suspicious = False

                        # Check for rapid repeated advertisements from same MAC (spam characteristic)
                        if time_since_last_seen is not None and time_since_last_seen < RAPID_MAC_THRESHOLD:
                            is_suspicious = True

                        # Check for random/spoofed device (no name or random MAC)
                        has_legitimate_name = service_info.name and not service_info.name.startswith(address[:8])

                        # Check for anomalous data patterns (legitimate Apple devices have consistent patterns)
                        # Real Apple devices send properly formatted manufacturer data
                        is_anomalous = len(data) < 3 or (data[0] == 0x12 and len(data) == 4)  # Fake AirTag pattern

                        # Flag if device has suspicious Apple Continuity prefix (0x0F, 0x07, 0x10) AND no legitimate name
                        # This catches:
                        # 1. Rapid spam from same MAC
                        # 2. MAC randomization attacks (new MAC each time)
                        # 3. Slow spam (every 1-6 seconds from same MAC)
                        # Intensity-based detection (10+ in 30s) filters false positives

                        # Check if data has suspicious Apple Continuity prefix
                        has_suspicious_prefix = False
                        for prefix in SPAM_PATTERNS["apple_continuity"]["type_prefixes"]:
                            if data[: len(prefix)] == prefix:
                                has_suspicious_prefix = True
                                break

                        if has_suspicious_prefix and not has_legitimate_name:
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

                # Check Microsoft spam - flag rapid advertising or MAC randomization attacks
                elif company_id == SPAM_PATTERNS["microsoft_swift_pair"]["company_id"]:
                    # Microsoft devices legitimately use Swift Pair, so check for spam characteristics
                    is_rapid_microsoft = time_since_last_seen is not None and time_since_last_seen < RAPID_MAC_THRESHOLD
                    has_ms_name = service_info.name and any(x in service_info.name.lower() for x in ["surface", "xbox", "microsoft"])
                    is_ms_mac_randomization = time_since_last_seen is None and not has_ms_name

                    # Flag if rapid advertising OR first-time device without legitimate name (MAC randomization)
                    if (is_rapid_microsoft or is_ms_mac_randomization) and not has_ms_name:
                        spam_detected = True
                        spam_type = "microsoft_swift_pair"
                        spam_details = {
                            "company_id": hex(company_id),
                            "data": data.hex(),
                        }
                        _LOGGER.warning("Microsoft Swift Pair spam detected from %s", address)

                # Check Samsung spam (flag rapid advertising or MAC randomization attacks)
                elif company_id == SPAM_PATTERNS["samsung_spam"]["company_id"]:
                    if len(data) >= 1:
                        # Flag Samsung spam if showing attack characteristics:
                        # - Rapid repeated advertisements (same MAC seen very quickly)
                        # - MAC randomization with Samsung manufacturer data
                        # - No legitimate Samsung device name

                        is_rapid = time_since_last_seen is not None and time_since_last_seen < RAPID_MAC_THRESHOLD
                        has_legitimate_name = service_info.name and "Samsung" in service_info.name
                        is_samsung_mac_randomization = time_since_last_seen is None and not has_legitimate_name

                        # Flag if rapid advertising OR first-time device without legitimate name
                        # Accept ANY Samsung manufacturer data pattern (Bruce ESP32 uses various patterns)
                        if (is_rapid or is_samsung_mac_randomization) and not has_legitimate_name:
                            spam_detected = True
                            spam_type = "samsung_spam"
                            spam_details = {
                                "company_id": hex(company_id),
                                "data_prefix": data[:2].hex() if len(data) >= 2 else data.hex(),
                            }
                            _LOGGER.warning("Samsung BLE spam attack detected from %s", address)

        # Check service data for spam patterns
        if service_info.service_data:
            for uuid_str, data in service_info.service_data.items():
                uuid_upper = uuid_str.upper()

                # Check Google Fast Pair spam - flag rapid advertising or MAC randomization
                # Legitimate Google devices use Fast Pair, so check for spam characteristics
                if "FE2C" in uuid_upper or "0000FE2C" in uuid_upper:
                    is_rapid_google = time_since_last_seen is not None and time_since_last_seen < RAPID_MAC_THRESHOLD
                    has_google_name = service_info.name and any(x in service_info.name.lower() for x in ["pixel", "google", "nest"])
                    is_google_mac_randomization = time_since_last_seen is None and not has_google_name

                    # Flag if rapid advertising OR first-time device without legitimate name (MAC randomization)
                    if (is_rapid_google or is_google_mac_randomization) and not has_google_name:
                        spam_detected = True
                        spam_type = "google_fast_pair"
                        spam_details = {
                            "service_uuid": uuid_str,
                            "data": data.hex() if isinstance(data, bytes) else str(data),
                        }
                        _LOGGER.warning("Google Fast Pair spam detected from %s", address)

                # Check Tile spam - flag rapid advertising or MAC randomization
                elif "FEED" in uuid_upper:
                    is_rapid_tile = time_since_last_seen is not None and time_since_last_seen < RAPID_MAC_THRESHOLD
                    has_tile_name = service_info.name and "Tile" in service_info.name
                    is_tile_mac_randomization = time_since_last_seen is None and not has_tile_name

                    # Flag if rapid advertising OR first-time device without legitimate name (MAC randomization)
                    if (is_rapid_tile or is_tile_mac_randomization) and not has_tile_name:
                        spam_detected = True
                        spam_type = "tile_spam"
                        spam_details = {
                            "service_uuid": uuid_str,
                        }
                        _LOGGER.warning("Tile tracker spam detected from %s", address)

                # Check nyanBOX detection (by service UUID)
                elif uuid_upper == SPAM_PATTERNS["nyanbox"]["service_uuid"].upper():
                    spam_detected = True
                    spam_type = "nyanbox"
                    spam_details = {
                        "service_uuid": uuid_str,
                        "device": "nyanBOX",
                    }
                    _LOGGER.warning("nyanBOX device detected from %s", address)

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
        # Only flag if showing clear attack pattern: rapid repeated advertisements + minimal data
        if not spam_detected and service_info.manufacturer_data:
            for company_id, data in service_info.manufacturer_data.items():
                if company_id == SPAM_PATTERNS["airtag_spoof"]["company_id"]:
                    if len(data) >= 1:
                        for prefix in SPAM_PATTERNS["airtag_spoof"]["type_prefixes"]:
                            if data[: len(prefix)] == prefix:
                                # Flag as spoofing attack if ANY of:
                                # 1. Very rapid repeated advertisements from same MAC (< 0.5s) with minimal data
                                # 2. First-time device with AirTag prefix, minimal data, and no legitimate name (MAC randomization)
                                # Intensity-based detection (10+ in 30s) will filter false positives
                                has_apple_name = service_info.name and any(x in service_info.name for x in ["AirTag", "iPhone", "iPad", "Mac"])
                                is_airtag_mac_randomization = time_since_last_seen is None and len(data) <= 4 and not has_apple_name
                                is_rapid_airtag = time_since_last_seen is not None and time_since_last_seen < AIRTAG_RAPID_THRESHOLD and len(data) <= 4 and not has_apple_name

                                if is_rapid_airtag or is_airtag_mac_randomization:
                                    spam_detected = True
                                    spam_type = "airtag_spoof"
                                    spam_details = {
                                        "company_id": hex(company_id),
                                        "data_prefix": data[:2].hex(),
                                        "rapid_mac_change": is_rapid_airtag,
                                        "mac_randomization": is_airtag_mac_randomization,
                                        "interval": f"{time_since_last_seen:.2f}s" if time_since_last_seen is not None else "first_seen",
                                    }
                                    if is_rapid_airtag:
                                        _LOGGER.warning(
                                            "AirTag spoofing attack detected from %s (rapid advertising: %.2fs)",
                                            address,
                                            time_since_last_seen,
                                        )
                                    else:
                                        _LOGGER.warning(
                                            "AirTag spoofing attack detected from %s (MAC randomization attack)",
                                            address,
                                        )
                                    break

        # Update spam tracking if spam was detected
        if spam_detected and spam_type:
            # Add to suspicious events for intensity tracking
            self._suspicious_events.append((now, address, spam_type))

            # Calculate current intensity
            intensity = self._calculate_intensity(now)

            # Check if we should trigger based on intensity threshold
            # Exception: FlipperZero detection always triggers (it's definitive)
            intensity_met = intensity >= self._intensity_threshold or spam_type == "flipper_zero"

            # Count ALL spam packets once sensor is ON, or if intensity threshold is met
            if self._attr_is_on or intensity_met:
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

                # Set binary sensor to ON if intensity threshold is met
                if not self._attr_is_on and intensity_met:
                    self._attr_is_on = True
                    _LOGGER.warning(
                        "BLE spam attack detected! Type: %s, Intensity: %d/%d events in %ds from %s",
                        spam_type,
                        intensity,
                        self._intensity_threshold,
                        self._intensity_window,
                        address,
                    )

                self.async_write_ha_state()
            else:
                # Suspicious but not enough intensity yet
                _LOGGER.debug(
                    "Suspicious BLE activity: %s from %s (intensity: %d/%d)",
                    spam_type,
                    address,
                    intensity,
                    self._intensity_threshold,
                )

    @callback
    def _check_auto_reset(self, now: datetime) -> None:
        """Check if sensor should auto-reset due to no recent spam."""
        if not self._attr_is_on:
            return  # Already off, nothing to do

        if self._last_spam_time is None:
            return  # No spam ever detected

        time_since_last_spam = (datetime.now() - self._last_spam_time).total_seconds()

        if time_since_last_spam > self._auto_reset_timeout:
            _LOGGER.info(
                "Auto-resetting BLE spam detector - no spam detected for %d seconds",
                int(time_since_last_spam)
            )
            self._attr_is_on = False
            self._spam_count = 0
            self._spam_types.clear()
            self._spam_devices.clear()
            self._suspicious_events.clear()
            self.async_write_ha_state()

    def _calculate_intensity(self, now: datetime) -> int:
        """Calculate current spam intensity based on recent suspicious events."""
        # Remove events outside the time window
        cutoff_time = now - timedelta(seconds=self._intensity_window)
        self._suspicious_events = [
            (ts, addr, evt_type)
            for ts, addr, evt_type in self._suspicious_events
            if ts > cutoff_time
        ]
        return len(self._suspicious_events)

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

        # Calculate current intensity for display
        current_intensity = self._calculate_intensity(datetime.now())

        return {
            "spam_detected": self._attr_is_on,
            "total_spam_count": self._spam_count,
            "unique_spam_devices": len(self._spam_devices),
            "spam_types_detected": list(self._spam_types),
            "last_spam_time": self._last_spam_time.isoformat() if self._last_spam_time else None,
            "spam_devices": spam_devices_list,
            "intensity": {
                "current": current_intensity,
                "threshold": self._intensity_threshold,
                "window_seconds": self._intensity_window,
                "status": "attacking" if current_intensity >= self._intensity_threshold else "monitoring",
            },
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
        self._entry = entry
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

        # Intensity tracking for FlipperZero
        self._flipper_events: list[tuple[datetime, str, str]] = []  # (timestamp, address, color)
        # Get configuration options with defaults
        self._intensity_threshold = entry.options.get(
            CONF_FLIPPER_INTENSITY_THRESHOLD, DEFAULT_FLIPPER_INTENSITY_THRESHOLD
        )
        self._intensity_window = entry.options.get(
            CONF_FLIPPER_INTENSITY_WINDOW, DEFAULT_FLIPPER_INTENSITY_WINDOW
        )
        self._auto_reset_timeout = entry.options.get(
            CONF_AUTO_RESET_TIMEOUT, DEFAULT_AUTO_RESET_TIMEOUT
        )

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
            # Add to events for intensity tracking
            self._flipper_events.append((now, address, flipper_color or "Unknown"))

            # Calculate current intensity
            intensity = self._calculate_flipper_intensity(now)

            # Only trigger alert if intensity exceeds threshold
            if intensity >= self._intensity_threshold:
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

                # Set binary sensor to ON (FlipperZero attack confirmed)
                if not self._attr_is_on:
                    self._attr_is_on = True
                    _LOGGER.warning(
                        "🐬 FlipperZero attack detected! Color: %s, Intensity: %d/%d in %ds from %s",
                        flipper_color,
                        intensity,
                        self._intensity_threshold,
                        self._intensity_window,
                        address,
                    )

                self.async_write_ha_state()
            elif self._attr_is_on:
                # If sensor is already ON, update last detection time to prevent auto-reset
                # This keeps the sensor ON as long as FlipperZero signals are being detected
                self._last_detection_time = now
                self.async_write_ha_state()
            else:
                # Detected but not enough intensity yet
                _LOGGER.debug(
                    "FlipperZero signal detected: %s from %s (intensity: %d/%d)",
                    flipper_color,
                    address,
                    intensity,
                    self._intensity_threshold,
                )

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

        if time_since_last_detection > self._auto_reset_timeout:
            _LOGGER.info(
                "Auto-resetting FlipperZero detector - no detection for %d seconds",
                int(time_since_last_detection)
            )
            self._attr_is_on = False
            self._total_detections = 0
            self._flipper_devices.clear()
            self._color_counts = {"Black": 0, "White": 0, "Orange": 0}
            self._flipper_events.clear()
            self.async_write_ha_state()

    def _calculate_flipper_intensity(self, now: datetime) -> int:
        """Calculate current FlipperZero detection intensity."""
        # Remove events outside the time window
        cutoff_time = now - timedelta(seconds=self._intensity_window)
        self._flipper_events = [
            (ts, addr, color)
            for ts, addr, color in self._flipper_events
            if ts > cutoff_time
        ]
        return len(self._flipper_events)

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

        # Calculate current intensity for display
        current_intensity = self._calculate_flipper_intensity(datetime.now())

        return {
            "flipper_detected": self._attr_is_on,
            "total_detections": self._total_detections,
            "unique_devices": len(self._flipper_devices),
            "last_detection": self._last_detection_time.isoformat() if self._last_detection_time else None,
            "intensity": {
                "current": current_intensity,
                "threshold": self._intensity_threshold,
                "window_seconds": self._intensity_window,
                "status": "attacking" if current_intensity >= self._intensity_threshold else "monitoring",
            },
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
