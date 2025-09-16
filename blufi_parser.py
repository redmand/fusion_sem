# blufi_parser.py
import time
import json
from typing import List, Dict

TYPE_WIFI = 1

def parse_status_payload(payload: bytes) -> dict:
    if len(payload) < 3:
        raise ValueError("status payload too short")
    pos = 0
    op_mode = payload[pos]; pos += 1
    sta_status = payload[pos]; pos += 1
    softap_count = payload[pos]; pos += 1

    out = {
        "op_mode": op_mode,
        "sta_connected": (sta_status == 1),
        "softap_client_count": softap_count,
        "sta_bssid": None,
        "sta_ssid": None,
        "sta_password": None,
        "softap_ssid": None,
        "softap_password": None,
        "softap_max_conn": None,
        "softap_security": None,
        "softap_channel": None,
    }

    while pos + 2 <= len(payload):
        t = payload[pos]; l = payload[pos+1]; pos += 2
        if pos + l > len(payload):
            break
        v = payload[pos:pos+l]; pos += l

        if t == 1:
            if l == 6:
                out["sta_bssid"] = ":".join(f"{b:02X}" for b in v)
        elif t == 2:
            out["sta_ssid"] = v.decode(errors="ignore")
        elif t == 3:
            out["sta_password"] = v.decode(errors="ignore")
        elif t == 4:
            out["softap_ssid"] = v.decode(errors="ignore")
        elif t == 5:
            out["softap_password"] = v.decode(errors="ignore")
        elif t == 6 and l >= 1:
            out["softap_max_conn"] = v[0]
        elif t == 7 and l >= 1:
            out["softap_security"] = v[0]
        elif t == 8 and l >= 1:
            out["softap_channel"] = v[0]

    return out

def decode_app_data_hex(self, topic, payload):
    """
    Decode MQTT APP_DATA_HEX payload
    
    Args:
        topic (str): MQTT topic, e.g., 'SEMMETER/XXXXXXXXXXXX/APP_DATA_HEX'
        payload (str or bytes): Hex string or bytes of the 188-byte payload
        
    Returns:
        dict: Decoded data with facility_number, rssi, and records
    """
    # Convert hex string to bytes if necessary
    if isinstance(payload, str):
        payload = bytes.fromhex(payload.replace(" ", ""))
    
    # Convert payload to integer array (0-255)
    i_arr = [b & 0xFF for b in payload]
    
    # Extract facility number from topic
    facility_number = topic.replace("SEMMETER/", "").replace("/APP_DATA_HEX", "")
    
    # Extract RSSI
    rssi = i_arr[5] if len(i_arr) > 5 else 0
    
    # Parse records (18 records of 17 bytes)
    records = []
    for i6 in range(18):
        record = []
        i7 = (i6 * 17) + 9
        for i8 in range(i7, min(i7 + 17, len(i_arr))):
            record.append(i_arr[i8])
        records.append(record)
    
    # Sort records by first value
    records.sort(key=lambda x: x[0] if x else 0)
    
    # Map to LineDataBean fields
    decoded_records = []
    for record in records:
        if len(record) < 17:
            continue
        
        voltage = (record[5] + (record[6] * 256)) / 10.0 if len(record) > 6 else 0.0        
        current = (record[7] + (record[8] * 256)) / 1000.0 if len(record) > 8 else 0.0        
        dosage = (record[9] | (record[10] << 8) | (record[11] << 16) | (record[12] << 24)) / 1000.0 if len(record) > 12 else 0.0
        
        time_val = int(time.time())   # Current UNIX timestamp (seconds)
        power    = voltage * current  # Calculate power (Watts)
        money    = 0.0                # Requires tariff data
        co2      = 0.0                # Requires carbon factor
        is_show  = True               # Default per LineDataBean constructor

        decoded_records.append({
            "time":    time_val,
            "money":   money,
            "dosage":  dosage,
            "voltage": voltage,
            "current": current,
            "power":   power,
            "co2":     co2,
            "isShow":  is_show
        })
    
    return {
        "facility_number": facility_number,
        "rssi": rssi,
        "records": decoded_records
    }

def parse_version_payload(payload: bytes, *, strict: bool = True):
    """
    Parse DATA/16 (version) payload.
    - strict=True: require exactly 2 bytes
    - strict=False: accept >=2 and ignore extras
    """
    if strict and len(payload) != 2:
        raise ValueError(f"BLUFI version payload must be 2 bytes, got {len(payload)}: {payload.hex()}")
    if len(payload) < 2:
        raise ValueError(f"BLUFI version payload too short: {payload.hex()}")

    return {
        "major": payload[0],
        "minor": payload[1]
    }

def parse_wifi_scan_payload(payload: bytes, *, encoding: str = "utf-8", errors: str = "replace"):
    """
    Parse DATA/17 (Wi-Fi scan) payload into a list of BlufiScanResult
    Payload format repeats:
        [len][rssi][ssid...]
    where len = 1 + len(ssid).

    - encoding: how to decode SSID bytes (ESP32 typically uses UTF-8).
    - errors: decoding error policy ("replace" avoids exceptions on weird SSIDs).
    """
    out: List[Dict] = []
    i = 0
    n = len(payload)

    while i < n:
        length = payload[i]
        i += 1

        # Invalid or truncated record
        if length < 1 or i + length - 1 > n:
            break

        rssi_raw = payload[i]
        i += 1

        # Convert unsigned byte to signed int (-128..127)
        rssi = rssi_raw - 256 if rssi_raw > 127 else rssi_raw

        ssid_bytes = payload[i : i + (length - 1)]
        i += (length - 1)

        ssid = ssid_bytes.decode(encoding, errors=errors)
        out.append({"type": TYPE_WIFI, "ssid": ssid, "rssi": rssi})

    out.sort(key=lambda d: d["rssi"], reverse=True)
    
    return json.dumps(out, ensure_ascii=False)