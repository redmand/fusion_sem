# main.py
import asyncio
import logging
from bleak import BleakClient, BleakScanner

from blufi_client import (
    BlufiClient,
    PKG_DATA,
    GET_WIFI_STATE,
    GET_VERSION,
    GET_WIFI_SCAN,
    GET_CUSTOM,
    NOTIFY_CHAR_UUID,
)

from blufi_parser import parse_status_payload, parse_version_payload, parse_wifi_scan_payload

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

async def main():
    # Scan for SEMMETER devices
    logger.info("Scanning for SEMMETER devices...")
    devices = await BleakScanner.discover(timeout=10.0)
    semmeters = [d for d in devices if d.name and d.name.startswith("SEMMETER")]

    if not semmeters:
        logger.error("No SEMMETER devices found. Please ensure the device is in pairing mode and nearby.")
        return
    
    if len(semmeters) == 1:
        selected = semmeters[0]
        logger.info(f"Found single SEMMETER device: {selected.name} ({selected.address})")
    else:
        logger.info(f"Found {len(semmeters)} SEMMETER devices:")
        for i, d in enumerate(semmeters):
            logger.info(f"{i}: {d.name} ({d.address})")
        try:
            idx = int(input("Select device index (0-based): "))
            selected = semmeters[idx]
            logger.info(f"Selected device: {selected.name} ({selected.address})")
        except (ValueError, IndexError):
            logger.error("Invalid selection. Exiting.")
            return
    
    address = selected.address

    loop = asyncio.get_running_loop()

    async with BleakClient(address, timeout=10.0) as ble:
        await ble.connect()
        client = BlufiClient(ble, loop)
        client.mRequireAck = False  # keep false unless firmware wants ACKs

        # Enable notifications
        await ble.start_notify(NOTIFY_CHAR_UUID, client.handle_notification)
        logger.info("Connected & notifications enabled")

        # OPTIONAL: subscribe to streaming custom data (unsubscribe() when done)
        unsubscribe_custom = client.on(PKG_DATA, GET_CUSTOM, lambda evt: logging.debug(f"CUSTOM: {evt.payload.hex()}"))

        # Authenticate to the device
        is_auth = await client.authenticate()
        if not is_auth:
            logger.error("Authenticate failed")
            await ble.stop_notify(NOTIFY_CHAR_UUID)
            return

        # Tell device we will use encryption + checksum for DATA frames
        ok = await client.post_set_security(True, True)  # enc=True, cks=True
        if not ok:
            # Failed to set encryption and checksum...cleanup and exit
            unsubscribe_custom()
            await ble.stop_notify(NOTIFY_CHAR_UUID)
            logger.error("Failed to set enc+checksum. Exiting...")
            return

        # Get wifi status
        ok = await client.request_wifi_status()
        if ok:        
            try:
                status_payload = await client.wait_for_data(GET_WIFI_STATE, timeout=5.0)
                logger.info("Status: %s", parse_status_payload(status_payload))
            except asyncio.TimeoutError:
                logger.warning("Timed out waiting for device status")
        else:
            logger.warning("Request device status failed")

        # Get version
        ok = await client.request_device_version()
        if ok:            
            try:
                version_payload = await client.wait_for_data(GET_VERSION, timeout=5.0)
                logger.info("Version: %s", parse_version_payload(version_payload))
            except asyncio.TimeoutError:
                logger.warning("Timed out waiting for device version")
        else:
            logger.warning("Request device version failed")

        # Trigger wifi scan - not working as of now
        # ok = await client.request_device_scan()
        # if ok:            
        #     try:
        #         scan_payload = await client.wait_for_data(SUB_WIFI_SCAN, timeout=15.0)
        #         logger.info("Scan parsed: %s", parse_wifi_scan_payload(scan_payload))
        #     except asyncio.TimeoutError:
        #         logger.warning("Timed out waiting for device wifi scan")
        # else:
        #     logger.warning("request_device_scan: post failed")

        # Solar State - not sure what this does exactly
        ok = await client.post_custom_data(b'{"Cmd":"solar_key","value":"0"}')
        if ok:
            try:
                pl = await client.wait_for_data(GET_CUSTOM, timeout=5.0)
                logger.info("Solar State: %s", pl.decode("utf-8"))
            except asyncio.TimeoutError:
                logger.warning("Timed out waiting for solar state")
        else:
            logger.warning("Request solar state failed")
        
        # Firmware version
        ok = await client.post_custom_data(b'{"Cmd":"ver"}')
        if ok:
            try:
                pl = await client.wait_for_data(GET_CUSTOM, timeout=5.0)
                logger.info("Firmware Version: %s", pl.decode("utf-8"))
            except asyncio.TimeoutError:
                logger.warning("Timed out waiting for firmware version")
        else:
            logger.warning("Request firmware version failed")

        # Read HA config
        ok = await client.post_custom_data(b'{"Cmd":"read_ha"}')
        if ok:
            try:
                pl = await client.wait_for_data(GET_CUSTOM, timeout=5.0)
                logger.info("HA Read: %s", pl.decode("utf-8"))
            except asyncio.TimeoutError:
                logger.warning("Timed out waiting for HA config")
        else:
            logger.warning("Request HA config failed")

        # Set HA config
        # ok = await client.post_custom_data(b'{"Cmd":"set_ha","sw":2,"url":"mqtt://homeassistant.local","port":1883,"username":"your_user","password":"your_pass"}')
        # if ok:
        #     try:
        #         pl = await client.wait_for_data(GET_CUSTOM, timeout=5.0)
        #         logger.info("HA Write: %s", pl.decode("utf-8"))
        #     except asyncio.TimeoutError:
        #         logger.warning("Timed out waiting for HA write response")
        # else:
        #     logger.warning("Request HA write failed")

        # SEM Source - not sure what this is and not working as of now
        #ok = await client.post_custom_data(b'{"Cmd":"sem_source"}')
        #if ok:
        #    try:
        #        pl = await client.wait_for_data(GET_CUSTOM, timeout=5.0)
        #        logger.info("SEM Source: %s", pl.decode("utf-8"))
        #    except asyncio.TimeoutError:
        #        logger.warning("Timed out waiting for SEM source")
        #else:
        #    logger.warning("Request SEM source failed")

        # STA - 1
        # rc = await client.configure_wifi(1, sta_ssid="your_ssid", sta_password="your_password")
        # if rc == 0:
        #     logger.info("WiFi config successful")
        # else:
        #     logger.warning(f"WiFi config failed with code {rc}")

        # Cleanup any streaming listeners you added (optional)
        unsubscribe_custom()
        await ble.stop_notify(NOTIFY_CHAR_UUID)

if __name__ == "__main__":
    # asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
