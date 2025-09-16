# SEM BLE Python Project

This project provides a Python client for interacting with Fusion SEM BLE devices using the Blufi protocol. It uses the Bleak library for Bluetooth Low Energy (BLE) communication and implements custom parsing and cryptography for device configuration and data retrieval.  It is a very rough implementation for configuring a SEM device over BLE without the mobile app.

## Requirements
- Python 3.8+
- [Bleak](https://github.com/hbldh/bleak) (for BLE communication)
- [cryptography](https://cryptography.io/)

Install dependencies:
```bash
pip install bleak cryptography
```

## Usage
Run the main script to scan and interact with SEMMETER devices:
```bash
python main.py
```
Some functions are commented out in the main.py.  You will need to uncomment them and specify your HA mqtt server and/or wifi settings.

## License
MIT License
