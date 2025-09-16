import hashlib
import logging, time, asyncio
from typing import Any, Optional, Callable
from io import BytesIO

from bleak import BleakClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from blufi_data import BlufiEventHub, BlufiEvent, BlufiDH

logger = logging.getLogger(__name__)

# ---- Common sub-types ----
PKG_CTRL        = 0
PKG_DATA        = 1

# Control & Data sub-types
SUB_NEGOTIATE       = 0  # Device public key during negotiate
SUB_SEC_MODE        = 1

GET_WIFI_STATE      = 15 # CTRL
GET_VERSION         = 16 # CTRL
GET_WIFI_SCAN       = 17 # CTRL
GET_ERROR           = 18 # CTRL
GET_CUSTOM          = 19 # CTRL
WIFI_STA    = 1
WIFI_STA_AP = 3

# ---- Device UUIDs (as before) ----
WRITE_CHAR_UUID  = "0000ff01-0000-1000-8000-00805f9b34fb"
NOTIFY_CHAR_UUID = "0000ff02-0000-1000-8000-00805f9b34fb"

# ---- Frame control flags ----
FLAG_ENCRYPTED = 0x01  # bit0
FLAG_CHECKSUM  = 0x02  # bit1
FLAG_ACK       = 0x08  # bit3
FLAG_FRAG      = 0x10  # bit4

CRC_TB = [
    0, 4129, 8258, 12387, 16516, 20645, 24774, 28903, 33032, 37161, 41290, 45419, 49548, 53677, 57806, 61935,
    4657, 528, 12915, 8786, 21173, 17044, 29431, 25302, 37689, 33560, 45947, 41818, 54205, 50076, 62463, 58334,
    9314, 13379, 1056, 5121, 25830, 29895, 17572, 21637, 42346, 46411, 34088, 38153, 58862, 62927, 50604, 54669,
    13907, 9842, 5649, 1584, 30423, 26358, 22165, 18100, 46939, 42874, 38681, 34616, 63455, 59390, 55197, 51132,
    18628, 22757, 26758, 30887, 2112, 6241, 10242, 14371, 51660, 55789, 59790, 63919, 35144, 39273, 43274, 47403,
    23285, 19156, 31415, 27286, 6769, 2640, 14899, 10770, 56317, 52188, 64447, 60318, 39801, 35672, 47931, 43802,
    27814, 31879, 19684, 23749, 11298, 15363, 3168, 7233, 60846, 64911, 52716, 56781, 44330, 48395, 36200, 40265,
    32407, 28342, 24277, 20212, 15891, 11826, 7761, 3696, 65439, 61374, 57309, 53244, 48923, 44858, 40793, 36728,
    37256, 33193, 45514, 41451, 53516, 49453, 61774, 57711, 4224, 161, 12482, 8419, 20484, 16421, 28742, 24679,
    33721, 37784, 41979, 46042, 49981, 54044, 58239, 62302, 689, 4752, 8947, 13010, 16949, 21012, 25207, 29270,
    46570, 42443, 38312, 34185, 62830, 58703, 54572, 50445, 13538, 9411, 5280, 1153, 29798, 25671, 21540, 17413,
    42971, 47098, 34713, 38840, 59231, 63358, 50973, 55100, 9939, 14066, 1681, 5808, 26199, 30326, 17941, 22068,
    55628, 51565, 63758, 59695, 39368, 35305, 47498, 43435, 22596, 18533, 30726, 26663, 6336, 2273, 14466, 10403,
    52093, 56156, 60223, 64286, 35833, 39896, 43963, 48026, 19061, 23124, 27191, 31254, 2801, 6864, 10931, 14994,
    64814, 60687, 56684, 52557, 48554, 44427, 40424, 36297, 31782, 27655, 23652, 19525, 15522, 11395, 7392, 3265,
    61215, 65342, 53085, 57212, 44955, 49082, 36825, 40952, 28183, 32310, 20053, 24180, 11923, 16050, 3793, 7920
]

class BlufiClient:
    AES_TRANSFORMATION = "AES/CFB/NoPadding"
    DEFAULT_PACKAGE_LENGTH = 20
    MIN_PACKAGE_LENGTH = 20
    PACKAGE_HEADER_LENGTH = 4

    NEG_SECURITY_SET_TOTAL_LENGTH = 0x00
    NEG_SECURITY_SET_ALL_DATA    = 0x01

    DH_G = "2"
    DH_P = ("cf5cf5c38419a724957ff5dd323b9c45c3cdd261eb740f69aa94b8bb1a5c9640"
            "9153bd76b24222d03274e4725a5406092e9e82e9135c643cae98132b0d95f7d6"
            "5347c68afc1e677da90e51bbab5f5cf429c291b4ba39c6b2dc5e8c7231e46aa7"
            "728e87664532cdf547be20c9a3fa8342be6e34371a27c06f7dc0edddd2f86373")
    
    mAESKey: Optional[bytes] = None

    def __init__(self, ble: BleakClient, loop: asyncio.AbstractEventLoop):
        self._ble                = ble
        self._loop               = loop
        self._send_seq           = -1
        self._accum_payload      = bytearray()
        self._accum_active       = False
        self._hub                = BlufiEventHub(loop)

        self.mAESKey             = None
        self.mRequireAck         = False
        self.mPackageLengthLimit = -1
        self.mBlufiMTU           = -1
        self.mEncrypted          = False
        self.mChecksum           = False
        self.default_pkg         = PKG_DATA

    # ---- Public high-level API ----
    async def gatt_write(self, frame_bytes: bytes) -> bool:
        await self._ble.write_gatt_char(WRITE_CHAR_UUID, frame_bytes, response=True)
        return True

    async def wait_for(self, pkg: int, sub: int, timeout: Optional[float] = None) -> bytes:
        evt = await self._hub.wait_for(pkg, sub, timeout)
        return evt.payload
    
    async def wait_for_default(self, sub: int, timeout: float | None = None, *, pkg: int | None = None) -> bytes:
        if pkg is None:
            pkg = self.default_pkg
        return await self.wait_for(pkg, sub, timeout)
    
    async def wait_for_data(self, sub: int, timeout: float | None = None) -> bytes:
        return await self.wait_for(PKG_DATA, sub, timeout)

    async def wait_for_ctrl(self, sub: int, timeout: float | None = None) -> bytes:
        return await self.wait_for(PKG_CTRL, sub, timeout)

    def on(self, pkg: int, sub: int, callback: Callable[[BlufiEvent], None]) -> Callable[[], None]:
        return self._hub.on(pkg, sub, callback)

    # ---------- helpers ----------
    def get_type_value(self, pkg_type: int, sub_type: int) -> int:
        return (pkg_type & 0x03) | ((sub_type & 0x3F) << 2)
    
    def _aes_iv_from_seq(self, seq: int) -> bytes:
        iv = bytearray(16)
        iv[0] = seq & 0xFF
        return bytes(iv)    

    def _blufi_crc_calc(self, init: int, data: bytes) -> int:
        i2 = (~init) & 0xFFFF
        for b in data:
            i2 = ((i2 << 8) ^ CRC_TB[(b & 0xFF) ^ (i2 >> 8)]) & 0xFFFF
        return (~i2) & 0xFFFF

    def toBytes(self, hex_str: str) -> bytes:
        s = hex_str
        if len(s) % 2 == 1:
            s = "0" + s
        return bytes.fromhex(s)

    def sleep(self, ms: int) -> None:
        time.sleep(ms / 1000.0)

    def generateSendSequence(self) -> int:
        self._send_seq = (self._send_seq + 1) & 0xFF
        return self._send_seq

    def receiveAck(self, expect_seq: int) -> bool:
        return True  # leave True unless your firmware requires ACKs now


    async def authenticate(self) -> bool:
        blufi_dh = await self.negotiateSecurity()
        if blufi_dh is None:
            logger.error("authenticate failed")
            return False

        try:
            pubkey_bytes = await self.wait_for(PKG_DATA, SUB_NEGOTIATE, timeout=15.0)
        except asyncio.TimeoutError:
            logger.warning("Timed out waiting for device public key")
            return False

        pubkey_int = int.from_bytes(pubkey_bytes, "big")
        blufi_dh.generate_secret_key(pubkey_int)
        shared = blufi_dh.get_secret_key()
        if shared is None:
            logger.error("Failed to derive shared secret key")
            return False

        p_bytes        = (blufi_dh.get_P().bit_length() + 7) // 8   # typically 128 for your P
        shared_padded  = shared.rjust(p_bytes, b"\x00")
        self.mAESKey   = hashlib.md5(shared_padded).digest()

        logging.info("AES key: %s", self.mAESKey.hex())

        return True

    # ---- Notification path (called by bleak) ----
    def handle_notification(self, _char: Any, data: bytearray) -> None:
        try:
            if len(data) < 4:
                return

            type_byte  = data[0]
            frame_ctrl = data[1]
            seq        = data[2]
            body_len   = data[3]

            if 4 + body_len > len(data):
                return  # malformed

            pkg_type =  type_byte & 0x03
            sub_type = (type_byte & 0xFC) >> 2

            encrypted = bool(frame_ctrl & FLAG_ENCRYPTED)
            checksum  = bool(frame_ctrl & FLAG_CHECKSUM)
            frag      = bool(frame_ctrl & FLAG_FRAG)

            body = bytes(data[4:4+body_len])

            # Decrypt data portion if needed (CRC bytes, if present, are NOT encrypted by spec)
            if encrypted:
                if not self.mAESKey:
                    return
                cipher = Cipher(algorithms.AES(self.mAESKey), modes.CFB(self._aes_iv_from_seq(seq)))
                dec    = cipher.decryptor()
                body   = dec.update(body) + dec.finalize()

            # Verify per-frame CRC if present
            if checksum:
                # CRC bytes are AFTER the payload, not part of body_len
                # header(4) + payload(body_len) + crc(2) must be present
                if len(data) < 4 + body_len + 2:
                    return
                crc_lo = data[4 + body_len]
                crc_hi = data[4 + body_len + 1]

                calc = self._blufi_crc_calc(0, bytes([seq & 0xFF, body_len & 0xFF]))
                if body_len:
                    calc = self._blufi_crc_calc(calc, body)  # <-- use full plaintext body, do NOT slice
                if (calc & 0xFF) != crc_lo or ((calc >> 8) & 0xFF) != crc_hi:
                    logger.debug("CRC mismatch; dropping frame pkg=%d sub=%d (got=%02x%02x calc=%04x)",
                            pkg_type, sub_type, crc_lo, crc_hi, calc & 0xFFFF)
                    return

            # Fragment reassembly (device uses FRAG flag; first two bytes MAY be 'remaining length' prefix)
            payload_piece = body
            if frag:
                # If firmware prefixes remaining length, ignore the first 2 bytes in fragments
                if len(payload_piece) >= 2:
                    payload_piece = payload_piece[2:]
                self._accum_payload.extend(payload_piece)
                self._accum_active = True
                return
            else:
                if self._accum_active:
                    self._accum_payload.extend(payload_piece)
                    payload = bytes(self._accum_payload)
                    self._accum_payload.clear()
                    self._accum_active = False
                else:
                    payload = payload_piece

            evt = BlufiEvent(
                pkg=pkg_type,
                sub=sub_type,
                seq=seq,
                encrypted=encrypted,
                checksum=checksum,
                fragmented=False,
                payload=payload,
            )

            # Emit to any waiters/listeners for this (pkg, sub)
            self._hub.emit(evt)

            # Optional: debug line
            logger.debug(
                "notify pkg=%d sub=%d seq=%d len=%d flags=%s%s%s payload=%s",
                pkg_type, sub_type, seq, len(payload),
                "E" if encrypted else "-", "C" if checksum else "-", "F" if frag else "-",
                payload.hex()[:128],
            )

        except Exception as e:
            logger.debug("handle_notification error: %r", e)
            return

    # ---------- Post (split into frames) ----------
    async def post(self, encrypted: bool, checksum: bool, require_ack: bool, type_value: int, data: bytes | None) -> bool:
        if not data:
            return await self.postNonData(encrypted, checksum, require_ack, type_value)
        return await self.postContainData(encrypted, checksum, require_ack, type_value, data)

    async def postNonData(self, encrypted: bool, checksum: bool, require_ack: bool, type_value: int) -> bool:
        seq   = self.generateSendSequence()
        frame = self._getPostBytes(type_value, encrypted, checksum, require_ack, False, seq, None)
        ok    = await self.gatt_write(frame)
        return ok and (not require_ack or self.receiveAck(seq))

    async def postContainData(self, encrypted: bool, checksum: bool, require_ack: bool, type_value: int, data: bytes) -> bool:
        from io import BytesIO
        b_in  = BytesIO(data)
        b_out = BytesIO()

        limit = self.mPackageLengthLimit if self.mPackageLengthLimit > 0 else (self.mBlufiMTU if self.mBlufiMTU > 0 else 20)

        body_budget = limit - 6 - (2 if checksum else 0)
        if body_budget < 0: body_budget = 0  # defensive

        while True:
            chunk = b_in.read(body_budget)
            if chunk == b"":
                return True

            b_out.write(chunk)

            remaining = len(b_in.getbuffer()) - b_in.tell()
            if 0 < remaining <= 2:
                b_out.write(b_in.read(remaining))

            has_frag = (len(b_in.getbuffer()) - b_in.tell()) > 0
            seq = self.generateSendSequence()

            if has_frag:
                size = b_out.getbuffer().nbytes + (len(b_in.getbuffer()) - b_in.tell())
                payload_now = b_out.getvalue()
                b_out = BytesIO()
                b_out.write(bytes([size & 0xFF, (size >> 8) & 0xFF]))  # low, high
                b_out.write(payload_now)

            payload = b_out.getvalue()
            frame = self._getPostBytes(type_value, encrypted, checksum, require_ack, has_frag, seq, payload)
            b_out = BytesIO()

            if not await self.gatt_write(frame):
                return False

            if not has_frag:
                return (not require_ack) or self.receiveAck(seq)

            if require_ack and not self.receiveAck(seq):
                return False

            self.sleep(10) # 10ms

    async def post_set_security(self, enable_encrypt: bool, enable_checksum: bool) -> bool:
        # flags: bit0=encrypt, bit1=checksum
        flags = (0x01 if enable_encrypt else 0x00) | (0x02 if enable_checksum else 0x00)
        type_value = self.get_type_value(PKG_CTRL, SUB_SEC_MODE)  # Ctrl / SET_SEC_MODE
        try:
            # Sends this UNENCRYPTED but WITH CHECKSUM
            ok =  await self.post(False, True, self.mRequireAck, type_value, bytes([flags]))
            if ok:
                self.mEncrypted = enable_encrypt
                self.mChecksum  = enable_checksum
                logger.info("Set security: enc=%s cks=%s", enable_encrypt, enable_checksum)
            return ok
        except InterruptedError:
            return False

    async def post_custom_data(self, payload: bytes) -> bool:
        type_value = self.get_type_value(PKG_DATA, GET_CUSTOM)  # Data / SUBTYPE_CUSTOM_DATA
        try:
            return await self.post(self.mEncrypted, self.mChecksum, self.mRequireAck, type_value, payload)
        except InterruptedError:
            return False

    async def request_wifi_status(self) -> bool:
        type_value = self.get_type_value(PKG_CTRL, 5)  # 5 = GET_WIFI_STATUS
        try:
            return await self.post(self.mEncrypted, self.mChecksum, False, type_value, None)
        except Exception:
            return False

    async def request_device_version(self) -> bool:
        type_value = self.get_type_value(PKG_CTRL, 7)  # 7 = GET_VERSION
        try:
            return await self.post(self.mEncrypted, self.mChecksum, False, type_value, None)
        except Exception:
            return False

    async def request_device_scan(self) -> bool:
        type_value = self.get_type_value(PKG_CTRL, 9)  # Ctrl / GET_WIFI_SCAN_RESULTS
        try:
            return await self.post(self.mEncrypted, self.mChecksum, self.mRequireAck, type_value, None)
        except Exception:
            return False

    async def post_device_mode(self, mode: int) -> bool:
        t = self.get_type_value(PKG_CTRL, 2)  # 2 = SET_DEVICE_MODE
        return await self.post(self.mEncrypted, self.mChecksum, True, t, bytes([mode & 0xFF]))

    async def post_sta_wifi_info(self, ssid: bytes, password: str) -> bool:
        """DATA: STA_SSID, STA_PASSWORD; then CTRL/END to apply"""
        t = self.get_type_value(PKG_DATA, 2)  # 2 = SUB_STA_SSID
        ok = await self.post(self.mEncrypted, self.mChecksum, self.mRequireAck, t, ssid)
        if not ok: return False
        await asyncio.sleep(0.01)

        # Password
        t = self.get_type_value(PKG_DATA, 3)  # 3 = SUB_STA_PASSWORD
        ok = await self.post(self.mEncrypted, self.mChecksum, self.mRequireAck, t, password.encode("utf-8"))
        if not ok: return False
        await asyncio.sleep(0.01)

        # CTRL/END (commit)
        t = self.get_type_value(PKG_CTRL, 3)  # 3 = SUB_END
        return await self.post(False, False, self.mRequireAck, t, None)

    async def _post_softap_info(
        self,
        ssid:     Optional[str] = None,
        password: Optional[str] = None,
        channel:  Optional[int] = None,
        max_conn: Optional[int] = None,
        security: Optional[int] = None,
    ) -> bool:
        """DATA: SoftAP params; final write always includes SECURITY byte."""
        # SSID
        if ssid:
            t = self.get_type_value(PKG_DATA, 4) # 4 = SUB_SOFTAP_SSID
            ok = await self.post(self.mEncrypted, self.mChecksum, self.mRequireAck, t, ssid.encode("utf-8"))
            if not ok: return False
            await asyncio.sleep(0.01)

        # Password
        if password:
            t = self.get_type_value(PKG_DATA, 5) # 5 = SUB_SOFTAP_PASSWORD
            ok = await self.post(self.mEncrypted, self.mChecksum, self.mRequireAck, t, password.encode("utf-8"))
            if not ok: return False
            await asyncio.sleep(0.01)

        # Channel
        if channel and channel > 0:
            t = self.get_type_value(PKG_DATA, 8) # 8 = SUB_SOFTAP_CHANNEL
            ok = await self.post(self.mEncrypted, self.mChecksum, self.mRequireAck, t, bytes([channel & 0xFF]))
            if not ok: return False
            await asyncio.sleep(0.01)

        # Max connections
        if max_conn and max_conn > 0:
            t = self.get_type_value(PKG_DATA, 6) # 6 = SUB_SOFTAP_MAX_CONN
            ok = await self.post(self.mEncrypted, self.mChecksum, self.mRequireAck, t, bytes([max_conn & 0xFF]))
            if not ok: return False
            await asyncio.sleep(0.01)

        t = self.get_type_value(PKG_DATA, 7) # 7 = SUB_SOFTAP_SECURITY
        sec = (security if security is not None else 0) & 0xFF
        return await self.post(self.mEncrypted, self.mChecksum, self.mRequireAck, t, bytes([sec]))

    async def configure_wifi(
        self,
        op_mode: int,
        *,
        sta_ssid:        Optional[str] = None,
        sta_password:    Optional[str] = None,
        softap_ssid:     Optional[str] = None,
        softap_password: Optional[str] = None,
        softap_channel:  Optional[int] = None,
        softap_max_conn: Optional[int] = None,
        softap_security: Optional[int] = None,
    ) -> int:
        """
        Return codes: 0=OK; -3000 invalid mode; -3001 mode post fail; -3002 STA fail; -3003 SoftAP fail
        op_mode: 0=NONE, 1=STA, 2=SoftAP, 3=STA+AP
        """
        # Set device mode
        if not await self.post_device_mode(op_mode): return -3001

        # STA path
        if op_mode in (1, 3):
            if sta_ssid is None or sta_password is None: return -3002
            # Send raw bytes of SSID
            if not await self.post_sta_wifi_info(sta_ssid.encode("utf-8"), sta_password): return -3002

        # SoftAP path
        if op_mode in (2, 3):
            if not await self._post_softap_info(
                ssid=softap_ssid,
                password=softap_password,
                channel=softap_channel,
                max_conn=softap_max_conn,
                security=softap_security,
            ): return -3003

        return 0


    def _generate_aes_iv(self, seq: int) -> bytes:
        iv = bytearray(16)
        iv[0] = seq & 0xFF
        return bytes(iv)

    def _frame_ctrl_value(self, encrypted: bool, checksum: bool, data_dir: int, require_ack: bool, frag: bool) -> int:
        val = 0
        if encrypted:   val |= 1 << 0
        if checksum:    val |= 1 << 1
        if data_dir==1: val |= 1 << 2
        if require_ack: val |= 1 << 3
        if frag:        val |= 1 << 4
        return val

    def _getPostBytes(self, type_value: int, encrypted: bool, checksum: bool, require_ack: bool, has_frag: bool, seq: int, payload: bytes | None) -> bytes:
        frame_ctrl = self._frame_ctrl_value(encrypted, checksum, 0, require_ack, has_frag)
        out = BytesIO()
        plain = payload or b""
        length = len(plain)

        out.write(bytes([type_value & 0xFF]))
        out.write(bytes([frame_ctrl & 0xFF]))
        out.write(bytes([seq & 0xFF]))
        out.write(bytes([length & 0xFF]))

        # CRC over [seq,len] then PLAINTEXT
        crc_bytes = b""
        if checksum:
            crc = self._blufi_crc_calc(0, bytes([seq & 0xFF, length & 0xFF]))
            if length: crc = self._blufi_crc_calc(crc, plain)
            crc_bytes = bytes([crc & 0xFF, (crc >> 8) & 0xFF])  # low, high

        # Encrypt plaintext if requested
        body = plain
        if encrypted and length > 0:
            if not self.mAESKey: raise RuntimeError("AES key not set")
            cipher = Cipher(algorithms.AES(self.mAESKey), modes.CFB(self._generate_aes_iv(seq)))
            enc    = cipher.encryptor()
            body   = enc.update(plain) + enc.finalize()

        # Payload then CRC
        if body:      out.write(body)
        if crc_bytes: out.write(crc_bytes)
        return out.getvalue()

    # ---------- (pads to 256 hex) ----------
    def _get_public_key_value(self, blufi_dh: BlufiDH) -> str | None:
        pub_int = blufi_dh.get_public_value_int()
        if pub_int is None: return None

        s = format(pub_int, "x")

        if len(s) < 256: s = ("0" * (256 - len(s))) + s
        return s

    async def negotiateSecurity(self):
        type_value = self.get_type_value(PKG_DATA, SUB_NEGOTIATE)
        p = int(self.DH_P, 16)
        g = int(self.DH_G)

        # do {...} while (publicValue == null)
        while True:
            blufi_dh = BlufiDH.create(p, g, L_bits=1024)
            s_p = format(blufi_dh.get_P(), "x")
            s_g = format(blufi_dh.get_G(), "x")
            public_value = self._get_public_key_value(blufi_dh)
            if public_value is not None: break

        bytes_p   = self.toBytes(s_p)
        bytes_g   = self.toBytes(s_g)
        bytes_pub = self.toBytes(public_value)

        total_len = len(bytes_p) + len(bytes_g) + len(bytes_pub) + 6

        # Packet 1: 0x00 + total_len (big-endian)
        buf = BytesIO()
        buf.write(bytes([self.NEG_SECURITY_SET_TOTAL_LENGTH]))
        buf.write(bytes([(total_len >> 8) & 0xFF]))
        buf.write(bytes([ total_len       & 0xFF]))

        if not await self.post(False, False, self.mRequireAck, type_value, buf.getvalue()):
            return None

        self.sleep(10)

        # Packet 2: 0x01 + [lenP P][lenG G][lenY Y]
        buf = BytesIO()
        buf.write(bytes([self.NEG_SECURITY_SET_ALL_DATA]))

        buf.write(bytes([(len(bytes_p) >> 8) & 0xFF]))
        buf.write(bytes([ len(bytes_p)       & 0xFF]))
        buf.write(bytes_p)

        buf.write(bytes([(len(bytes_g) >> 8) & 0xFF]))
        buf.write(bytes([ len(bytes_g)       & 0xFF]))
        buf.write(bytes_g)

        buf.write(bytes([(len(bytes_pub) >> 8) & 0xFF]))
        buf.write(bytes([ len(bytes_pub)       & 0xFF]))
        buf.write(bytes_pub)

        if not await self.post(False, False, self.mRequireAck, type_value, buf.getvalue()):
            return None

        return blufi_dh
