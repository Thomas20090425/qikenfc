#!/usr/bin/env python3

import asyncio
import json
from datetime import datetime
from pathlib import Path

from bleak import BleakClient, BleakScanner

# Confirmed TMS512 / Minicopy BLE characteristics
RX_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"  # notify
TX_UUID = "0000ff02-0000-1000-8000-00805f9b34fb"  # write

PN532_ACK = bytes.fromhex("0000FF00FF00")
DEFAULT_PASSWORD = "FFFFFFFF"


def hexstr(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def make_pn532_frame(payload: bytes) -> bytes:
    if len(payload) > 255:
        raise ValueError("Payload too large for a normal PN532 frame")

    length = len(payload)
    lcs = (-length) & 0xFF
    dcs = (-sum(payload)) & 0xFF

    return (
        b"\x00\x00\xFF"
        + bytes([length, lcs])
        + payload
        + bytes([dcs, 0x00])
    )


class PN532BLE:
    def __init__(self, client, rx_char, tx_char):
        self.client = client
        self.rx_char = rx_char
        self.tx_char = tx_char
        self.buffer = bytearray()
        self.responses = asyncio.Queue()
        self.write_with_response = "write" in set(tx_char.properties)

    async def start(self):
        await self.client.start_notify(self.rx_char, self._on_notify)

    async def stop(self):
        try:
            await self.client.stop_notify(self.rx_char)
        except Exception:
            pass

    def _on_notify(self, _sender, data):
        self.buffer.extend(data)
        self._parse_buffer()

    def _parse_buffer(self):
        while True:
            start = self.buffer.find(b"\x00\x00\xFF")

            if start < 0:
                if len(self.buffer) > 2:
                    del self.buffer[:-2]
                return

            if start > 0:
                del self.buffer[:start]

            if len(self.buffer) < 6:
                return

            if self.buffer[:6] == PN532_ACK:
                del self.buffer[:6]
                continue

            if self.buffer[:6] == bytes.fromhex("0000FFFF0000"):
                del self.buffer[:6]
                print("[!] PN532 NACK")
                continue

            # Extended frame
            if self.buffer[3] == 0xFF and self.buffer[4] == 0xFF:
                if len(self.buffer) < 10:
                    return

                length_hi = self.buffer[5]
                length_lo = self.buffer[6]
                lcs = self.buffer[7]

                if (length_hi + length_lo + lcs) & 0xFF:
                    del self.buffer[0]
                    continue

                length = (length_hi << 8) | length_lo
                total = 8 + length + 2

                if len(self.buffer) < total:
                    return

                payload = bytes(self.buffer[8:8 + length])
                dcs = self.buffer[8 + length]
                del self.buffer[:total]

            else:
                length = self.buffer[3]
                lcs = self.buffer[4]

                if (length + lcs) & 0xFF:
                    del self.buffer[0]
                    continue

                total = 5 + length + 2
                if len(self.buffer) < total:
                    return

                payload = bytes(self.buffer[5:5 + length])
                dcs = self.buffer[5 + length]
                del self.buffer[:total]

            if (sum(payload) + dcs) & 0xFF:
                print("[!] Bad PN532 response checksum")
                continue

            if payload:
                self.responses.put_nowait(payload)

    def clear_queue(self):
        while True:
            try:
                self.responses.get_nowait()
            except asyncio.QueueEmpty:
                break

    async def command(self, payload: bytes, expected_code: int, timeout: float = 3.0):
        self.clear_queue()

        await self.client.write_gatt_char(
            self.tx_char,
            make_pn532_frame(payload),
            response=self.write_with_response,
        )

        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout

        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError(f"Timeout waiting for D5 {expected_code:02X}")

            response = await asyncio.wait_for(self.responses.get(), timeout=remaining)

            if (
                len(response) >= 2
                and response[0] == 0xD5
                and response[1] == expected_code
            ):
                return response


async def find_reader():
    print("[*] Scanning for Minicopy BLE reader...")
    devices = await BleakScanner.discover(timeout=8.0)

    for device in devices:
        name = device.name or ""
        if "minicopy" in name.lower():
            return device

    return None


def parse_password(text: str) -> bytes:
    value = text.strip().upper()
    if not value:
        value = DEFAULT_PASSWORD

    value = value.replace("0X", "")
    value = value.replace(" ", "")
    value = value.replace(":", "")
    value = value.replace("-", "")

    if len(value) != 8:
        raise ValueError("Password must be exactly 8 hex characters / 4 bytes")

    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("Password contains invalid hexadecimal characters") from exc


def parse_target(response: bytes):
    # D5 4B NbTg Tg SENS_RES[2] SEL_RES UIDLEN UID...
    if len(response) < 3 or response[2] == 0:
        return None

    if len(response) < 8:
        raise ValueError("Short InListPassiveTarget response")

    target_number = response[3]
    atqa = response[4:6]
    sak = response[6]
    uid_len = response[7]

    if len(response) < 8 + uid_len:
        raise ValueError("Incomplete UID in target response")

    uid = response[8:8 + uid_len]
    remaining = response[8 + uid_len:]

    ats = None
    if remaining:
        ats_len = remaining[0]
        if ats_len and len(remaining) >= ats_len:
            ats = remaining[:ats_len]

    return {
        "target_number": target_number,
        "atqa": atqa,
        "sak": sak,
        "uid": uid,
        "ats": ats,
    }


async def get_pn532_firmware(pn: PN532BLE):
    response = await pn.command(bytes.fromhex("D402"), expected_code=0x03)
    if len(response) < 6:
        return None

    return {
        "ic": response[2],
        "version": response[3],
        "revision": response[4],
        "support": response[5],
    }


async def select_card(pn: PN532BLE):
    response = await pn.command(
        bytes.fromhex("D44A0100"),
        expected_code=0x4B,
        timeout=10.0,
    )
    return parse_target(response)


async def raw_type2_command(pn: PN532BLE, command: bytes, timeout: float = 3.0):
    """Send a raw Type-2 command using PN532 InCommunicateThru (D4 42)."""
    try:
        response = await pn.command(
            b"\xD4\x42" + command,
            expected_code=0x43,
            timeout=timeout,
        )
    except Exception as exc:
        return None, str(exc)

    if len(response) < 3:
        return None, "short PN532 response"

    status = response[2] & 0x3F
    if status != 0:
        return None, f"PN532 status 0x{status:02X}"

    return response[3:], None


async def pwd_auth(pn: PN532BLE, password: bytes):
    data, error = await raw_type2_command(pn, b"\x1B" + password, timeout=2.5)
    if data is None:
        return False, None, error

    if len(data) < 2:
        return False, None, "card did not return a PACK"

    return True, data[:2], None


async def get_type2_version(pn: PN532BLE):
    data, _error = await raw_type2_command(pn, b"\x60", timeout=2.0)
    if data is None or len(data) < 8:
        return None
    return data[:8]


async def read_signature(pn: PN532BLE):
    data, error = await raw_type2_command(pn, bytes.fromhex("3C00"), timeout=4.0)
    if data is None:
        return None, error
    if len(data) < 32:
        return None, f"short signature response ({len(data)} bytes)"
    return data[:32], None


async def read_counter(pn: PN532BLE, counter_number: int):
    data, error = await raw_type2_command(
        pn,
        bytes([0x39, counter_number & 0xFF]),
        timeout=2.0,
    )
    if data is None:
        return None, error
    if len(data) < 3:
        return None, f"short counter response ({len(data)} bytes)"

    raw = data[:3]
    return {
        "raw": hexstr(raw),
        "value_lsb_first": int.from_bytes(raw, "little"),
    }, None


async def check_tearing(pn: PN532BLE, counter_number: int):
    data, error = await raw_type2_command(
        pn,
        bytes([0x3E, counter_number & 0xFF]),
        timeout=2.0,
    )
    if data is None:
        return None, error
    if len(data) < 1:
        return None, "short tearing-status response"

    flag = data[0]
    return {
        "flag": f"{flag:02X}",
        "valid": flag == 0xBD,
    }, None


async def read_page(pn: PN532BLE, target_number: int, page: int):
    # Type-2 READ (0x30) returns 16 bytes starting at PAGE.
    payload = bytes([0xD4, 0x40, target_number, 0x30, page])

    try:
        response = await pn.command(payload, expected_code=0x41, timeout=1.5)
    except Exception as exc:
        return None, str(exc)

    if len(response) < 3:
        return None, "short response"

    status = response[2] & 0x3F
    if status != 0:
        return None, f"PN532 status 0x{status:02X}"

    data = response[3:]
    if len(data) < 4:
        return None, "short card response"

    # Keep only the specifically addressed page. This avoids rollover ambiguity.
    return data[:4], None


def decode_version(version: bytes | None):
    if not version or len(version) < 8:
        return {
            "raw": None,
            "recognized": False,
            "variant": "unknown",
            "total_pages": None,
            "user_bytes": None,
        }

    info = {
        "raw": hexstr(version[:8]),
        "fixed_header": f"{version[0]:02X}",
        "vendor_id": f"{version[1]:02X}",
        "product_type": f"{version[2]:02X}",
        "product_subtype": f"{version[3]:02X}",
        "major_version": f"{version[4]:02X}",
        "minor_version": f"{version[5]:02X}",
        "storage_size": f"{version[6]:02X}",
        "protocol_type": f"{version[7]:02X}",
        "recognized": False,
        "variant": "unknown",
        "total_pages": None,
        "user_bytes": None,
    }

    looks_like_ul_ev1 = (
        version[0] == 0x00
        and version[1] == 0x04
        and version[2] == 0x03
        and version[4] == 0x01
        and version[7] == 0x03
    )

    if looks_like_ul_ev1 and version[6] == 0x0B:
        info.update({
            "recognized": True,
            "variant": "MIFARE Ultralight EV1 MF0UL11-compatible",
            "total_pages": 20,
            "user_bytes": 48,
            "user_page_start": 0x04,
            "user_page_end": 0x0F,
            "config_page_start": 0x10,
            "config_page_end": 0x13,
        })
    elif looks_like_ul_ev1 and version[6] == 0x0E:
        info.update({
            "recognized": True,
            "variant": "MIFARE Ultralight EV1 MF0UL21-compatible",
            "total_pages": 41,
            "user_bytes": 128,
            "user_page_start": 0x04,
            "user_page_end": 0x23,
            "dynamic_lock_page": 0x24,
            "config_page_start": 0x25,
            "config_page_end": 0x28,
        })

    return info


async def dump_pages(pn: PN532BLE, target_number: int, total_pages: int | None):
    pages = {}
    errors = {}

    print()
    print("[*] Dumping readable EEPROM pages...")
    print()

    if total_pages is not None:
        addresses = range(total_pages)
    else:
        addresses = range(0x100)

    for page in addresses:
        data, error = await read_page(pn, target_number, page)

        if data is None:
            errors[page] = error
            print(f"Page {page:03d} / 0x{page:02X}: <unreadable: {error}>")

            # If the size is unknown, the first invalid page is our stopping point.
            if total_pages is None:
                break
            continue

        pages[page] = data
        ascii_view = "".join(chr(x) if 32 <= x <= 126 else "." for x in data)
        print(
            f"Page {page:03d} / 0x{page:02X}: "
            f"{hexstr(data):11s}  |{ascii_view}|"
        )

    return pages, errors


def pages_to_blob(pages: dict[int, bytes], total_pages: int | None) -> bytes:
    if not pages:
        return b""

    if total_pages is None:
        total_pages = max(pages) + 1

    missing = [page for page in range(total_pages) if page not in pages]
    if missing:
        raise RuntimeError(
            "Refusing to create a misleading BIN because these pages were unreadable: "
            + ", ".join(f"0x{page:02X}" for page in missing)
        )

    blob = bytearray()
    for page in range(total_pages):
        blob.extend(pages[page])

    return bytes(blob)


def analyze_uid_bcc(pages: dict[int, bytes], selected_uid: bytes):
    result = {
        "selected_uid": selected_uid.hex().upper(),
        "memory_uid": None,
        "bcc0_actual": None,
        "bcc0_expected": None,
        "bcc0_ok": None,
        "bcc1_actual": None,
        "bcc1_expected": None,
        "bcc1_ok": None,
    }

    if 0 not in pages or 1 not in pages or 2 not in pages:
        return result

    p0 = pages[0]
    p1 = pages[1]
    p2 = pages[2]
    memory_uid = p0[:3] + p1[:4]

    result["memory_uid"] = memory_uid.hex().upper()

    if len(memory_uid) == 7:
        bcc0_actual = p0[3]
        bcc0_expected = 0x88 ^ memory_uid[0] ^ memory_uid[1] ^ memory_uid[2]
        bcc1_actual = p2[0]
        bcc1_expected = memory_uid[3] ^ memory_uid[4] ^ memory_uid[5] ^ memory_uid[6]

        result.update({
            "bcc0_actual": f"{bcc0_actual:02X}",
            "bcc0_expected": f"{bcc0_expected:02X}",
            "bcc0_ok": bcc0_actual == bcc0_expected,
            "bcc1_actual": f"{bcc1_actual:02X}",
            "bcc1_expected": f"{bcc1_expected:02X}",
            "bcc1_ok": bcc1_actual == bcc1_expected,
            "selected_uid_matches_memory": selected_uid == memory_uid,
        })

    return result


def analyze_mf0ul11_locking(pages: dict[int, bytes], authenticated: bool):
    """Decode standard MF0UL11 static locks, OTP, and password/config protection."""
    analysis = {
        "supported": False,
        "reason": None,
        "static_lock_bytes": None,
        "block_lock_bits": None,
        "otp": None,
        "configuration": None,
        "pages": {},
    }

    required = [0x02, 0x03, 0x10, 0x11]
    missing = [p for p in required if p not in pages]
    if missing:
        analysis["reason"] = "missing required pages: " + ", ".join(f"0x{p:02X}" for p in missing)
        return analysis

    lock0 = pages[0x02][2]
    lock1 = pages[0x02][3]

    static_locked = {3: bool(lock0 & 0x08)}
    for page in range(4, 8):
        static_locked[page] = bool(lock0 & (1 << page))
    for page in range(8, 16):
        static_locked[page] = bool(lock1 & (1 << (page - 8)))

    block_locks = {
        "OTP_lock_bit_frozen": bool(lock0 & 0x01),
        "pages_04_09_lock_bits_frozen": bool(lock0 & 0x02),
        "pages_0A_0F_lock_bits_frozen": bool(lock0 & 0x04),
    }

    otp = pages[0x03]
    otp_set_bits = sum(byte.bit_count() for byte in otp)

    cfg0 = pages[0x10]
    cfg1 = pages[0x11]
    auth0 = cfg0[3]
    access = cfg1[0]
    prot = bool(access & 0x80)
    cfglck = bool(access & 0x40)
    authlim = access & 0x07
    password_enabled = auth0 <= 0x13

    config = {
        "CFG0_raw": hexstr(cfg0),
        "CFG1_raw": hexstr(cfg1),
        "MOD": f"{cfg0[0]:02X}",
        "AUTH0": f"{auth0:02X}",
        "password_protection_enabled": password_enabled,
        "ACCESS": f"{access:02X}",
        "PROT": int(prot),
        "PROT_meaning": "read+write protected" if prot else "write-only protected",
        "CFGLCK": int(cfglck),
        "configuration_pages_10_11_permanently_locked": cfglck,
        "AUTHLIM": authlim,
        "VCTID": f"{cfg1[1]:02X}",
        "PWD_readback": "masked as 00 00 00 00 by the tag",
        "PACK_readback": "masked as 00 00 by the tag",
    }

    page_rows = {}

    # Manufacturer/UID pages are read-only on genuine NXP MF0UL11. USCUID clones
    # can deliberately make them writable, which is outside the standard lock map.
    page_rows[0x00] = {
        "region": "manufacturer/UID",
        "locked": None,
        "write_status": "factory read-only on genuine NXP; clone-specific on USCUID",
        "password_write_required": False,
        "password_read_required": False,
    }
    page_rows[0x01] = {
        "region": "manufacturer/UID",
        "locked": None,
        "write_status": "factory read-only on genuine NXP; clone-specific on USCUID",
        "password_write_required": False,
        "password_read_required": False,
    }
    page_rows[0x02] = {
        "region": "BCC1/internal/static lock bytes",
        "locked": None,
        "write_status": "special: lock bits are one-way (0->1) on genuine NXP; clone-specific UID/BCC behavior may differ",
        "password_write_required": password_enabled and 0x02 >= auth0,
        "password_read_required": prot and password_enabled and 0x02 >= auth0,
    }

    for page in range(0x03, 0x10):
        locked = static_locked.get(page, False)
        pwd_write = password_enabled and page >= auth0
        pwd_read = prot and password_enabled and page >= auth0

        if page == 0x03:
            if locked:
                status = "PERMANENTLY LOCKED (OTP page)"
            else:
                status = "OTP one-way programmable only (0 bits may become 1; cannot erase 1 bits)"
            region = "OTP"
        else:
            status = "PERMANENTLY LOCKED" if locked else "writable"
            region = "user memory"

        page_rows[page] = {
            "region": region,
            "locked": locked,
            "write_status": status,
            "password_write_required": pwd_write,
            "password_read_required": pwd_read,
            "editable_in_current_authenticated_session": (not locked) if authenticated else ((not locked) and not pwd_write),
        }

    # Standard configuration pages.
    for page in (0x10, 0x11):
        pwd_write = password_enabled and page >= auth0
        pwd_read = prot and password_enabled and page >= auth0
        page_rows[page] = {
            "region": "configuration",
            "locked": cfglck,
            "write_status": "PERMANENTLY LOCKED by CFGLCK" if cfglck else "writable configuration",
            "password_write_required": pwd_write,
            "password_read_required": pwd_read,
            "editable_in_current_authenticated_session": not cfglck,
        }

    for page, region in ((0x12, "PWD (read masked)"), (0x13, "PACK/RFUI (PACK read masked)")):
        pwd_write = password_enabled and page >= auth0
        pwd_read = prot and password_enabled and page >= auth0
        page_rows[page] = {
            "region": region,
            "locked": False,
            "write_status": "writable after required authentication; secret value cannot be read back",
            "password_write_required": pwd_write,
            "password_read_required": pwd_read,
            "editable_in_current_authenticated_session": True if authenticated else not pwd_write,
        }

    analysis.update({
        "supported": True,
        "static_lock_bytes": {
            "lock_byte_0": f"{lock0:02X}",
            "lock_byte_1": f"{lock1:02X}",
        },
        "block_lock_bits": block_locks,
        "otp": {
            "raw": hexstr(otp),
            "set_bits": otp_set_bits,
            "zero_bits_remaining": 32 - otp_set_bits,
            "permanently_locked": static_locked[3],
            "lock_bit_frozen": block_locks["OTP_lock_bit_frozen"],
        },
        "configuration": config,
        "pages": {f"{page:02X}": row for page, row in page_rows.items()},
    })

    return analysis


def choose_output_base() -> Path:
    # User-requested BIN naming format: YYYY-MM-DD.bin
    base = Path(datetime.now().strftime("%Y-%m-%d"))
    outputs = [
        base.with_suffix(".bin"),
        Path(str(base) + ".scan.json"),
        Path(str(base) + ".scan.txt"),
    ]

    existing = [p for p in outputs if p.exists()]
    if not existing:
        return base

    print()
    print("[!] One or more output files already exist:")
    for path in existing:
        print(f"    {path}")

    answer = input("Overwrite today's scan files? [y/N]: ").strip().lower()
    if answer not in {"y", "yes"}:
        raise RuntimeError("Cancelled to avoid overwriting the existing scan")

    return base


def build_text_report(report: dict) -> str:
    lines = []
    card = report["card"]
    version = report["version"]

    lines.append("TMS512 FULL CARD SCAN")
    lines.append("=====================")
    lines.append(f"Time: {report['time']}")
    lines.append(f"Reader: {report['reader']['name']}")
    lines.append(f"UID: {card['uid']}")
    lines.append(f"ATQA: {card['atqa']}")
    lines.append(f"SAK: {card['sak']}")
    lines.append(f"Password authentication: {'SUCCESS' if report['authentication']['success'] else 'FAILED'}")
    if report["authentication"].get("pack"):
        lines.append(f"PACK returned: {report['authentication']['pack']}")
    lines.append(f"GET_VERSION: {version.get('raw')}")
    lines.append(f"Detected variant: {version.get('variant')}")
    lines.append("")

    bcc = report.get("uid_bcc", {})
    if bcc:
        lines.append("UID / BCC")
        lines.append("---------")
        lines.append(f"Memory UID: {bcc.get('memory_uid')}")
        lines.append(f"BCC0: actual={bcc.get('bcc0_actual')} expected={bcc.get('bcc0_expected')} ok={bcc.get('bcc0_ok')}")
        lines.append(f"BCC1: actual={bcc.get('bcc1_actual')} expected={bcc.get('bcc1_expected')} ok={bcc.get('bcc1_ok')}")
        lines.append("")

    locking = report.get("locking", {})
    if locking.get("supported"):
        lines.append("LOCK / OTP / ACCESS SCAN (MF0UL11 standard map)")
        lines.append("---------------------------------------------")
        sl = locking["static_lock_bytes"]
        lines.append(f"Static lock bytes: {sl['lock_byte_0']} {sl['lock_byte_1']}")
        lines.append(f"Block lock bits: {json.dumps(locking['block_lock_bits'])}")
        otp = locking["otp"]
        lines.append(
            f"OTP page 03: {otp['raw']} | set bits={otp['set_bits']}/32 | "
            f"remaining zero bits={otp['zero_bits_remaining']} | permanently_locked={otp['permanently_locked']}"
        )
        cfg = locking["configuration"]
        lines.append(
            f"AUTH0={cfg['AUTH0']} PROT={cfg['PROT']} CFGLCK={cfg['CFGLCK']} "
            f"AUTHLIM={cfg['AUTHLIM']} VCTID={cfg['VCTID']}"
        )
        lines.append("")
        lines.append("Page writeability / lock status")
        lines.append("--------------------------------")
        for page_hex, row in locking["pages"].items():
            pwd = "PWD" if row.get("password_write_required") else "no-PWD"
            lock_text = row.get("write_status")
            lines.append(f"{page_hex}: {row.get('region'):<32} {lock_text} [{pwd}]")
        lines.append("")
    else:
        lines.append("Lock analysis: not decoded as MF0UL11 standard map")
        lines.append(f"Reason: {locking.get('reason')}")
        lines.append("")

    lines.append("COUNTERS / TEARING")
    lines.append("------------------")
    for idx in range(3):
        item = report["counters"].get(str(idx), {})
        counter = item.get("counter")
        tearing = item.get("tearing")
        if counter:
            counter_text = f"raw={counter['raw']} value={counter['value_lsb_first']}"
        else:
            counter_text = f"unavailable ({item.get('counter_error')})"
        if tearing:
            tear_text = f"flag={tearing['flag']} valid={tearing['valid']}"
        else:
            tear_text = f"unavailable ({item.get('tearing_error')})"
        lines.append(f"Counter {idx}: {counter_text}; tearing: {tear_text}")
    lines.append("")

    sig = report.get("originality_signature", {})
    lines.append("ORIGINALITY SIGNATURE")
    lines.append("---------------------")
    if sig.get("raw"):
        lines.append(sig["raw"])
        lines.append("Captured only; this script does not cryptographically verify the signature.")
    else:
        lines.append(f"Unavailable: {sig.get('error')}")
    lines.append("")

    lines.append("RAW EEPROM PAGES")
    lines.append("----------------")
    for page_hex, data in report["pages"].items():
        lines.append(f"{page_hex}: {data}")

    if report.get("page_read_errors"):
        lines.append("")
        lines.append("PAGE READ ERRORS")
        lines.append("----------------")
        for page_hex, error in report["page_read_errors"].items():
            lines.append(f"{page_hex}: {error}")

    lines.append("")
    lines.append("NOTES")
    lines.append("-----")
    lines.append("The .bin file is raw linear EEPROM page data only.")
    lines.append("Counters and the 32-byte originality signature are command-accessed data, so they are stored in the .scan.json/.scan.txt sidecars instead of being appended to the BIN.")
    lines.append("PWD and PACK readback bytes are masked by compliant MF0UL11 tags; zeroes in their pages do not reveal the actual secret values.")
    lines.append("This scan is read-only with respect to EEPROM/user data. No WRITE, COMPATIBILITY_WRITE, or INCR_CNT command is sent.")

    return "\n".join(lines) + "\n"


async def main():
    print()
    print("TMS512 Full Password Card Scanner")
    print("=================================")
    print()
    print("Read-only scan: no EEPROM WRITE or counter increment commands are sent.")
    print("For Ultralight EV1, the report decodes lock bits and OTP state without write-testing pages.")
    print()

    device = await find_reader()
    if device is None:
        print("[!] Minicopy BLE reader not found.")
        print("[!] Disconnect LightBlue and try again.")
        return

    print(f"[+] Found: {device.name}")
    print(f"[*] Connecting to {device.address}...")

    async with BleakClient(device) as client:
        print("[+] Connected")

        rx = client.services.get_characteristic(RX_UUID)
        tx = client.services.get_characteristic(TX_UUID)

        if rx is None or tx is None:
            raise RuntimeError("FF01/FF02 characteristics not found")

        pn = PN532BLE(client, rx, tx)
        await pn.start()

        try:
            firmware = await get_pn532_firmware(pn)
            if firmware:
                print(
                    "[+] PN532 firmware: "
                    f"IC=0x{firmware['ic']:02X} "
                    f"Version={firmware['version']} "
                    f"Revision={firmware['revision']} "
                    f"Support=0x{firmware['support']:02X}"
                )

            print()
            print("Place ONE Ultralight/NTAG-style card on the reader.")
            await asyncio.to_thread(input, "Press Enter when ready... ")

            print()
            print("[*] Selecting card...")
            target = await select_card(pn)

            if target is None:
                print("[!] No ISO14443-A card detected.")
                return

            uid = target["uid"]
            print("[+] Card detected")
            print(f"[+] UID:  {hexstr(uid)}")
            print(f"[+] ATQA: {hexstr(target['atqa'])}")
            print(f"[+] SAK:  {target['sak']:02X}")
            if target["ats"]:
                print(f"[+] ATS:  {hexstr(target['ats'])}")

            if target["sak"] != 0x00:
                print()
                print("[!] This does not look like the same Ultralight/Type-2 style tag.")
                print("[!] Refusing to continue with Ultralight PWD_AUTH.")
                return

            # Identify the variant before authentication when possible.
            version_raw = await get_type2_version(pn)
            version_info = decode_version(version_raw)
            if version_raw:
                print(f"[+] GET_VERSION: {hexstr(version_raw)}")
                print(f"[+] Variant: {version_info['variant']}")

            print()
            print("[!] One password attempt is made per run. On a tag configured with AUTHLIM,")
            print("    a wrong password may count toward its failed-authentication limit.")
            password_text = await asyncio.to_thread(
                input,
                f"Password [{DEFAULT_PASSWORD}]: ",
            )

            try:
                password = parse_password(password_text)
            except ValueError as exc:
                print(f"[!] {exc}")
                return

            print(f"[*] Authenticating with {password.hex().upper()}...")
            success, pack, error = await pwd_auth(pn, password)

            if not success:
                print(f"[!] Authentication failed: {error}")
                return

            print("[+] Password accepted")
            print(f"[+] PACK: {hexstr(pack)}")

            # Some clones only answer GET_VERSION reliably after authentication.
            if version_raw is None:
                version_raw = await get_type2_version(pn)
                version_info = decode_version(version_raw)
                if version_raw:
                    print(f"[+] GET_VERSION after auth: {hexstr(version_raw)}")
                    print(f"[+] Variant: {version_info['variant']}")

            pages, page_errors = await dump_pages(
                pn,
                target["target_number"],
                version_info.get("total_pages"),
            )

            if not pages:
                print("[!] No card memory was read.")
                return

            print()
            print("[*] Reading three one-way counters + tearing flags...")
            counters = {}
            for idx in range(3):
                counter, counter_error = await read_counter(pn, idx)
                tearing, tearing_error = await check_tearing(pn, idx)
                counters[str(idx)] = {
                    "counter": counter,
                    "counter_error": counter_error,
                    "tearing": tearing,
                    "tearing_error": tearing_error,
                }

                c_text = counter["raw"] if counter else f"ERR: {counter_error}"
                t_text = (
                    f"{tearing['flag']} ({'OK' if tearing['valid'] else 'TEARING FLAG'})"
                    if tearing else f"ERR: {tearing_error}"
                )
                print(f"    Counter {idx}: {c_text}; tearing={t_text}")

            print()
            print("[*] Reading 32-byte originality signature...")
            signature, signature_error = await read_signature(pn)
            if signature:
                print(f"[+] Signature: {hexstr(signature)}")
            else:
                print(f"[*] Signature unavailable: {signature_error}")

            uid_bcc = analyze_uid_bcc(pages, uid)

            if version_info.get("variant", "").startswith("MIFARE Ultralight EV1 MF0UL11"):
                locking = analyze_mf0ul11_locking(pages, authenticated=True)
            else:
                locking = {
                    "supported": False,
                    "reason": "automatic detailed lock decoder in this version is targeted at MF0UL11-compatible cards",
                }

            blob = pages_to_blob(pages, version_info.get("total_pages"))
            base = choose_output_base()
            bin_path = base.with_suffix(".bin")
            json_path = Path(str(base) + ".scan.json")
            txt_path = Path(str(base) + ".scan.txt")

            bin_path.write_bytes(blob)

            report = {
                "time": datetime.now().isoformat(timespec="seconds"),
                "reader": {
                    "name": device.name,
                    "ble_identifier": device.address,
                    "pn532_firmware": firmware,
                },
                "card": {
                    "uid": uid.hex().upper(),
                    "atqa": target["atqa"].hex().upper(),
                    "sak": f"{target['sak']:02X}",
                    "ats": target["ats"].hex().upper() if target["ats"] else None,
                },
                "authentication": {
                    "attempted": True,
                    "success": True,
                    "pack": pack.hex().upper(),
                    "password_not_saved": True,
                },
                "version": version_info,
                "uid_bcc": uid_bcc,
                "locking": locking,
                "otp": locking.get("otp") if isinstance(locking, dict) else None,
                "counters": counters,
                "originality_signature": {
                    "raw": hexstr(signature) if signature else None,
                    "error": signature_error,
                    "cryptographically_verified": False,
                },
                "pages": {f"{page:02X}": hexstr(data) for page, data in sorted(pages.items())},
                "page_read_errors": {f"{page:02X}": error for page, error in sorted(page_errors.items())},
                "files": {
                    "bin": str(bin_path),
                    "scan_json": str(json_path),
                    "scan_txt": str(txt_path),
                },
                "bin_bytes": len(blob),
                "notes": [
                    "BIN contains only linear EEPROM page data.",
                    "Counters and originality signature are stored in sidecar scan files because they are command-accessed data, not linear EEPROM pages.",
                    "PWD and PACK memory readback is masked by compliant MF0UL11 tags.",
                    "No EEPROM write, compatibility-write, or counter-increment command is sent by this scanner.",
                    "USCUID clone-specific DirectWrite/magic configuration is not actively probed because it is outside the standard MF0UL11 lock map.",
                ],
            }

            json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
            txt_path.write_text(build_text_report(report), encoding="utf-8")

            print()
            print("=================================")
            print("[+] FULL SCAN COMPLETE")
            print(f"[+] Raw EEPROM BIN: {bin_path}")
            print(f"[+] Detailed JSON:  {json_path}")
            print(f"[+] Human report:   {txt_path}")
            print(f"[+] EEPROM bytes:   {len(blob)}")
            if locking.get("supported"):
                print(f"[+] OTP:            {locking['otp']['raw']}")
                locked_pages = [
                    page_hex
                    for page_hex, row in locking["pages"].items()
                    if row.get("locked") is True
                ]
                print(f"[+] Locked pages:   {', '.join(locked_pages) if locked_pages else 'none in standard lock map'}")
            print("=================================")

        finally:
            await pn.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print()
        print("[*] Cancelled.")
    except Exception as exc:
        print()
        print(f"[!] Error: {exc}")
