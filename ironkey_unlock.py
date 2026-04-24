#!/usr/bin/env python3
"""
Kingston IronKey Locker+ - Unlock Tool
=======================================
Finds and unlocks any IronKey Locker+ USB drive on Linux.

Discovers the device by Kingston VID (0x0951) and validates it via
USB string descriptors, so no hardcoded PIDs are needed. This allows
the tool to work with any capacity variant (16G2, 32G2, 50G2, etc.).

Usage:
    sudo python3 ironkey_unlock.py              # prompt for password
    sudo python3 ironkey_unlock.py -p PASSWORD   # pass password inline
"""

import argparse
import ctypes
import fcntl
import getpass
import hashlib
import os
import select
import struct
import subprocess
import sys
import time

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.number import getPrime, inverse
except ImportError:
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.number import getPrime, inverse
    except ImportError:
        print(
            "Error: pycryptodome is required.\n"
            "\n"
            "Install with one of:\n"
            "  pip install pycryptodome\n"
            "  apt install python3-pycryptodome"
        )
        sys.exit(1)


VID_KINGSTON = 0x0951
MROT_MAGIC = 0x4D524F54
HID_FEATURE_SIZE = 512
PRODUCT_KEYWORDS = ("ironkey", "locker")

PVC0_KEY = bytes.fromhex(
    "6aed67b98bcf83f2a0d6227fb8a358c4"
    "74e7db472b9ddcd509af8bef1cb9c8b8"
    "949ce641ccafe1d5847d8dcc79e1ba18"
    "215c80b75c4e10dd6442ffacbcbd1684"
)


def _HIDIOC(dir_, nr, length):
    return (dir_ << 30) | (0x48 << 8) | nr | (length << 16)


HIDIOCSFEATURE = lambda l: _HIDIOC(3, 0x06, l)
HIDIOCGFEATURE = lambda l: _HIDIOC(3, 0x07, l)

USBDEVFS_CONTROL = 0xC0185500
USBDEVFS_DISCONNECT = 0x81015505

USB_DT_DEVICE = 0x01
USB_DT_STRING = 0x03
USB_REQ_GET_DESCRIPTOR = 0x06
USB_ENDPOINT_IN = 0x80
LANGID_US_ENGLISH = 0x0409


class UsbCtrlTransfer(ctypes.Structure):
    _fields_ = [
        ("bRequestType", ctypes.c_uint8),
        ("bRequest", ctypes.c_uint8),
        ("wValue", ctypes.c_uint16),
        ("wIndex", ctypes.c_uint16),
        ("wLength", ctypes.c_uint16),
        ("timeout", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("data", ctypes.c_void_p),
    ]


class IronKeyError(Exception):
    pass


class DeviceNotFoundError(IronKeyError):
    pass


class PidSwitchError(IronKeyError):
    pass


class HandshakeError(IronKeyError):
    pass


class UnlockError(IronKeyError):
    pass


def log(msg=""):
    print(msg, flush=True)


def usb_control(fd, bmRequestType, bRequest, wValue, wIndex, data_or_len,
                timeout=5000):
    if isinstance(data_or_len, int):
        wLength = data_or_len
        buf = (ctypes.c_uint8 * wLength)()
    else:
        wLength = len(data_or_len)
        buf = (ctypes.c_uint8 * wLength)(*data_or_len)
    ctrl = UsbCtrlTransfer()
    ctrl.bRequestType = bmRequestType
    ctrl.bRequest = bRequest
    ctrl.wValue = wValue
    ctrl.wIndex = wIndex
    ctrl.wLength = wLength
    ctrl.timeout = timeout
    ctrl._pad = 0
    ctrl.data = ctypes.cast(buf, ctypes.c_void_p)
    fcntl.ioctl(fd, USBDEVFS_CONTROL, ctrl)
    return bytes(buf)


def usb_read_string(fd, index, langid=LANGID_US_ENGLISH, length=255):
    data = usb_control(fd, USB_ENDPOINT_IN, USB_REQ_GET_DESCRIPTOR,
                       (USB_DT_STRING << 8) | index, langid, length)
    if not data or len(data) < 4 or data[1] != USB_DT_STRING:
        return None
    try:
        return data[2:data[0]].decode("utf-16-le")
    except (UnicodeDecodeError, ValueError):
        return None


def enum_usb_devices():
    devices = []
    for root, dirs, _files in os.walk("/sys/bus/usb/devices/"):
        for d in dirs:
            dev_path = os.path.join(root, d)
            vid_file = os.path.join(dev_path, "idVendor")
            pid_file = os.path.join(dev_path, "idProduct")
            if not (os.path.isfile(vid_file) and os.path.isfile(pid_file)):
                continue
            try:
                with open(vid_file) as f:
                    dev_vid = int(f.read().strip(), 16)
                with open(pid_file) as f:
                    dev_pid = int(f.read().strip(), 16)
                bus_file = os.path.join(dev_path, "busnum")
                devnum_file = os.path.join(dev_path, "devnum")
                serial_file = os.path.join(dev_path, "serial")
                serial = ""
                if os.path.isfile(serial_file):
                    with open(serial_file) as f:
                        serial = f.read().strip()
                if os.path.isfile(bus_file) and os.path.isfile(devnum_file):
                    with open(bus_file) as f:
                        bus = int(f.read().strip())
                    with open(devnum_file) as f:
                        devnum = int(f.read().strip())
                    usbfs = f"/dev/bus/usb/{bus:03d}/{devnum:03d}"
                    if os.path.exists(usbfs):
                        devices.append({
                            "vid": dev_vid, "pid": dev_pid,
                            "bus": bus, "devnum": devnum,
                            "usbfs": usbfs, "serial": serial,
                            "sysfs": dev_path,
                        })
            except (ValueError, OSError):
                continue
    return devices


def find_ironkey_locked(serial_filter=None):
    for dev in enum_usb_devices():
        if dev["vid"] != VID_KINGSTON:
            continue
        try:
            fd = os.open(dev["usbfs"], os.O_RDWR)
        except OSError:
            continue
        try:
            desc = usb_control(fd, USB_ENDPOINT_IN, USB_REQ_GET_DESCRIPTOR,
                               USB_DT_DEVICE << 8, 0, 18)
            if not desc or len(desc) < 18:
                continue
            i_product = desc[15]
            product = usb_read_string(fd, i_product) or ""
            if not any(kw in product.lower() for kw in PRODUCT_KEYWORDS):
                continue
            i_serial = desc[16]
            serial = usb_read_string(fd, i_serial) or ""
            if serial_filter and serial.upper() != serial_filter.upper():
                log(f"Skipping {product} (S/N {serial}) - not the target device")
                continue
            dev["product"] = product
            dev["serial"] = serial
            dev["i_serial"] = i_serial
            return dev
        except OSError:
            continue
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
    return None


def find_ironkey_hidraw(serial_filter=None):
    for dev_name in sorted(
        f for f in os.listdir("/dev") if f.startswith("hidraw")
    ):
        try:
            with open(f"/sys/class/hidraw/{dev_name}/device/uevent") as f:
                content = f.read()
            vid = pid = None
            name = ""
            uniq = ""
            for line in content.splitlines():
                if line.startswith("HID_ID="):
                    parts = line.split("=")[1].split(":")
                    if len(parts) >= 3:
                        vid = int(parts[1], 16)
                        pid = int(parts[2], 16)
                elif line.startswith("HID_NAME="):
                    name = line.split("=", 1)[1]
                elif line.startswith("HID_UNIQ="):
                    uniq = line.split("=", 1)[1].strip()
            if vid == VID_KINGSTON and any(
                kw in name.lower() for kw in ("kingston", "locker", "ironkey")
            ):
                if serial_filter and uniq and uniq.upper() != serial_filter.upper():
                    continue
                return f"/dev/{dev_name}", name
        except (OSError, ValueError):
            continue
    return None, None


def unmount_volumes():
    try:
        result = subprocess.run(
            ["findmnt", "-lo", "SOURCE,TARGET"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                source, mountpoint = parts[0], parts[1]
                if "/sr" in source or "/sg" in source or "IronKey" in source:
                    subprocess.run(["umount", mountpoint], timeout=10,
                                   capture_output=True)
    except Exception:
        pass
    try:
        subprocess.run(["eject", "/dev/sr0"], timeout=10, capture_output=True)
    except Exception:
        pass


def trigger_pid_switch(dev):
    usbfs_path = dev["usbfs"]
    unmount_volumes()

    fd = os.open(usbfs_path, os.O_RDWR)
    try:
        for intf_num in range(8):
            try:
                fcntl.ioctl(fd, USBDEVFS_DISCONNECT, intf_num)
            except OSError:
                pass

        desc = usb_control(fd, USB_ENDPOINT_IN, USB_REQ_GET_DESCRIPTOR,
                           USB_DT_DEVICE << 8, 0, 18)
        if not desc or len(desc) < 18:
            raise PidSwitchError("Failed to read device descriptor")

        i_serial = desc[16]
        if i_serial == 0:
            raise PidSwitchError("Device has no serial number")

        idx2 = i_serial + 2
        idx3 = i_serial + 3
        pattern = [idx2, idx2, idx3, idx3, idx2, idx2]

        for i, idx in enumerate(pattern):
            try:
                usb_control(fd, USB_ENDPOINT_IN, USB_REQ_GET_DESCRIPTOR,
                            (USB_DT_STRING << 8) | idx, LANGID_US_ENGLISH, 16)
            except OSError:
                if i == len(pattern) - 1:
                    break
            if i < len(pattern) - 1:
                time.sleep(0.1)

        time.sleep(3)
        return True
    except OSError:
        return True
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def hid_set_feature(fd, data):
    buf_len = HID_FEATURE_SIZE + 1
    buf = bytearray(buf_len)
    buf[1:1 + len(data)] = data
    fcntl.ioctl(fd, HIDIOCSFEATURE(buf_len),
                (ctypes.c_char * buf_len).from_buffer(buf))


def hid_get_feature(fd, size=HID_FEATURE_SIZE):
    buf_len = size + 1
    buf = (ctypes.c_char * buf_len)()
    fcntl.ioctl(fd, HIDIOCGFEATURE(buf_len), buf)
    return bytes(buf)[1:]


def read_interrupt(fd, timeout=2.0):
    r, _, _ = select.select([fd], [], [], timeout)
    if r:
        return os.read(fd, 64)
    return None


def drain_interrupts(fd, timeout=0.2):
    while True:
        if not read_interrupt(fd, timeout):
            break


def send_hid(fd, sub, cdb2, direction, data=b"", data_len=0,
             cdb3_10=b"\x00" * 8):
    actual_len = data_len if data_len else len(data)
    out = bytearray(64)
    out[0] = sub
    out[1] = cdb2
    struct.pack_into("<I", out, 0x02, actual_len)
    struct.pack_into("<I", out, 0x06, 1 if actual_len > 0 else 0)
    struct.pack_into("<I", out, 0x0A, MROT_MAGIC)
    out[0x0E] = 1 if direction == "read" else 0
    out[0x0F] = 0
    out[0x10:0x18] = cdb3_10[:8]

    os.write(fd, b"\x00" + bytes(out))

    ack = read_interrupt(fd, 2.0)
    if not ack:
        raise IronKeyError(f"No interrupt ACK for command 0x{sub:02X}")

    if direction == "write" and data:
        hid_set_feature(fd, data)
        resp = read_interrupt(fd, 2.0)
        if resp and len(resp) >= 6:
            status = struct.unpack_from("<H", resp, 4)[0]
            if status != 0:
                raise IronKeyError(
                    f"Command 0x{sub:02X} error: status=0x{status:04X}"
                )
        return b""

    if direction == "read" and actual_len > 0:
        time.sleep(0.3)
        result = hid_get_feature(fd, 512)
        read_interrupt(fd, 2.0)
        return result[:actual_len] if len(result) >= actual_len else result

    resp = read_interrupt(fd, 2.0)
    if resp and len(resp) >= 6:
        status = struct.unpack_from("<H", resp, 4)[0]
        if status != 0:
            raise IronKeyError(
                f"Command 0x{sub:02X} error: status=0x{status:04X}"
            )
    return b""


def aes128_ecb_encrypt(key, block):
    assert len(key) == 16 and len(block) == 16
    return AES.new(key, AES.MODE_ECB).encrypt(block)


def generate_rsa512():
    e = 65537
    while True:
        p = getPrime(256)
        q = getPrime(256)
        n = p * q
        if n.bit_length() == 512:
            phi = (p - 1) * (q - 1)
            try:
                d = inverse(e, phi)
                return (n.to_bytes(64, "little"),
                        e.to_bytes(64, "little"),
                        d.to_bytes(64, "little"))
            except ValueError:
                continue


def clamp(buf, n_dev):
    b = bytearray(buf)
    for i in range(63, -1, -1):
        if b[i] != 0:
            b[i] = max(0, n_dev[63] - 1)
            break
    return bytes(b)


def encrypt_pvc_key(pvc0_key, shared_secret):
    hash1 = hashlib.sha256(pvc0_key).digest()
    local = bytearray(64)
    local[0:32] = hash1
    local[32:48] = shared_secret
    hash2 = hashlib.sha256(bytes(local[0:48])).digest()
    local[0:32] = hash2
    local[32:48] = bytes(16)
    import random
    random.seed()
    for i in range(32):
        local[32 + i] = random.getrandbits(8)
    result = b""
    for i in range(4):
        result += aes128_ecb_encrypt(shared_secret,
                                     bytes(local[i * 16:(i + 1) * 16]))
    return result


def rsa_handshake(fd):
    drain_interrupts(fd)

    resp = send_hid(fd, 0x81, 0x00, "read", data_len=128)
    if not resp or len(resp) < 128:
        raise HandshakeError("FF 81: failed to read device public key")
    N_dev = resp[:64]
    E_dev = resp[64:128]
    N_dev_int = int.from_bytes(N_dev, "little")
    E_dev_int = int.from_bytes(E_dev, "little")

    N_host, E_host, D_host = generate_rsa512()

    send_hid(fd, 0x82, 0x00, "write", data=N_host + E_host)

    r1_bytes = clamp(os.urandom(64), N_dev)
    send_hid(fd, 0x83, 0x00, "write", data=r1_bytes)

    sig1 = send_hid(fd, 0x84, 0x00, "read", data_len=64)
    if not sig1 or len(sig1) < 64:
        raise HandshakeError("FF 84: failed to read device signature")

    nonce_dev = send_hid(fd, 0x85, 0x00, "read", data_len=64)
    if not nonce_dev or len(nonce_dev) < 64:
        raise HandshakeError("FF 85: failed to read device nonce")

    ff86_int = pow(int.from_bytes(nonce_dev, "little"),
                   int.from_bytes(D_host, "little"),
                   int.from_bytes(N_host, "little"))
    send_hid(fd, 0x86, 0x00, "write",
             data=ff86_int.to_bytes(64, "little"))

    r2_bytes = clamp(os.urandom(64), N_dev)
    ff87_int = pow(int.from_bytes(r2_bytes, "little"), E_dev_int, N_dev_int)
    send_hid(fd, 0x87, 0x00, "write",
             data=ff87_int.to_bytes(64, "little"))

    sig2 = send_hid(fd, 0x88, 0x00, "read", data_len=64)
    if not sig2 or len(sig2) < 64:
        raise HandshakeError("FF 88: failed to read device secret")

    r_dev_int = pow(int.from_bytes(sig2, "little"),
                    int.from_bytes(D_host, "little"),
                    int.from_bytes(N_host, "little"))
    r_dev_bytes = r_dev_int.to_bytes(64, "little")
    shared = bytes(a ^ b for a, b in zip(r2_bytes[:16], r_dev_bytes[:16]))
    return shared


def send_unlock(fd, shared, password):
    pvc_payload = encrypt_pvc_key(PVC0_KEY, shared)

    send_hid(fd, 0x8B, 0x00, "none",
             cdb3_10=bytes([0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))

    send_hid(fd, 0x8F, 0x00, "write", data=pvc_payload,
             cdb3_10=bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))

    plaintext = password.encode("utf-8").ljust(16, b"\x00")
    if len(password.encode("utf-8")) > 16:
        raise UnlockError("Password too long (max 16 bytes)")
    encrypted_pw = aes128_ecb_encrypt(shared, plaintext)

    send_hid(fd, 0xA4, 0x00, "write", data=encrypted_pw, data_len=16,
             cdb3_10=bytes([0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00]))

    send_hid(fd, 0x89, 0x00, "none")


def block_device_usb_vid(name):
    path = os.path.realpath(f"/sys/block/{name}/device")
    while path != "/":
        vid_file = os.path.join(path, "idVendor")
        if os.path.isfile(vid_file):
            try:
                with open(vid_file) as f:
                    return int(f.read().strip(), 16)
            except (ValueError, OSError):
                return None
        path = os.path.dirname(path)
    return None


def block_device_usb_serial(name):
    path = os.path.realpath(f"/sys/block/{name}/device")
    while path != "/":
        serial_file = os.path.join(path, "serial")
        if os.path.isfile(serial_file):
            try:
                with open(serial_file) as f:
                    return f.read().strip()
            except OSError:
                return None
        path = os.path.dirname(path)
    return None


def find_data_partition(serial_filter=None):
    try:
        result = subprocess.run(
            ["lsblk", "-dbno", "NAME,SIZE,TYPE"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                name, size_s, typ = parts[0], parts[1], parts[2]
                if (typ == "disk" and name.startswith("sd")
                        and int(size_s) > 0
                        and block_device_usb_vid(name) == VID_KINGSTON):
                    if serial_filter:
                        dev_serial = block_device_usb_serial(name)
                        if not dev_serial or dev_serial.upper() != serial_filter.upper():
                            continue
                    return f"/dev/{name}", int(size_s)
    except Exception:
        pass
    return None, 0


def main():
    parser = argparse.ArgumentParser(
        description="Unlock Kingston IronKey Locker+ USB drive")
    parser.add_argument("-p", "--password",
                        help="Password (otherwise prompted)")
    parser.add_argument("-s", "--serial",
                        help="Target device serial number - use when multiple "
                             "Kingston devices are connected "
                             "(e.g. -s 80C5F260C690B93031833015)")
    args = parser.parse_args()
    serial_filter = args.serial or None

    log("IronKey Locker+ Unlock Tool")
    log("=" * 40)
    if serial_filter:
        log(f"Targeting serial: {serial_filter}")

    # Step 1: Check if already unlocked
    part_dev, part_size = find_data_partition(serial_filter)
    if part_dev and part_size > 1_000_000:
        log(f"Data partition already visible at {part_dev} "
            f"({part_size / (1 << 30):.1f} GiB)")
        return 0

    # Step 2: Get password
    password = args.password or getpass.getpass("IronKey password: ")
    if not password:
        log("Error: no password provided")
        return 1

    # Step 3: Find hidraw device (HID mode) or locked USB device
    hidraw_path, hid_name = find_ironkey_hidraw(serial_filter)
    if hidraw_path:
        log(f"Found HID device: {hidraw_path} ({hid_name})")
    else:
        dev = find_ironkey_locked(serial_filter)
        if not dev:
            if serial_filter:
                log(f"Error: No IronKey with serial {serial_filter} found.")
            else:
                log("Error: No IronKey device found. Plug it in and try again.")
            log("  (lsusb | grep -i kingston)")
            return 1

        log(f"Found {dev['product']} (PID {dev['pid']:04X}, "
            f"S/N {dev['serial']})")
        log("Triggering HID mode switch...")

        try:
            trigger_pid_switch(dev)
        except PidSwitchError as e:
            log(f"Error: {e}")
            log("  Try physically replugging the device.")
            return 1

        hidraw_path, hid_name = find_ironkey_hidraw(serial_filter)
        if not hidraw_path:
            log("Error: PID switch completed but no HID device found.")
            log("  Try replugging the device.")
            return 1

        log(f"HID device: {hidraw_path}")

    # Step 4: Open and unlock
    fd = os.open(hidraw_path, os.O_RDWR | os.O_NONBLOCK)
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)

    try:
        shared = rsa_handshake(fd)
        send_unlock(fd, shared, password)
    except IronKeyError as e:
        log(f"Error: {e}")
        os.close(fd)
        return 1
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    # Step 5: Verify partition appeared
    log("Waiting for data partition...")
    for _ in range(10):
        time.sleep(1)
        part_dev, part_size = find_data_partition(serial_filter)
        if part_dev and part_size > 1_000_000:
            log(f"SUCCESS: Data partition at {part_dev} "
                f"({part_size / (1 << 30):.1f} GiB)")
            return 0

    log("Error: unlock commands succeeded but no partition appeared.")
    log("  Check: lsblk; dmesg | tail -20")
    return 1


if __name__ == "__main__":
    sys.exit(main())
