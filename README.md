# ironkey-unlocker

A Linux tool to unlock Kingston IronKey Locker+ 50G2 (and likely other
capacity variants) encrypted USB drives. Kingston only ships official
software for macOS and Windows; this implements the proprietary
authentication protocol natively on Linux.

Amazon affiliate link to item: https://amzn.to/4vDLm4E

## NOTE

This does not allow you to unlock keys you don't have the password to, or
expose any flaw or weakness in the device. This just enabled legitimate 
access to your device on Linux systems..

## Requirements

- Linux with `hidraw` kernel support (standard on most distros)
- Python 3.8+
- `pycryptodome` (`pip install pycryptodome`)
- Root access (`sudo`) for USB device access
- Kingston IronKey (Maybe only G2 devices?) already set up in Password mode

## Usage

```bash
# Interactive (prompts for password)
sudo python3 ironkey_unlock.py

# Inline password
sudo python3 ironkey_unlock.py -p 'MyP@ssw0rd!'
```

The tool will:
1. Detect a plugged-in IronKey by Kingston VID (0x0951) and product name
2. Switch the device into HID mode if it's locked
3. Perform RSA-512 key exchange + AES-128 authentication
4. Verify the encrypted data partition appears

No hardcoded PIDs — it discovers the device by vendor ID and USB string
descriptors, so it should work with any Locker+ capacity variant (16G2,
32G2, 50G2, etc.) without modification.

If the drive is already unlocked (data partition visible), it exits
immediately.

## How It Works

See [PROTOCOL.md](PROTOCOL.md) for the complete authentication sequence
with byte-level detail.


## Background

Kingston sent me an IronKey review unit, but I guess the individual handling
review units didn't recognize that they didn't have Linux compatibility. Well,
I suppose they picked the right Youtuber, because I took that on as a side-quest.

## Reverse Engineering Methodology

### Overview

The IronKey Locker+ uses a proprietary authentication protocol over USB.
When locked, the device presents as a mass-storage device with a read-only
CD-ROM partition containing the vendor software. Unlocking requires:

1. Switching the device into a hidden HID mode
2. Performing a mutual RSA-512 key exchange
3. Sending the user password encrypted with the negotiated session key

No documentation existed for any of this.

### Phase 1: USB Capture (Windows/macOS)

The Windows and macOS IronKey applications were used with Wireshark to capture
a complete unlock session. Initial analysis of the pcap was misleading and conflicting..
The capture contained SCSI bulk transfers, not the HID commands the
application ultimately uses. This was a long stall in the process.

### Phase 2: Binary Reverse Engineering (Ghidra)

The macOS IronKey application binary was loaded into Ghidra for
decompilation. Key functions were identified and analyzed:

- **`activateHIDInterface`** — Discovered the PID switch mechanism: reading
  USB string descriptors in a specific pattern (indices iSerial+2, iSerial+2,
  iSerial+3, iSerial+3, iSerial+2, iSerial+2) causes the device firmware to
  switch from PID 0x159D (mass-storage only) to a mode exposing a HID
  interface.

- **`sendHIDCommand`** — Mapped the HID output report format: a 64-byte
  report containing the subcommand byte, data length, MROT magic
  (0x4D524F54), direction flag, and CDB parameters. Data payloads travel
  via 512-byte HID Feature reports.

- **`_UDV_Login` → `NTU_PVC_Open` → `PVCOpen` → `openPVC`** — Traced the
  full login call chain, identifying the sequence of HID subcommands (FF 81
  through FF A4) and their parameters.

- **`encryptPVCKey`** — Decompiled the PVC key encryption algorithm:
  SHA-256 hash chaining combined with AES-128-ECB encryption using the RSA
  session key.

- **`encryptWithKey`** — Simple AES-128-ECB encryption of the password
  using the shared secret from the RSA handshake.

### Phase 3: LLDB Debugging (macOS)

A parallel macOS agent was used for live debugging of the IronKey
application with LLDB. (see https://github.com/wltechblog/agentchat-mcp for another
side quest to make THAT work!)
Breakpoints were set on cryptographic functions to capture intermediate values:

- Verified the `encryptPVCKey` algorithm by capturing the SHA-256
  intermediate hashes and comparing against our Python reimplementation.

- Confirmed the shared secret derivation from the RSA handshake by
  breakpointing after the key exchange completed.

- Captured the exact bytes sent for FF A4 (NTU_Open), revealing the
  correct parameter layout (secureType=0, timeInterval=6) that was
  previously incorrect.

### Phase 4: pcap Re-analysis

With the Ghidra knowledge, the original pcap was re-examined. The macOS
agent found FF A4 in subsequent logins (not the first), and identified the
critical missing steps:

- **FF 89 (Commit)** — A commit command that must follow FF A4. This was
  the single missing piece preventing unlock.
- **FF A4 parameter correction** — The CDB bytes 8-11 should be `00 00 00
  06`, not the values we had been using.

### Phase 5: Linux Implementation

The complete protocol was implemented in Python using Linux `hidraw`:

- **HID transport**: `write()` for output reports, `ioctl(HIDIOCSFEATURE)`
  for feature reports, `read()` for interrupt endpoint responses.
- **PID switch**: Direct `usbdevfs` control transfers via `ioctl`.
- **Crypto**: PyCryptodome/cryptography for RSA-512 and AES-128-ECB.

### Tools Used

| Tool | Purpose |
|------|---------|
| Wireshark | USB packet capture on macOS and Windows |
| Ghidra | Decompilation of macOS an Windows IronKey binaries |
| LLDB | Live debugging of crypto operations on macOS |
| Python | Protocol implementation and testing |
| Linux usbdevfs | Raw USB control transfers for PID switch |
| Linux hidraw | HID transport for authentication commands |

### Timeline

This project took approximately two weeks of iterative reverse
engineering, with several false starts:

1. **Week 1**: USB capture analysis, initial Ghidra decompilation, mapping
   the HID command set and RSA handshake. Multiple failed unlock attempts
   due to incorrect FF A4 parameters and the missing FF 89 commit command.

2. **Week 2**: Deep dive into `encryptPVCKey` with LLDB validation. pcap
   re-analysis revealing the correct FF A4 layout. Discovery of the FF 89
   commit command as the final missing piece. Successful unlock.


### Remaining Items

It would be nice if you could do the initial setup in Linux, and be compatible with
passphrase mode.

## License

This software is released under the GNU GPL 2.0 license.
