# IronKey Locker+ Authentication Protocol

This document describes the complete unlock sequence for the Kingston
IronKey Locker+ 50G2, as reverse-engineered from the macOS IronKey
application binary and verified on actual hardware.

## Device States

The IronKey has two USB personalities:

| State | PID | Interfaces | Description |
|-------|-----|------------|-------------|
| Locked | varies by model | Mass Storage (CD-ROM + 0B disk) | Read-only setup partition |
| HID mode | varies by model | Mass Storage + HID | Accepts authentication commands |

The PID varies by device capacity (e.g., 0x159D for 50G2). The tool
discovers PIDs at runtime via the USB product string.

## Step 1: PID Switch (activateHIDInterface)

When locked, the device only exposes mass storage. To reach the HID
interface, a magic sequence of USB string descriptor reads triggers a
firmware-mode PID switch.

**Prerequisites**: Unmount all volumes (CD-ROM LUN 1 and data LUN 0).

**Sequence**: Read USB string descriptors via standard GET_DESCRIPTOR
control transfers:

```
bmRequestType = 0x80  (device-to-host, standard)
bRequest      = 0x06  (GET_DESCRIPTOR)
wValue        = 0x03XX (STRING, XX = descriptor index)
wIndex        = 0x0409 (US English)
wLength       = 16
```

**Pattern** (6 reads, ~100ms apart):

```
Read string descriptor at iSerialNumber + 2
Read string descriptor at iSerialNumber + 2
Read string descriptor at iSerialNumber + 3
Read string descriptor at iSerialNumber + 3
Read string descriptor at iSerialNumber + 2
Read string descriptor at iSerialNumber + 2
```

After the last read, the device disconnects and re-enumerates with a new
PID that includes a HID interface (interface 1, HID boot-level).

## Step 2: HID Transport

All authentication commands use HID reports via the hidraw device:

| Operation | Method |
|-----------|--------|
| Send command | `write()` — Output report (64 bytes + report ID 0x00) |
| Send data | `ioctl(HIDIOCSFEATURE)` — Feature report (512 bytes) |
| Read data | `ioctl(HIDIOCGFEATURE)` — Feature report (512 bytes) |
| Status | `read()` — Interrupt endpoint (64 bytes) |

### Output Report Format (64 bytes)

```
Offset  Size  Field
------  ----  -----
0x00    1     Subcommand (0x81, 0x82, ..., 0xA4, etc.)
0x01    1     CDB[2] — secondary parameter
0x02    4     Data length (little-endian uint32)
0x06    4     Chunk count (1 if data, 0 if no data)
0x0A    4     Magic: 0x4D524F54 ("MROT")
0x0E    1     Direction: 0=write, 1=read
0x0F    1     Reserved (0)
0x10    8     CDB[3:10] — subcommand parameters
0x18    1     CDB[11] — final parameter
0x19    7     Padding (zeros)
```

### Interrupt Response Format (64 bytes)

```
Offset  Size  Field
------  ----  -----
0x00    2     Acknowledge: 0x0001 (command received)
0x02    2     Command echo (e.g., 0x0081 for subcommand 0x81)
0x04    2     Status: 0x0000 = success, nonzero = error
```

## Step 3: RSA-512 Key Exchange (FF 81-88)

A mutual RSA-512 challenge-response establishes a 16-byte shared secret.
Both the host and device generate ephemeral RSA-512 key pairs.

### FF 81 — Get Device Public Key (READ 128 bytes)

```
Output report:  subcommand=0x81, direction=read, data_length=128
Response:       N_dev (64 bytes, little-endian) || E_dev (64 bytes, little-endian)
```

The device returns its RSA modulus (N) and public exponent (E). Both are
512-bit values in little-endian byte order.

### FF 82 — Send Host Public Key (WRITE 128 bytes)

```
Output report:  subcommand=0x82, direction=write, data_length=128
Feature data:   N_host (64 bytes) || E_host (64 bytes)
```

Host sends its own RSA-512 public key.

### FF 83 — Send Host Challenge (WRITE 64 bytes)

```
Output report:  subcommand=0x83, direction=write, data_length=64
Feature data:   r1 (64 bytes) — random challenge, clamped < N_dev
```

The host generates a random 64-byte value `r1`, clamped so it is
numerically less than `N_dev`. `r1` is sent in the clear.

### FF 84 — Get Device Signature (READ 64 bytes)

```
Output report:  subcommand=0x84, direction=read, data_length=64
Response:       sig1 = Sign_device(r1)
```

The device signs `r1` with its private key, proving possession of the
corresponding private key. (The signature is not verified by the host in
practice — this step establishes the challenge is fresh.)

### FF 85 — Get Device Nonce (READ 64 bytes)

```
Output report:  subcommand=0x85, direction=read, data_length=64
Response:       nonce_dev (64 bytes) — device-generated random nonce
```

### FF 86 — Send Encrypted Nonce (WRITE 64 bytes)

```
Output report:  subcommand=0x86, direction=write, data_length=64
Feature data:   nonce_dev ^ D_host mod N_host (as 64 bytes LE)
```

The host encrypts the device's nonce with its own private key, proving it
received the nonce and holds the corresponding private key.

### FF 87 — Send Encrypted Challenge (WRITE 64 bytes)

```
Output report:  subcommand=0x87, direction=write, data_length=64
Feature data:   r2 ^ E_dev mod N_dev (as 64 bytes LE)
```

The host generates a fresh random `r2` (clamped < N_dev) and encrypts it
with the device's public key. The device will decrypt this with its
private key.

### FF 88 — Get Device Secret (READ 64 bytes)

```
Output report:  subcommand=0x88, direction=read, data_length=64
Response:       r2_decoded ^ D_host mod N_host
```

The device decrypts `r2` from FF 87, then encrypts it with the host's
public key. The host decrypts with its private key to recover `r2_dev`.

### Shared Secret Derivation

```
r2_dev = pow(response_from_FF88, D_host, N_host)
shared_secret = r2[:16] XOR r2_dev[:16]
```

The first 16 bytes of the host's `r2` and the device's decrypted `r2_dev`
are XORed to produce a 16-byte AES key used for all subsequent operations.

## Step 4: PVC Key Exchange (FF 8B, FF 8F)

### FF 8B — Start Secure Access

```
Output report:  subcommand=0x8B, CDB[3]=0x00, CDB[4]=0x03
```

Opens a secure session with `secureType=3` (PVC domain).

### FF 8F — PVCFuncOpen (WRITE 64 bytes)

```
Output report:  subcommand=0x8F, CDB[3]=0x02
Feature data:   encryptPVCKey(PVC0_KEY, shared_secret) — 64 bytes
```

Sends a device-specific PVC key encrypted under the session key. The PVC
key is hardcoded per device and derived from the device's provisioning
data.

### encryptPVCKey Algorithm

```
hash1 = SHA-256(PVC0_KEY)
local[0:32]  = hash1
local[32:48] = shared_secret
hash2 = SHA-256(local[0:48])
local[0:32]  = hash2
local[32:64] = random(32 bytes)
result = AES-128-ECB(shared_secret, local[0:16])
       + AES-128-ECB(shared_secret, local[16:32])
       + AES-128-ECB(shared_secret, local[32:48])
       + AES-128-ECB(shared_secret, local[48:64])
```

Four AES-128-ECB blocks encrypted with the shared secret, totaling 64
bytes.

## Step 5: Password Authentication (FF A4, FF 89)

### FF A4 — NTU_Open (WRITE 16 bytes)

```
Output report:  subcommand=0xA4, CDB[3]=0x00, CDB[4]=0x00, CDB[5]=0x00, CDB[6]=0x06
Feature data:   AES-128-ECB(shared_secret, password_padded) — 16 bytes
```

The user password is zero-padded to 16 bytes (max 16 bytes) and
AES-128-ECB encrypted with the shared secret.

CDB parameters:
- CDB[3] = secureType (0x00)
- CDB[4] = userIDIndex (0x00)
- CDB[5] = timeInterval (0x00)
- CDB[6] = autoLogout (0x06)

### FF 89 — Commit

```
Output report:  subcommand=0x89, no data
```

Finalizes the authentication. If the encrypted password was correct, the
device exposes the encrypted data partition. This command was the last
piece discovered and was critical to making unlock work.

## Step 6: Verification

After FF 89, the device re-enumerates the mass storage LUN 0 to expose
the encrypted data partition (e.g., /dev/sda). The tool polls `lsblk` for
up to 10 seconds to detect the new partition.

## Complete Sequence Summary

```
FF 81  READ  128B   Get device RSA public key (N, E)
FF 82  WRITE 128B   Send host RSA public key (N, E)
FF 83  WRITE 64B    Send host challenge r1
FF 84  READ  64B    Get device signature on r1
FF 85  READ  64B    Get device nonce
FF 86  WRITE 64B    Send encrypted nonce (proves host identity)
FF 87  WRITE 64B    Send encrypted r2 (challenge for device)
FF 88  READ  64B    Get device's decryption of r2

                      Derive shared_secret = r2[:16] XOR r2_dev[:16]

FF 8B  NONE          Start Secure Access (secureType=3)
FF 8F  WRITE 64B    PVCFuncOpen (encrypted PVC key)
FF A4  WRITE 16B    NTU_Open (encrypted user password)
FF 89  NONE          Commit (finalize authentication)

                      Device exposes data partition
```

## Subcommand Reference

| Subcmd | Name | Dir | Size | Description |
|--------|------|-----|------|-------------|
| 0x21 | GetConfig | READ | 0x200 | Device configuration |
| 0x41 | CD_Unlock | NONE | — | CD-ROM unlock (alternative path) |
| 0x81 | GetDevPubKey | READ | 128 | Device RSA public key |
| 0x82 | SetHostPubKey | WRITE | 128 | Host RSA public key |
| 0x83 | HostChallenge | WRITE | 64 | Host random challenge r1 |
| 0x84 | DevSignature | READ | 64 | Device signature of r1 |
| 0x85 | GetDevNonce | READ | 64 | Device random nonce |
| 0x86 | EncryptedNonce | WRITE | 64 | Host-encrypted device nonce |
| 0x87 | EncryptedChallenge | WRITE | 64 | Encrypted r2 for device |
| 0x88 | DevSecret | READ | 64 | Device-decrypted r2 |
| 0x89 | Commit | NONE | — | Finalize session |
| 0x8B | StartSecureAccess | NONE | — | Open secure domain |
| 0x8F | PVCFuncOpen | WRITE | 64 | PVC key exchange |
| 0xA0 | GetAreaParams | READ | 0x200 | Area parameters / status |
| 0xA2 | ConfigPrivateArea | WRITE | — | Configure data area |
| 0xA4 | NTU_Open | WRITE | 16 | Encrypted password auth |
