# Goodix 27c6:521d protocol notes

Reverse-engineering notes for the Goodix USB fingerprint sensor `27c6:521d`
(firmware family `GFUSB_GM168SEC_APP_100xx`, found in the ASUS ROG Zephyrus G14
GA401 and others), as used by the `goodixtls52xd` driver in this repository.

The aim is to cover the "specifications of the protocol" that libfprint asks for
before accepting a driver (see `HACKING.md`). Every statement is tagged:

- **[verified]**: observed on real hardware (firmware `GFUSB_GM168SEC_APP_10034`)
  and relied on by the driver.
- **[inferred]**: consistent with observations, not independently confirmed.
- **[unknown]**: open question. Contributions welcome (see the end).

Reference devices so far: **1** (ASUS GA401QM, Windows 11 dual boot).
libfprint asks for 3 stand-alone devices, so reports from more units are the
most useful contribution.

---

## 1. Transport

| | |
|---|---|
| USB ID | `27c6:521d` |
| Interface | 0 |
| Bulk OUT | `0x01`. Writes are padded with zeros to a multiple of 64 bytes **[verified]** |
| Bulk IN | `0x83`. A whole message arrives in one transfer (read up to 64 KiB) **[verified]** |

### 1.1 Pack (outer frame) [verified]

```
+-------+-----------+----------------------+-------------------+
| flags | length    | header checksum      | payload           |
| u8    | u16 LE    | (sum of bytes 0..2)  | `length` bytes    |
|       |           |  & 0xff               |                   |
+-------+-----------+----------------------+-------------------+
```

| flags | meaning |
|---|---|
| `0xa0` | protocol message (section 1.2) |
| `0xb0` | TLS handshake records, raw |
| `0xb2` | TLS application data (image). Payload starts with a 9-byte prefix, then a TLS record **[verified]**. The prefix's meaning is **[unknown]** |

### 1.2 Protocol message [verified]

```
+-----+-----------------+-----------+----------+
| cmd | length = n + 1  | body      | checksum |
| u8  | u16 LE          | n bytes   | u8       |
+-----+-----------------+-----------+----------+
checksum = (0xaa - sum(cmd, length, body)) & 0xff, or the constant 0x88 (used by NOP)
```

Every command is acknowledged with an ACK message, `cmd = 0xb0`, body
`[acked_cmd, flags]`. Bit 0 of `flags` is always set. Bit 1 appears to mean
"MCU has no config" **[inferred]**. A command with a reply then sends a second
message with the same `cmd`.

**Unsolicited and stray messages [verified]:** after an interrupted session, or
around a reset, the sensor can send messages that answer neither the current
command nor its ACK. Hosts must skip them rather than fail. A USB port reset
before opening clears half-finished sessions.

## 2. Commands

Payload bytes are hex. "Reply" means a message with the same `cmd` follows the ACK.

| cmd | name | payload | reply | notes |
|---|---|---|---|---|
| `00` | NOP | `00000000`, checksum `0x88` | none (ACK optional) | sync after connect **[verified]** |
| `a8` | firmware version | `0000` | NUL-terminated ASCII, e.g. `GFUSB_GM168SEC_APP_10034` | **[verified]** |
| `e4` | preset PSK read | `len u32, offset u32, slot u32, 0 u32` (16 bytes) | `status u8` (0 = ok), `slot u32`, `len u32`, data | the 12-byte form without the trailing 0 and the form without len/offset both return status 1 **[verified]** |
| `e0` | preset PSK write | | | **never used**; see section 3 |
| `a2` | reset | `[0x05, sleep_ms]` (reset sensor) | `[1, u16]` on success | **[verified]** |
| `a6` | read OTP | `0000` | 64 bytes | the 1-byte payload in earlier code is wrong **[verified]** |
| `d0` | request TLS | `0000` | flags `0xb0` pack: TLS ClientHello | the sensor is the TLS *client* **[verified]** |
| `90` | upload MCU config | 256-byte config | `[1]` = accepted | config block in `goodix52xd.h` **[verified]** |
| `c4` | set driver state | `0100` | none | **[verified]** (purpose **[unknown]**) |
| `36` | switch to FDT mode | 27 bytes (section 6) | when last byte = 1: 8 x u16 LE region values at body[4:20] | **[verified]** |
| `80` | write sensor register | `00, addr u16 LE, value (2 bytes)` | none | **[verified]** |
| `20` | get image | 10 bytes (section 5) | flags `0xb2` pack with encrypted image | **[verified]** |
| `70` | MCU idle | `[sleep, 0]` | none | **[verified]** |
| `a4`, `f0`-`f6` | erase app, firmware read/write/check, IAP version | | | **never used**. These flash the MCU (section 7) |

## 3. Pairing and TLS

The sensor opens a **TLS 1.2 PSK** session as client. The host is the server.
Any PSK cipher OpenSSL offers works; OpenSSL 3+ needs `@SECLEVEL=0` **[verified]**.
After the handshake, image data arrives as TLS application data (section 1.1).
Each image read is one TLS record of 7684 plaintext bytes.

### 3.1 Key slots [verified]

| slot | size | readable | content |
|---|---|---|---|
| `bb010002` | 332 | yes | 324-byte **Windows DPAPI blob**, then an 8-byte trailer `03 00 01 bb 60 00 00 00` (= slot `bb010003`, length `0x60`) |
| `bb010003` | 96 | no | host PSK as stored by the Windows driver (MCU-wrapped). Format **[unknown]**. It is not the 102-byte AES-GCM envelope used by the `27c6:5125`/ST411 firmware |
| `bb020001` | 32 | yes | **SHA-256(PSK)**. Verified both with the all-zero PSK used by goodix-fp-dump and with a Windows-provisioned PSK |
| `bb020002`, `bb020003` | | no | |

### 3.2 The DPAPI record [verified]

`bb010002[0:324]` is a standard DPAPI blob:

- provider GUID `df9d8cd0-1501-11d1-8c7a-00c04fc297eb`, flags `0`
- description `"This is the description string."` (UTF-16)
- cipher `0x6610` (AES-256), hash `0x800e` (SHA-512)
- master key GUID at offset 24. It lives in
  `C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\` and is decrypted with
  the `DPAPI_SYSTEM` LSA secret's *user* key (from the `SYSTEM` and `SECURITY` hives)
- plaintext: the 32-byte PSK

So Linux can use the PSK Windows provisioned, recovered offline from the same
machine's Windows install (`goodix52xd-setup pair`), without writing anything
to the sensor. Windows Hello is unaffected.

**Why not provision a Linux key instead?** Earlier tools (goodix-fp-dump) erase
the application firmware, write a known PSK in IAP mode and flash an *older*
firmware (`APP_10019`). Windows Update then reflashes its own firmware, which
breaks Linux again, and a failed flash can leave the MCU stuck in IAP mode.
Writing a PSK in application mode, as the `27c6:5125` project does, would need
the `bb010003` envelope format, which is **[unknown]** for this firmware.

## 4. OTP calibration

64 bytes, readable with `a6`.

- bytes 0..5: ASCII identifier, e.g. `NLM17.` in a published dump **[inferred]**
- a CRC-8 (poly 0x07, inverted) over `otp[0:11] + otp[36:40]` equals `otp[60]` **[verified]**.
  The other two CRC groups of the ST411 layout do not match, so the rest of the layout differs.
- **DAC calibration [verified]:**

  | mode | 4 DAC values |
  |---|---|
  | clear | `otp[42], otp[41], otp[42], otp[43]` |
  | finger | `otp[45], otp[44], otp[45], otp[46]` |

  Checked against both OTP dumps published in goodix-fp-dump's `driver_52xd.py`:
  the first reproduces that tool's hard-coded values (`27 21 27 23` / `a7 a1 a7 a3`)
  exactly. So the hard-coded values in earlier drivers were one specific sensor's
  calibration, which explains the "finger capture saturates" reports from other units.

## 5. Image capture [verified]

1. Write register `0x022c` with the mode value.
2. `20` get image with `[mode_byte, 0x03, dac0, hi, dac1, hi, dac2, hi, dac3, hi]`.
3. Decrypt the TLS record: 7684 bytes, of which 7680 are pixels and 4 are trailing
   bytes (CRC?) **[unknown]**.
4. Write `0x022c = 0a 02` to return to idle.

| mode | reg `0x022c` | mode byte | DAC | `hi` | result |
|---|---|---|---|---|---|
| clear | `0a 03` | `0x81` | clear DACs | `0x01` | flat background (~2060). A finger lowers it slightly; needs background subtraction. Ridge SNR ≈ 8 |
| finger | `05 03` | `0x45` | finger DACs | `0x00` | **saturated (~3950) with no finger**, ~1900 with a finger, ridges visible in the raw frame. Ridge SNR ≈ 43 |

Pixel format: 64 x 80 (width x height), 12-bit, 4 pixels packed in 6 bytes:

```
p0 = ((b0 & 0xf) << 8) | b1        p1 = (b3 << 4) | (b0 >> 4)
p2 = ((b5 & 0xf) << 8) | b2        p3 = (b4 << 4) | (b5 >> 4)
```

**Finger presence:** in finger mode, the share of pixels below 3400 (ignoring a
4-pixel border) is 0 % with no finger and 100 % with a full touch. The driver
polls this. The FDT interrupt mechanism (section 6) would avoid polling.

### 5.1 Image artifacts [verified]

- A **static fixed pattern** specific to each sensor, identical under every finger.
  If it is not removed, different fingers "match" each other through it. Estimate
  it as the mean of many finger-mode frames at different positions.
- Row and column stripes: subtract per-row and per-column medians.
- Bright border: crop 4 pixels on each side (giving 56 x 72).
- Ridge period is about 4-5 pixels. A band-pass of σ 0.8 / 3.0 isolates ridges.

## 6. FDT (finger detect)

`36` payload: `0d 01` + 4 x (clear DAC, `0x01`) + 16 threshold bytes + `reply`
flag. With zero thresholds and `reply = 1`, the reply holds 8 region values
(u16 LE, body[4:20]) **[verified]**.

- With **per-sensor** DACs, a finger *raises* all 8 regions by about 45. With the
  hard-coded DACs of earlier tools, it lowered them. **[verified]**
- The interrupt-style "FDT down" command (`32`) with thresholds fired immediately
  or never in earlier experiments. Correct thresholds are **[unknown]**.
  A capture from the Windows driver would settle this.

## 7. Firmware

- Observed: `GFUSB_GM168SEC_APP_10034` (Windows-updated). Earlier tools target `APP_10019`.
- IAP (bootloader) identifies as `MILAN_GM168SEC_IAP_10007` **[inferred, from goodix-fp-dump]**.
- This driver **never** erases or flashes firmware and never writes key slots.

## 8. Open questions (contributions welcome)

1. **More devices:** run `goodix52xd-setup status` on other `27c6:521d` (and
   `27c6:538d`) units and report the firmware, the OTP DAC bytes, and whether
   pairing and calibration work.
2. The `bb010003` envelope format. Knowing it would allow Linux-native pairing
   without a Windows install.
3. FDT-down thresholds for interrupt-driven finger detection (power saving).
4. The 9-byte prefix on `0xb2` packs and the 4 trailing bytes of each image.
5. The remaining OTP fields and the remaining MCU config registers.
6. Sleep and power-down modes (`60`, `92`, `94`) for suspend and resume.
7. A umockdev recording for libfprint's test suite. Because of TLS, this needs a
   test mode with a fixed PSK, or a recording plus the matching (throwaway) key.

## Credits

Builds on work by the goodix-fp-linux-dev project (goodix-fp-dump, MIT;
goodixtls libfprint branch, LGPL) by Alexander Meiler, Matthieu CHARETTE,
Natasha England-Elbro, Timur Mangliev, Michael Teuscher and contributors, and
on findings from the `27c6:5125` project
(https://github.com/sorguido/goodix-27c6-5125): reuse of the Windows key and
fixed-pattern handling.
