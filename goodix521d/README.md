# libfprint + goodixtls52xd: Goodix 27c6:521d on Linux, dual-boot safe

A fork of [libfprint](https://gitlab.freedesktop.org/libfprint/libfprint)
1.94.100 adding a driver for the Goodix `27c6:521d` fingerprint sensor (ASUS
ROG Zephyrus G14 GA401 and others) that **keeps Windows Hello working**.

> **Status: experimental.** Tested on one device. Keep password login as a fallback.

## How it differs from the existing 521d drivers

Earlier Linux drivers for this sensor (goodix-fp-dump, `libfprint-goodix-521d`
on the AUR) first **erase the sensor firmware, write a known pairing key and
flash an older firmware**. Windows then puts its own firmware back, which breaks
Linux again, and a failed flash can brick the sensor.

This driver **never writes to the sensor**. The sensor talks to the host over
TLS with a pre-shared key that Windows generated and stored, encrypted, on the
sensor itself. `goodix52xd-setup pair` decrypts it **offline, from your own
Windows partition**, checks it against the hash the sensor reports, and Linux
then uses the same key as Windows. Details: [PROTOCOL.md](PROTOCOL.md).

Other changes from earlier drivers:
- calibration values are read from the sensor's own factory data (OTP) instead
  of being hard-coded from one particular unit,
- capture uses the sensor's high-contrast "finger" mode,
- the sensor's fixed noise pattern is removed,
- matching uses a SIGFM-derived geometric matcher plus rotated correlation,
  through a small libfprint hook (NBIS doesn't work on 64x80 images),
- enrollment takes 15 touches and rejects near-duplicates.

## Requirements

- `27c6:521d` with firmware `GFUSB_GM168SEC_APP_100xx` (check: `sudo goodix52xd-setup status`)
- A Windows install **on the same machine** that has used the sensor (Windows
  Hello set up, or at least the Goodix driver installed), on an NTFS partition
  that isn't BitLocker-locked. If it is, unlock it first and pass `--windows <mountpoint>`.
- `python-pyusb`, `impacket` (for `pair`), `opencv`

## Install (Arch Linux)

```sh
git clone https://github.com/Dak0verflow/libfprint-goodix521d
cd libfprint-goodix521d/goodix521d
makepkg -si                       # answer "y" to remove libfprint (this replaces it)
sudo goodix52xd-setup status      # read-only check
sudo goodix52xd-setup pair        # recover the pairing key from Windows
sudo goodix52xd-setup calibrate   # 20 touches, different fingers/positions
fprintd-enroll                    # 15 touches, vary placement
fprintd-verify
```

On KDE Plasma you can enroll from the GUI instead: **System Settings → Users →
Configure Fingerprint Authentication**. KDE's lock screen uses the fingerprint out
of the box; for the boot login screen see `--login` below.

To undo: `sudo pacman -S libfprint`, then optionally
`sudo rm -r /var/lib/fprint/goodixtls52xd`.

If Windows ever re-pairs the sensor (e.g. after reinstalling Windows or the
Goodix driver), the driver reports "Sensor pairing key changed". Re-run
`goodix52xd-setup pair`.

### Using it for sudo and admin popups

`goodix52xd-pam` turns fingerprint on for a PAM service, with password fallback
(3 tries or 15 s, or Ctrl+C in a terminal):

```sh
sudo goodix52xd-pam            # terminal sudo
sudo goodix52xd-pam polkit-1   # KDE/GNOME admin popups (e.g. Partition Manager)
sudo goodix52xd-pam polkit-1 --undo
sudo goodix52xd-pam sddm --login   # boot login screen, see below
```

**Boot login screen (SDDM).** KDE's lock screen supports the fingerprint out
of the box, but the SDDM login screen after a reboot does not. SDDM has no
fingerprint prompt and only runs PAM after you press Enter, so `--login` mode
works differently: **type your password as usual, or press Enter on an empty
password field and then touch the sensor.** A fingerprint login cannot unlock a
password-encrypted KDE Wallet, so KDE asks for the wallet password once after
such a login.

For services whose PAM file only exists in `/usr/lib/pam.d` (like `polkit-1`),
it creates an override in `/etc/pam.d`, so package updates don't revert it.
Keep a root shell open (`sudo -s`) while testing PAM changes.

## Accuracy (one device, one user; small numbers)

| test | result |
|---|---|
| offline: 3 fingers x 20 touches, 10-sample templates | 0 / 360 impostor accepts; about 27 % of single genuine attempts rejected (default thresholds) |
| live: enrolled right index | 5 / 5 accepted |
| live: other fingers | 5 / 5 rejected |
| daily use so far | KDE login, lock screen, sudo, polkit popups |

These numbers are far too small to state a false-accept rate. More data from
more people and devices is needed before relying on this as the only factor.
Tuning knobs: `GOODIX52XD_THRESHOLD_SIGFM` (default 30) and
`GOODIX52XD_THRESHOLD_CORR` (default 0.80); `GOODIX52XD_DUMP_DIR=<dir>` saves
every capture.

## Security notes

- The pairing key is stored root-only (`0600`) in `/var/lib/fprint/goodixtls52xd/`.
  Anyone with root could read it, as they could on Windows.
- `goodix52xd-setup pair` reads the Windows `SYSTEM` and `SECURITY` registry
  hives into a temporary root-only directory, uses them only to decrypt the
  sensor's record, and deletes them. Nothing leaves the machine.

## Upstreaming

libfprint accepts new drivers given 3 stand-alone devices and a protocol
specification. [PROTOCOL.md](PROTOCOL.md) is the specification so far. What's
missing is listed at its end, and reports or PRs from other `521d`/`538d` owners
are the most useful help.

## Credits and license

LGPL-2.1-or-later, like libfprint. The protocol and TLS layer comes from
[infinytum/libfprint](https://github.com/infinytum/libfprint) and the
goodix-fp-linux-dev project (Alexander Meiler, Matthieu CHARETTE, Michael
Teuscher and contributors). The matcher is derived from SIGFM (Matthieu
CHARETTE, Natasha England-Elbro, Timur Mangliev). The Windows-key approach was
inspired by [goodix-27c6-5125](https://github.com/sorguido/goodix-27c6-5125).
