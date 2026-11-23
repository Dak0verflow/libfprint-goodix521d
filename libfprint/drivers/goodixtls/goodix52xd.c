// Goodix TLS driver for libfprint — 27c6:521d (GM168SEC firmware)
//
// Copyright (C) 2021 Alexander Meiler <alex.meiler@protonmail.com>
// Copyright (C) 2021 Matthieu CHARETTE <matthieu.charette@gmail.com>
// Copyright (C) 2021 Michael Teuscher <michael.teuscher@pm.me>
//
// Reworked for dual-boot use: never flashes firmware or writes a pairing key.
// The TLS PSK is the one Windows provisioned (recovered offline from the
// sensor's DPAPI-protected BB010002 record) and is checked against the
// sensor's BB020001 validator (sha256(psk)) on every activation.
// Capture uses per-sensor DAC calibration from OTP and the "finger" image
// mode; matching is done by goodix52xd_match.cpp via the image-device
// custom-matcher hooks.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.

#define FP_COMPONENT "goodixtls52xd"

#include <errno.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>

#include "drivers_api.h"
#include "fpi-print.h"
#include "goodix.h"
#include "goodix_proto.h"
#include "goodixtls.h"
#include "goodix52xd.h"
#include "goodix52xd_match.h"

#define G52_STATE_DIR "/var/lib/fprint/goodixtls52xd"
#define G52_PSK_FILE G52_STATE_DIR "/psk.bin"
#define G52_FPN_FILE G52_STATE_DIR "/fpn.bin"
#define G52_FW_PREFIX "GFUSB_GM168SEC_APP_100"
#define G52_VALIDATOR_FLAGS 0xbb020001
#define G52_FRAME_BYTES (G52_RAW_W * G52_RAW_H / 4 * 6) /* 7680 */
#define G52_ENROLL_STAGES 15
#define G52_POLL_MS 120
#define G52_SETTLE_MS 300
#define G52_TOUCH_COVERAGE 0.60
#define G52_LIFT_COVERAGE 0.03
#define G52_FPN_ALPHA (1.0f / 64.0f)
#define G52_DEFAULT_TS 30
#define G52_DEFAULT_TC 0.80
#define G52_DUPLICATE_CORR 0.93

#define REG_IMG_MODE 0x022c
#define REG_CLEAR 0x030a  /* bytes 0a 03 */
#define REG_IDLE 0x020a   /* bytes 0a 02 */
#define REG_FINGER 0x0305 /* bytes 05 03 */

struct _FpiDeviceGoodixTls52XD {
  FpiDeviceGoodixTls parent;

  guint8 otp[64];
  guint8 dac_clear[4];
  guint8 dac_finger[4];
  guint8 psk[32];

  float *fpn; /* 64x80, NULL until loaded/learned */
  gboolean fpn_dirty;

  /* scan loop */
  gboolean active;        /* activated and TLS up */
  gboolean deactivating;  /* deactivate requested */
  gboolean busy;          /* a capture is in flight */
  gboolean want_finger;   /* TRUE: waiting for touch, FALSE: waiting for lift */
  gint touch_hits;
  gboolean final_capture; /* next capture is the one we report */
  GSource *poll_source;

  gint thr_sigfm;
  gdouble thr_corr;
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodixTls52XD, fpi_device_goodixtls52xd, FPI,
                      DEVICE_GOODIXTLS52XD, FpiDeviceGoodixTls);
G_DEFINE_TYPE (FpiDeviceGoodixTls52XD, fpi_device_goodixtls52xd,
               FPI_TYPE_DEVICE_GOODIXTLS);

static void scan_schedule (FpiDeviceGoodixTls52XD *self, guint ms);
static void maybe_finish_deactivate (FpiDeviceGoodixTls52XD *self);

/* ------------------------------------------------------------------------ */
/* helpers                                                                  */

static const gchar *
state_path (const gchar *env, const gchar *dflt)
{
  const gchar *v = g_getenv (env);

  return v && *v ? v : dflt;
}

static gboolean
load_psk (FpiDeviceGoodixTls52XD *self, GError **error)
{
  const gchar *path = state_path ("GOODIX52XD_PSK_FILE", G52_PSK_FILE);
  g_autofree gchar *buf = NULL;
  gsize len = 0;

  if (!g_file_get_contents (path, &buf, &len, NULL) || len != sizeof (self->psk))
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL,
                   "goodixtls52xd: pairing key %s missing or invalid "
                   "(run goodix52xd-setup)", path);
      return FALSE;
    }
  memcpy (self->psk, buf, sizeof (self->psk));
  memset (buf, 0, len);
  return TRUE;
}

static void
load_fpn (FpiDeviceGoodixTls52XD *self)
{
  const gchar *path = state_path ("GOODIX52XD_FPN_FILE", G52_FPN_FILE);
  g_autofree gchar *buf = NULL;
  gsize len = 0;

  if (self->fpn)
    return;
  if (g_file_get_contents (path, &buf, &len, NULL) &&
      len == G52_RAW_W * G52_RAW_H * sizeof (float))
    {
      self->fpn = g_memdup2 (buf, len);
      fp_dbg ("loaded fixed-pattern estimate from %s", path);
    }
  else
    {
      fp_warn ("no fixed-pattern estimate at %s; learning from scratch", path);
    }
}

static void
save_fpn (FpiDeviceGoodixTls52XD *self)
{
  const gchar *path = state_path ("GOODIX52XD_FPN_FILE", G52_FPN_FILE);
  g_autoptr(GError) error = NULL;

  if (!self->fpn || !self->fpn_dirty)
    return;
  if (!g_file_set_contents_full (path, (const gchar *) self->fpn,
                                 G52_RAW_W * G52_RAW_H * sizeof (float),
                                 G_FILE_SET_CONTENTS_CONSISTENT, 0600, &error))
    fp_warn ("failed to save fixed-pattern estimate: %s", error->message);
  else
    self->fpn_dirty = FALSE;
}

static void
update_fpn (FpiDeviceGoodixTls52XD *self, const guint16 *raw)
{
  if (!self->fpn)
    {
      self->fpn = g_new (float, G52_RAW_W * G52_RAW_H);
      for (int i = 0; i < G52_RAW_W * G52_RAW_H; i++)
        self->fpn[i] = raw[i];
    }
  else
    {
      for (int i = 0; i < G52_RAW_W * G52_RAW_H; i++)
        self->fpn[i] += G52_FPN_ALPHA * ((float) raw[i] - self->fpn[i]);
    }
  self->fpn_dirty = TRUE;
}

static void
decode_frame (const guint8 *data, guint16 *out)
{
  guint16 *p = out;

  for (int i = 0; i < G52_FRAME_BYTES; i += 6)
    {
      const guint8 *c = data + i;
      *p++ = ((c[0] & 0xf) << 8) + c[1];
      *p++ = (c[3] << 4) + (c[0] >> 4);
      *p++ = ((c[5] & 0xf) << 8) + c[2];
      *p++ = (c[4] << 4) + (c[5] >> 4);
    }
}

/* image params: mode byte, 0x03, then 4 little-endian DAC words */
static void
image_params (FpiDeviceGoodixTls52XD *self, gboolean finger, guint8 out[10])
{
  const guint8 *dac = finger ? self->dac_finger : self->dac_clear;

  out[0] = finger ? 0x45 : 0x81;
  out[1] = 0x03;
  for (int i = 0; i < 4; i++)
    {
      out[2 + 2 * i] = dac[i];
      out[3 + 2 * i] = finger ? 0x00 : 0x01;
    }
}

static void
fdt_report_mode (FpiDeviceGoodixTls52XD *self, gboolean reply, guint8 out[27])
{
  memset (out, 0, 27);
  out[0] = 0x0d;
  out[1] = 0x01;
  for (int i = 0; i < 4; i++)
    {
      out[2 + 2 * i] = self->dac_clear[i];
      out[3 + 2 * i] = 0x01;
    }
  out[26] = reply ? 0x01 : 0x00;
}

static void
send_simple (FpDevice *dev, guint8 cmd, guint8 *payload, guint16 len,
             GoodixNoneCallback cb, gpointer user_data)
{
  GoodixCallbackInfo *cb_info = g_new0 (GoodixCallbackInfo, 1);

  cb_info->callback = G_CALLBACK (cb);
  cb_info->user_data = user_data;
  goodix_send_protocol (dev, cmd, payload, len, NULL, TRUE, GOODIX_TIMEOUT,
                        FALSE, goodix_receive_none, cb_info);
}

/* ------------------------------------------------------------------------ */
/* activation                                                               */

enum activate_states {
  ACTIVATE_NOP,
  ACTIVATE_FW_VERSION,
  ACTIVATE_CHECK_PAIRING,
  ACTIVATE_RESET,
  ACTIVATE_OTP,
  ACTIVATE_TLS,
  ACTIVATE_CONFIG,
  ACTIVATE_DRV_STATE,
  ACTIVATE_FDT_0,
  ACTIVATE_FDT_1,
  ACTIVATE_NUM_STATES,
};

static void
on_none (FpDevice *dev, gpointer ssm, GError *error)
{
  if (error)
    fpi_ssm_mark_failed (ssm, error);
  else
    fpi_ssm_next_state (ssm);
}

static void
on_data_next (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm, GError *error)
{
  on_none (dev, ssm, error);
}

static void
on_fw_version (FpDevice *dev, gchar *fw, gpointer ssm, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  fp_info ("sensor firmware: %s", fw);
  if (!g_str_has_prefix (fw, G52_FW_PREFIX))
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                          "Unsupported firmware: %s", fw));
      return;
    }
  fpi_ssm_next_state (ssm);
}

static void
on_validator (FpDevice *dev, gboolean success, guint32 flags, guint8 *val,
              guint16 len, gpointer ssm, GError *error)
{
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (dev);
  g_autoptr(GChecksum) sum = g_checksum_new (G_CHECKSUM_SHA256);
  guint8 digest[32];
  gsize dlen = sizeof (digest);

  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (!success || len != 32)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "Could not read pairing validator"));
      return;
    }
  g_checksum_update (sum, self->psk, sizeof (self->psk));
  g_checksum_get_digest (sum, digest, &dlen);
  if (memcmp (digest, val, 32) != 0)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                          "Sensor pairing key changed (Windows "
                                                          "re-paired the sensor?). Re-run "
                                                          "goodix52xd-setup."));
      return;
    }
  fp_dbg ("pairing key matches sensor validator");
  fpi_ssm_next_state (ssm);
}

static void
on_reset (FpDevice *dev, gboolean success, guint16 number, gpointer ssm, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (!success)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                          "Sensor reset failed"));
      return;
    }
  fp_dbg ("sensor reset ok (%u)", number);
  fpi_ssm_next_state (ssm);
}

static void
on_otp (FpDevice *dev, guint8 *data, guint16 len, gpointer ssm, GError *error)
{
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (dev);

  if (error)
    {
      fpi_ssm_mark_failed (ssm, error);
      return;
    }
  if (len < 64)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                          "Invalid OTP (len %u)", len));
      return;
    }
  memcpy (self->otp, data, 64);
  /* Per-sensor DAC calibration (verified against goodix-fp-dump captures) */
  self->dac_clear[0] = self->otp[42];
  self->dac_clear[1] = self->otp[41];
  self->dac_clear[2] = self->otp[42];
  self->dac_clear[3] = self->otp[43];
  self->dac_finger[0] = self->otp[45];
  self->dac_finger[1] = self->otp[44];
  self->dac_finger[2] = self->otp[45];
  self->dac_finger[3] = self->otp[46];
  fp_dbg ("DAC clear %02x %02x %02x %02x finger %02x %02x %02x %02x",
          self->dac_clear[0], self->dac_clear[1], self->dac_clear[2], self->dac_clear[3],
          self->dac_finger[0], self->dac_finger[1], self->dac_finger[2], self->dac_finger[3]);
  fpi_ssm_next_state (ssm);
}

static void
on_tls_ready (FpDevice *dev, gpointer ssm, GError *error)
{
  on_none (dev, ssm, error);
}

static void
on_config (FpDevice *dev, gboolean success, gpointer ssm, GError *error)
{
  if (error)
    fpi_ssm_mark_failed (ssm, error);
  else if (!success)
    fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                        "Sensor rejected config"));
  else
    fpi_ssm_next_state (ssm);
}

static void
activate_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case ACTIVATE_NOP:
      goodix_start_read_loop (dev);
      goodix_send_nop (dev, on_none, ssm);
      break;

    case ACTIVATE_FW_VERSION:
      goodix_send_firmware_version (dev, on_fw_version, ssm);
      break;

    case ACTIVATE_CHECK_PAIRING:
      goodix_send_preset_psk_read (dev, G52_VALIDATOR_FLAGS, 32, on_validator, ssm);
      break;

    case ACTIVATE_RESET:
      goodix_send_reset (dev, TRUE, 20, on_reset, ssm);
      break;

    case ACTIVATE_OTP:
      goodix_send_read_otp (dev, on_otp, ssm);
      break;

    case ACTIVATE_TLS:
      goodix_tls_set_psk (self->psk, sizeof (self->psk));
      goodix_tls (dev, on_tls_ready, ssm);
      break;

    case ACTIVATE_CONFIG:
      goodix_send_upload_config_mcu (dev, goodix_52xd_config, sizeof (goodix_52xd_config),
                                     NULL, on_config, ssm);
      break;

    case ACTIVATE_DRV_STATE:
      {
        static guint8 drv[] = { 0x01, 0x00 };
        send_simple (dev, GOODIX_CMD_SET_DRV_STATE, drv, sizeof (drv), on_none, ssm);
        break;
      }

    case ACTIVATE_FDT_0:
    case ACTIVATE_FDT_1:
      {
        gboolean reply = fpi_ssm_get_cur_state (ssm) == ACTIVATE_FDT_1;
        guint8 *mode = g_malloc (27);

        fdt_report_mode (self, reply, mode);
        /* without a reply the callback fires on the ACK */
        goodix_send_mcu_switch_to_fdt_mode (dev, mode, 27, reply, g_free, on_data_next, ssm);
        break;
      }
    }
}

static void
activate_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (dev);

  if (error)
    fp_warn ("activation failed: %s", error->message);
  else
    self->active = TRUE;
  fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
}

/* ------------------------------------------------------------------------ */
/* scanning: poll finger-mode frames for coverage                           */

typedef struct {
  FpiDeviceGoodixTls52XD *self;
  guint8 params[10];
} CaptureCtx;

static void capture_step_restore (FpDevice *dev, gpointer user_data, GError *error);

static void
dump_frame (const guint16 *raw, const guint8 *img)
{
  static guint counter = 0;
  const gchar *dir = g_getenv ("GOODIX52XD_DUMP_DIR");
  g_autofree gchar *base = NULL;
  g_autofree gchar *p1 = NULL;
  g_autofree gchar *p2 = NULL;

  if (!dir || !*dir)
    return;
  base = g_strdup_printf ("%s/%" G_GINT64_FORMAT "-%03u", dir, g_get_real_time () / 1000, counter++);
  p1 = g_strconcat (base, ".raw", NULL);
  p2 = g_strconcat (base, ".img", NULL);
  g_file_set_contents (p1, (const gchar *) raw, G52_RAW_W * G52_RAW_H * 2, NULL);
  g_file_set_contents (p2, (const gchar *) img, G52_IMG_W * G52_IMG_H, NULL);
}

static void
report_image (FpiDeviceGoodixTls52XD *self, const guint16 *raw)
{
  FpImage *img = fp_image_new (G52_IMG_W, G52_IMG_H);

  update_fpn (self, raw);
  g52_preprocess (raw, self->fpn, img->data);
  dump_frame (raw, img->data);
  fpi_image_device_image_captured (FP_IMAGE_DEVICE (self), img);
}

static void
on_frame (FpDevice *dev, guint8 *data, guint16 len, gpointer user_data, GError *error)
{
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (dev);
  FpImageDevice *img_dev = FP_IMAGE_DEVICE (dev);
  guint16 raw[G52_RAW_W * G52_RAW_H];
  double cov;

  if (error || len < G52_FRAME_BYTES)
    {
      if (!error)
        error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "Short frame (%u)", len);
      g_free (data);
      self->busy = FALSE;
      if (self->deactivating)
        {
          g_error_free (error);
          maybe_finish_deactivate (self);
          return;
        }
      fpi_image_device_session_error (img_dev, error);
      return;
    }

  decode_frame (data, raw);
  g_free (data);

  /* restore the idle register before doing anything else */
  goodix_send_write_sensor_register (dev, REG_IMG_MODE, REG_IDLE, capture_step_restore, NULL);

  cov = g52_coverage (raw);

  if (self->deactivating)
    return;

  if (self->final_capture)
    {
      self->final_capture = FALSE;
      if (cov < G52_TOUCH_COVERAGE)
        {
          fp_dbg ("finger moved during capture (coverage %.2f)", cov);
          fpi_image_device_retry_scan (img_dev, FP_DEVICE_RETRY_CENTER_FINGER);
          self->want_finger = FALSE;
          return;
        }
      fp_dbg ("captured (coverage %.2f)", cov);
      report_image (self, raw);
      self->want_finger = FALSE;
      return;
    }

  if (self->want_finger)
    {
      self->touch_hits = cov >= G52_TOUCH_COVERAGE ? self->touch_hits + 1 : 0;
      if (self->touch_hits >= 2)
        {
          self->touch_hits = 0;
          fpi_image_device_report_finger_status (img_dev, TRUE);
          self->final_capture = TRUE;
        }
    }
  else if (cov <= G52_LIFT_COVERAGE)
    {
      fpi_image_device_report_finger_status (img_dev, FALSE);
    }
}

static void
capture_step_restore (FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (dev);

  self->busy = FALSE;
  if (error)
    {
      fp_warn ("register restore failed: %s", error->message);
      g_error_free (error);
    }
  if (self->deactivating)
    {
      maybe_finish_deactivate (self);
      return;
    }
  scan_schedule (self, self->final_capture ? G52_SETTLE_MS : G52_POLL_MS);
}

static void
capture_step_get (FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (dev);
  guint8 params[10];

  if (error)
    {
      self->busy = FALSE;
      if (self->deactivating)
        {
          g_error_free (error);
          maybe_finish_deactivate (self);
          return;
        }
      fpi_image_device_session_error (FP_IMAGE_DEVICE (dev), error);
      return;
    }
  image_params (self, TRUE, params);
  goodix_tls_read_image (dev, params, sizeof (params), on_frame, NULL);
}

static void
scan_tick (FpDevice *dev, gpointer user_data)
{
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (dev);

  self->poll_source = NULL;
  if (self->deactivating || !self->active || self->busy)
    return;
  self->busy = TRUE;
  goodix_send_write_sensor_register (dev, REG_IMG_MODE, REG_FINGER, capture_step_get, NULL);
}

static void
scan_schedule (FpiDeviceGoodixTls52XD *self, guint ms)
{
  if (self->poll_source || self->deactivating)
    return;
  self->poll_source = fpi_device_add_timeout (FP_DEVICE (self), ms, scan_tick, NULL, NULL);
  g_source_set_ready_time (self->poll_source, g_get_monotonic_time () + ms * (gint64) 1000);
}

/* ------------------------------------------------------------------------ */
/* matcher hooks                                                            */

#define G52_SAMPLES_TYPE G_VARIANT_TYPE ("aay")

static gboolean
g52_print_from_image (FpImageDevice *dev, FpImage *image, FpPrint *print, GError **error)
{
  size_t len = 0;
  int nkp = 0;
  uint8_t *blob;
  GVariant *sample, *arr;

  if (image->width != G52_IMG_W || image->height != G52_IMG_H)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID, "bad image size");
      return FALSE;
    }
  blob = g52_extract (image->data, &len, &nkp);
  fp_dbg ("extracted %d keypoints", nkp);
  if (nkp < 10)
    {
      free (blob);
      g_set_error (error, FP_DEVICE_RETRY, FP_DEVICE_RETRY_CENTER_FINGER,
                   "Too little fingerprint detail, please retry");
      return FALSE;
    }
  /* Enrollment diversity: reject near-duplicates of samples already in the
   * template so the 15 samples cover more of the finger. */
  if (fpi_device_get_current_action (FP_DEVICE (dev)) == FPI_DEVICE_ACTION_ENROLL)
    {
      FpPrint *tmpl = NULL;
      g_autoptr(GVariant) tv = NULL;

      fpi_device_get_enroll_data (FP_DEVICE (dev), &tmpl);
      if (tmpl)
        g_object_get (tmpl, "fpi-data", &tv, NULL);
      while (tv && g_variant_is_of_type (tv, G_VARIANT_TYPE_VARIANT))
        {
          GVariant *inner = g_variant_get_variant (tv);
          g_variant_unref (tv);
          tv = inner;
        }
      if (tv && g_variant_is_of_type (tv, G52_SAMPLES_TYPE))
        {
          for (gsize i = 0; i < g_variant_n_children (tv); i++)
            {
              g_autoptr(GVariant) e = g_variant_get_child_value (tv, i);
              gsize elen;
              const guint8 *edata = g_variant_get_fixed_array (e, &elen, 1);
              G52Score sc;

              if (g52_score (blob, len, edata, elen, &sc) == 0 && sc.corr >= G52_DUPLICATE_CORR)
                {
                  fp_info ("enroll: too similar to sample %" G_GSIZE_FORMAT " (corr %.3f)",
                           i + 1, sc.corr);
                  free (blob);
                  g_set_error (error, FP_DEVICE_RETRY, FP_DEVICE_RETRY_CENTER_FINGER,
                               "Same spot as before - shift your finger slightly");
                  return FALSE;
                }
            }
        }
    }

  sample = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, blob, len, 1);
  free (blob);
  arr = g_variant_new_array (G_VARIANT_TYPE_BYTESTRING, &sample, 1);
  g_object_set (print, "fpi-data", arr, NULL);
  return TRUE;
}

static void
g52_print_append (FpImageDevice *dev, FpPrint *template_print, FpPrint *sample)
{
  g_autoptr(GVariant) old = NULL;
  g_autoptr(GVariant) add = NULL;
  GVariantBuilder b;
  GVariantIter it;
  GVariant *child;

  g_object_get (template_print, "fpi-data", &old, NULL);
  g_object_get (sample, "fpi-data", &add, NULL);
  g_variant_builder_init (&b, G_VARIANT_TYPE ("aay"));
  if (old && g_variant_is_of_type (old, G52_SAMPLES_TYPE))
    {
      g_variant_iter_init (&it, old);
      while ((child = g_variant_iter_next_value (&it)))
        {
          g_variant_builder_add_value (&b, child);
          g_variant_unref (child);
        }
    }
  if (add && g_variant_is_of_type (add, G52_SAMPLES_TYPE))
    {
      g_variant_iter_init (&it, add);
      while ((child = g_variant_iter_next_value (&it)))
        {
          g_variant_builder_add_value (&b, child);
          g_variant_unref (child);
        }
    }
  g_object_set (template_print, "fpi-data", g_variant_builder_end (&b), NULL);
}

static FpiMatchResult
g52_print_match (FpImageDevice *dev, FpPrint *template_print, FpPrint *probe, GError **error)
{
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (dev);
  g_autoptr(GVariant) tv = NULL;
  g_autoptr(GVariant) pv = NULL;
  g_autoptr(GVariant) pblob = NULL;
  const guint8 *pdata;
  gsize plen, n;
  gint best_s = 0;
  gdouble best_c = -1;

  g_object_get (template_print, "fpi-data", &tv, NULL);
  g_object_get (probe, "fpi-data", &pv, NULL);
  if (!tv || !pv || !g_variant_is_of_type (tv, G52_SAMPLES_TYPE) ||
      !g_variant_is_of_type (pv, G52_SAMPLES_TYPE) || g_variant_n_children (pv) != 1)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "Print is not a goodixtls52xd template");
      return FPI_MATCH_ERROR;
    }
  pblob = g_variant_get_child_value (pv, 0);
  pdata = g_variant_get_fixed_array (pblob, &plen, 1);
  n = g_variant_n_children (tv);
  for (gsize i = 0; i < n; i++)
    {
      g_autoptr(GVariant) e = g_variant_get_child_value (tv, i);
      gsize elen;
      const guint8 *edata = g_variant_get_fixed_array (e, &elen, 1);
      G52Score sc;

      if (g52_score (pdata, plen, edata, elen, &sc) != 0)
        continue;
      best_s = MAX (best_s, sc.sigfm);
      best_c = MAX (best_c, sc.corr);
      if (sc.sigfm >= self->thr_sigfm || sc.corr >= self->thr_corr)
        {
          fp_info ("match: sample %" G_GSIZE_FORMAT "/%" G_GSIZE_FORMAT
                   " sigfm %d corr %.3f", i + 1, n, sc.sigfm, sc.corr);
          return FPI_MATCH_SUCCESS;
        }
    }
  fp_info ("no match: best sigfm %d (>= %d), best corr %.3f (>= %.3f), %" G_GSIZE_FORMAT " samples",
           best_s, self->thr_sigfm, best_c, self->thr_corr, n);
  return FPI_MATCH_FAIL;
}

/* ------------------------------------------------------------------------ */
/* device lifecycle                                                         */

static void
dev_init (FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE (img_dev);
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (dev);
  GError *error = NULL;

  if (!load_psk (self, &error))
    {
      fpi_image_device_open_complete (img_dev, error);
      return;
    }
  load_fpn (self);
  /* clear any half-finished session left by a previous process */
  if (!g_usb_device_reset (fpi_device_get_usb_device (dev), &error))
    {
      fp_warn ("USB reset failed: %s", error->message);
      g_clear_error (&error);
    }
  if (!goodix_dev_init (dev, &error))
    {
      fpi_image_device_open_complete (img_dev, error);
      return;
    }
  fpi_image_device_open_complete (img_dev, NULL);
}

static void
dev_deinit (FpImageDevice *img_dev)
{
  FpDevice *dev = FP_DEVICE (img_dev);
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (dev);
  GError *error = NULL;

  save_fpn (self);
  memset (self->psk, 0, sizeof (self->psk));
  goodix_dev_deinit (dev, &error);
  fpi_image_device_close_complete (img_dev, error);
}

static void
dev_activate (FpImageDevice *img_dev)
{
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (img_dev);

  self->active = FALSE;
  self->deactivating = FALSE;
  self->busy = FALSE;
  self->final_capture = FALSE;
  self->touch_hits = 0;
  fpi_ssm_start (fpi_ssm_new (FP_DEVICE (img_dev), activate_run_state, ACTIVATE_NUM_STATES),
                 activate_complete);
}

static void
dev_change_state (FpImageDevice *img_dev, FpiImageDeviceState state)
{
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (img_dev);

  switch (state)
    {
    case FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON:
      self->want_finger = TRUE;
      self->touch_hits = 0;
      scan_schedule (self, G52_POLL_MS);
      break;

    case FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF:
      self->want_finger = FALSE;
      scan_schedule (self, G52_POLL_MS);
      break;

    case FPI_IMAGE_DEVICE_STATE_INACTIVE:
    case FPI_IMAGE_DEVICE_STATE_ACTIVATING:
    case FPI_IMAGE_DEVICE_STATE_DEACTIVATING:
    case FPI_IMAGE_DEVICE_STATE_IDLE:
    case FPI_IMAGE_DEVICE_STATE_CAPTURE:
    default:
      break;
    }
}

static void
maybe_finish_deactivate (FpiDeviceGoodixTls52XD *self)
{
  FpDevice *dev = FP_DEVICE (self);
  GError *error = NULL;

  if (!self->deactivating || self->busy)
    return;
  g_clear_pointer (&self->poll_source, g_source_destroy);
  self->active = FALSE;
  self->deactivating = FALSE;
  save_fpn (self);
  goodix_reset_state (dev);
  goodix_shutdown_tls (dev, &error);
  fpi_image_device_deactivate_complete (FP_IMAGE_DEVICE (dev), error);
}

static void
dev_deactivate (FpImageDevice *img_dev)
{
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (img_dev);

  self->deactivating = TRUE;
  g_clear_pointer (&self->poll_source, g_source_destroy);
  maybe_finish_deactivate (self);
}

static void
fpi_device_goodixtls52xd_finalize (GObject *obj)
{
  FpiDeviceGoodixTls52XD *self = FPI_DEVICE_GOODIXTLS52XD (obj);

  g_clear_pointer (&self->fpn, g_free);
  G_OBJECT_CLASS (fpi_device_goodixtls52xd_parent_class)->finalize (obj);
}

static void
fpi_device_goodixtls52xd_init (FpiDeviceGoodixTls52XD *self)
{
  const gchar *ts = g_getenv ("GOODIX52XD_THRESHOLD_SIGFM");
  const gchar *tc = g_getenv ("GOODIX52XD_THRESHOLD_CORR");

  self->thr_sigfm = ts ? atoi (ts) : G52_DEFAULT_TS;
  self->thr_corr = tc ? g_ascii_strtod (tc, NULL) : G52_DEFAULT_TC;
}

static void
fpi_device_goodixtls52xd_class_init (FpiDeviceGoodixTls52XDClass *class)
{
  GObjectClass *obj_class = G_OBJECT_CLASS (class);
  FpiDeviceGoodixTlsClass *gx_class = FPI_DEVICE_GOODIXTLS_CLASS (class);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (class);
  FpImageDeviceClass *img_dev_class = FP_IMAGE_DEVICE_CLASS (class);

  obj_class->finalize = fpi_device_goodixtls52xd_finalize;

  gx_class->interface = GOODIX_52XD_INTERFACE;
  gx_class->ep_in = GOODIX_52XD_EP_IN;
  gx_class->ep_out = GOODIX_52XD_EP_OUT;

  dev_class->id = "goodixtls52xd";
  dev_class->full_name = "Goodix TLS Fingerprint Sensor 52XD";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = G52_ENROLL_STAGES;

  img_dev_class->img_width = G52_IMG_W;
  img_dev_class->img_height = G52_IMG_H;
  img_dev_class->img_open = dev_init;
  img_dev_class->img_close = dev_deinit;
  img_dev_class->activate = dev_activate;
  img_dev_class->change_state = dev_change_state;
  img_dev_class->deactivate = dev_deactivate;

  img_dev_class->print_from_image = g52_print_from_image;
  img_dev_class->print_append = g52_print_append;
  img_dev_class->print_match = g52_print_match;

  fpi_device_class_auto_initialize_features (dev_class);
}
