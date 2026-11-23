/*
 * Goodix 27c6:521d image preprocessing + matching (SIGFM-derived)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define G52_RAW_W 64
#define G52_RAW_H 80
#define G52_CROP 4
#define G52_IMG_W (G52_RAW_W - 2 * G52_CROP) /* 56 */
#define G52_IMG_H (G52_RAW_H - 2 * G52_CROP) /* 72 */

/* raw: 64x80 12-bit finger-mode frame (row-major, 64 wide).
 * fpn: optional 64x80 fixed-pattern estimate (NULL = none).
 * out: 56x72 8-bit ridge image. */
void g52_preprocess (const uint16_t *raw, const float *fpn, uint8_t *out);

/* Fraction (0..1) of the sensor covered by a finger (finger-mode frame). */
double g52_coverage (const uint16_t *raw);

/* Serialized sample (features + ridge image). Caller frees with free(). */
uint8_t *g52_extract (const uint8_t *img, size_t *out_len, int *n_keypoints);

typedef struct {
  int    sigfm;    /* geometric-consistency score */
  double corr;     /* best rotated normalized cross-correlation */
} G52Score;

/* Returns 0 on success, -1 if a blob is malformed. */
int g52_score (const uint8_t *probe, size_t probe_len,
               const uint8_t *enrolled, size_t enrolled_len,
               G52Score *out);

#ifdef __cplusplus
}
#endif
