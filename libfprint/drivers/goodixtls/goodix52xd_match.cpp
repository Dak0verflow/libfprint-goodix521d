/*
 * Goodix 27c6:521d image preprocessing + matching
 *
 * Scoring is derived from SIGFM (C) 2022 Matthieu CHARETTE,
 * Natasha England-Elbro, Timur Mangliev (LGPL-2.1-or-later), with relaxed
 * tolerances tuned for this sensor, plus a rotated cross-correlation score.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */
#include "goodix52xd_match.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <set>
#include <tuple>
#include <vector>

#include <opencv2/core.hpp>
#include <opencv2/features2d.hpp>
#include <opencv2/imgproc.hpp>
#if __has_include(<opencv2/geometry.hpp>)
#include <opencv2/geometry.hpp> /* OpenCV 5: getRotationMatrix2D */
#endif

namespace {

constexpr double kRatio = 0.80;
constexpr double kLenTol = 0.10;
constexpr double kAngTol = 0.10;
constexpr int kMinMatch = 5;
constexpr int kUpscale = 2;
constexpr int kCorrPatchH = 40;
constexpr int kCorrPatchW = 32;
constexpr int kCorrAngleMax = 24;
constexpr int kCorrAngleStep = 3;
constexpr uint32_t kMagic = 0x53323547; /* "G52S" */
constexpr uint8_t kVersion = 1;

double percentile (std::vector<float> v, double p)
{
  /* numpy.percentile default ("linear") */
  std::sort (v.begin (), v.end ());
  double idx = p / 100.0 * (v.size () - 1);
  size_t lo = (size_t) std::floor (idx), hi = (size_t) std::ceil (idx);
  return v[lo] + (v[hi] - v[lo]) * (idx - lo);
}

float median (std::vector<float> s)
{
  /* numpy.median: mean of the two middle values for even sizes */
  size_t m = s.size () / 2;
  std::nth_element (s.begin (), s.begin () + m, s.end ());
  float med = s[m];
  if (s.size () % 2 == 0)
    med = (med + *std::max_element (s.begin (), s.begin () + m)) / 2.0f;
  return med;
}

void remove_row_col_median (cv::Mat &x)
{
  std::vector<float> v;
  for (int r = 0; r < x.rows; r++)
    {
      v.assign (x.ptr<float> (r), x.ptr<float> (r) + x.cols);
      float med = median (v);
      for (int c = 0; c < x.cols; c++)
        x.at<float> (r, c) -= med;
    }
  for (int c = 0; c < x.cols; c++)
    {
      v.clear ();
      for (int r = 0; r < x.rows; r++)
        v.push_back (x.at<float> (r, c));
      float med = median (v);
      for (int r = 0; r < x.rows; r++)
        x.at<float> (r, c) -= med;
    }
}

struct Sample {
  std::vector<cv::Point2f> pts;
  cv::Mat desc;     /* CV_32F n x 128 */
  cv::Mat ridge;    /* CV_8U 72 x 56 */
};

template <typename T> void put (std::vector<uint8_t> &b, const T &v)
{
  const uint8_t *p = reinterpret_cast<const uint8_t *>(&v);
  b.insert (b.end (), p, p + sizeof (T));
}

template <typename T> bool get (const uint8_t *&p, const uint8_t *end, T &v)
{
  if ((size_t) (end - p) < sizeof (T))
    return false;
  std::memcpy (&v, p, sizeof (T));
  p += sizeof (T);
  return true;
}

bool deserialize (const uint8_t *buf, size_t len, Sample &s)
{
  const uint8_t *p = buf, *end = buf + len;
  uint32_t magic;
  uint8_t ver;
  uint16_t n, dim;
  if (!get (p, end, magic) || magic != kMagic || !get (p, end, ver) || ver != kVersion ||
      !get (p, end, n) || !get (p, end, dim) || dim != 128)
    return false;
  s.pts.resize (n);
  for (auto &pt : s.pts)
    if (!get (p, end, pt.x) || !get (p, end, pt.y))
      return false;
  size_t dbytes = (size_t) n * dim;
  if ((size_t) (end - p) < dbytes + G52_IMG_W * G52_IMG_H)
    return false;
  cv::Mat d8 (n, dim, CV_8U, const_cast<uint8_t *>(p));
  d8.convertTo (s.desc, CV_32F);
  p += dbytes;
  s.ridge = cv::Mat (G52_IMG_H, G52_IMG_W, CV_8U, const_cast<uint8_t *>(p)).clone ();
  return true;
}

int sigfm_score (const Sample &a, const Sample &b)
{
  if (a.desc.rows < 2 || b.desc.rows < 2)
    return 0;
  std::vector<std::vector<cv::DMatch>> knn;
  cv::BFMatcher (cv::NORM_L2).knnMatch (a.desc, b.desc, knn, 2);

  using P = std::tuple<int, int, int, int>;
  std::set<P> uniq;
  for (const auto &m : knn)
    if (m.size () == 2 && m[0].distance < kRatio * m[1].distance)
      {
        const auto &p1 = a.pts[m[0].queryIdx], &p2 = b.pts[m[0].trainIdx];
        uniq.emplace ((int) p1.x, (int) p1.y, (int) p2.x, (int) p2.y);
      }
  if ((int) uniq.size () < kMinMatch)
    return 0;

  std::vector<P> ms (uniq.begin (), uniq.end ());
  std::vector<std::pair<double, double>> angles; /* (cos-ish, sin-ish) as in SIGFM */
  for (size_t j = 0; j < ms.size (); j++)
    for (size_t k = j + 1; k < ms.size (); k++)
      {
        auto [ax1, ay1, ax2, ay2] = ms[j];
        auto [bx1, by1, bx2, by2] = ms[k];
        double v1x = ax1 - bx1, v1y = ay1 - by1, v2x = ax2 - bx2, v2y = ay2 - by2;
        double l1 = std::hypot (v1x, v1y), l2 = std::hypot (v2x, v2y);
        if (l1 == 0 || l2 == 0)
          continue;
        if (1 - std::min (l1, l2) / std::max (l1, l2) <= kLenTol)
          {
            double prod = l1 * l2;
            double s_ = std::clamp ((v1x * v2x + v1y * v2y) / prod, -1.0, 1.0);
            double c_ = std::clamp ((v1x * v2y - v1y * v2x) / prod, -1.0, 1.0);
            angles.emplace_back (M_PI / 2 + std::asin (s_), std::acos (c_));
          }
      }
  if ((int) angles.size () < kMinMatch)
    return 0;

  int count = 0;
  for (size_t j = 0; j < angles.size (); j++)
    for (size_t k = j + 1; k < angles.size (); k++)
      {
        auto [c1, s1] = angles[j];
        auto [c2, s2] = angles[k];
        double ms_ = std::max (s1, s2), mc = std::max (c1, c2);
        if (ms_ == 0 || mc == 0)
          continue;
        if (1 - std::min (s1, s2) / ms_ <= kAngTol && 1 - std::min (c1, c2) / mc <= kAngTol)
          count++;
      }
  return count;
}

cv::Mat normalized (const cv::Mat &u8)
{
  cv::Mat f;
  u8.convertTo (f, CV_32F);
  cv::Scalar mean, sd;
  cv::meanStdDev (f, mean, sd);
  return (f - mean[0]) / (sd[0] + 1e-6);
}

double corr_score (const Sample &probe, const Sample &enrolled)
{
  cv::Mat p = normalized (probe.ridge), t = normalized (enrolled.ridge);
  const int h = p.rows, w = p.cols, cy = h / 2, cx = w / 2;
  cv::Rect roi (cx - kCorrPatchW / 2, cy - kCorrPatchH / 2, kCorrPatchW, kCorrPatchH);
  double best = -1;
  for (int a = -kCorrAngleMax; a <= kCorrAngleMax; a += kCorrAngleStep)
    {
      cv::Mat M = cv::getRotationMatrix2D (cv::Point2f (w / 2.0f, h / 2.0f), a, 1.0), r, res;
      cv::warpAffine (p, r, M, p.size (), cv::INTER_LINEAR, cv::BORDER_REFLECT);
      cv::matchTemplate (t, r (roi), res, cv::TM_CCOEFF_NORMED);
      double mx;
      cv::minMaxLoc (res, nullptr, &mx);
      best = std::max (best, mx);
    }
  return best;
}

} // namespace

extern "C" {

double g52_coverage (const uint16_t *raw)
{
  int covered = 0, total = 0;
  for (int y = G52_CROP; y < G52_RAW_H - G52_CROP; y++)
    for (int x = G52_CROP; x < G52_RAW_W - G52_CROP; x++, total++)
      covered += raw[y * G52_RAW_W + x] < 3400;
  return (double) covered / total;
}

void g52_preprocess (const uint16_t *raw, const float *fpn, uint8_t *out)
{
  cv::Mat x (G52_RAW_H, G52_RAW_W, CV_32F);
  for (int i = 0; i < G52_RAW_W * G52_RAW_H; i++)
    ((float *) x.data)[i] = (float) raw[i] - (fpn ? fpn[i] : 0.0f);
  cv::Mat c = x (cv::Rect (G52_CROP, G52_CROP, G52_IMG_W, G52_IMG_H)).clone ();
  remove_row_col_median (c);
  cv::Mat g1, g2;
  cv::GaussianBlur (c, g1, cv::Size (0, 0), 0.8);
  cv::GaussianBlur (c, g2, cv::Size (0, 0), 3.0);
  cv::Mat bp = g1 - g2;
  std::vector<float> v (bp.begin<float> (), bp.end<float> ());
  double lo = percentile (v, 1), hi = percentile (v, 99);
  double span = std::max (hi - lo, 1.0);
  for (int i = 0; i < G52_IMG_W * G52_IMG_H; i++)
    {
      double s = (((float *) bp.data)[i] - lo) / span * 255.0;
      out[i] = (uint8_t) std::clamp (s, 0.0, 255.0);
    }
}

uint8_t *g52_extract (const uint8_t *img, size_t *out_len, int *n_keypoints)
{
  cv::Mat m (G52_IMG_H, G52_IMG_W, CV_8U, const_cast<uint8_t *>(img)), up;
  cv::resize (m, up, cv::Size (), kUpscale, kUpscale, cv::INTER_CUBIC);
  std::vector<cv::KeyPoint> kp;
  cv::Mat desc;
  cv::SIFT::create (0, 3, 0.04, 10, 1.6, CV_8U)->detectAndCompute (up, cv::noArray (), kp, desc);

  std::vector<uint8_t> b;
  put (b, kMagic);
  put (b, kVersion);
  put (b, (uint16_t) kp.size ());
  put (b, (uint16_t) 128);
  for (const auto &k : kp)
    {
      put (b, k.pt.x);
      put (b, k.pt.y);
    }
  if (!kp.empty ())
    b.insert (b.end (), desc.data, desc.data + desc.total ());
  b.insert (b.end (), img, img + G52_IMG_W * G52_IMG_H);

  uint8_t *ret = (uint8_t *) malloc (b.size ());
  std::memcpy (ret, b.data (), b.size ());
  *out_len = b.size ();
  if (n_keypoints)
    *n_keypoints = (int) kp.size ();
  return ret;
}

int g52_score (const uint8_t *probe, size_t probe_len,
               const uint8_t *enrolled, size_t enrolled_len, G52Score *out)
{
  try
    {
      Sample a, b;
      if (!deserialize (probe, probe_len, a) || !deserialize (enrolled, enrolled_len, b))
        return -1;
      out->sigfm = sigfm_score (a, b);
      out->corr = corr_score (a, b);
      return 0;
    }
  catch (...)
    {
      return -1;
    }
}

} // extern "C"
