#pragma once
#include <graphene/chain/types.hpp>
#include <graphene/protocol/asset.hpp>
#include <fc/uint128.hpp>
#include <cmath>

namespace graphene { namespace chain {

/// AB (Asymmetric Bounded) pool helpers for n = 2.
///
/// Invariant: (x + xv)^w * (y + yv)^(1-w) = k
/// Price: p = (w/(1-w)) * (y + yv)/(x + xv)
/// Bounds: [P_low, P_high]; outside, one reserve is zero (single-sided).
///
/// All math uses 128-bit integers where it fits; the weighted-product exponent
/// is evaluated with long double and rounded toward the pool (pool never
/// overpays). For consensus, both nodes use the identical computation.

/// Compute virtual offsets xv, yv from weight w (as num/den) and price bounds.
/// P_low, P_high are fixed-point prices.
/// Returns (xv, yv). Returns (0,0) on invalid input.
inline std::pair<uint64_t, uint64_t> compute_abpool_virtual_offsets(
    uint64_t w_num, uint64_t w_den,
    uint64_t P_low, uint64_t P_high)
{
    if (w_num == 0 || w_den == 0 || w_num >= w_den ||
        P_low == 0 || P_high == 0 || P_low >= P_high)
        return {0, 0};

    // Scale derived from the price bounds (integer, no roots).
    uint64_t diff = P_high - P_low;
    __uint128_t num = (__uint128_t)P_high * P_low;
    uint64_t xv = (uint64_t)(num / diff);
    if (xv == 0) xv = 1;

    // yv = xv * (1-w)/w * P_low  (with (1-w)/w = (w_den - w_num)/w_num)
    __uint128_t yv_num = (__uint128_t)xv * (w_den - w_num) * P_low;
    uint64_t yv = (uint64_t)(yv_num / w_num);
    if (yv == 0) yv = 1;

    return {xv, yv};
}

/// Compute the payout dy for dx added to the input (real) reserve x in an AB pool.
/// real_x, real_y are the actual reserves (without virtual offsets).
/// xv, yv are the virtual offsets.
/// w_num, w_den define w = w_num / w_den.
/// Returns 0 on invalid input or if no payout. Rounding favors the pool.
inline uint64_t compute_abpool_dy(
    uint64_t real_x, uint64_t real_y, uint64_t xv, uint64_t yv,
    uint64_t w_num, uint64_t w_den,
    uint64_t dx)
{
    if (w_num == 0 || w_den == 0 || w_num >= w_den) return 0;
    if (dx == 0) return 0;

    __uint128_t X = (__uint128_t)real_x + xv;   // virtual input balance
    __uint128_t Y = (__uint128_t)real_y + yv;   // virtual output balance
    __uint128_t Xp = X + dx;                    // new virtual input balance

    if (X == 0 || Y == 0 || Xp == 0) return 0;

    // exponent r = w/(1-w) = w_num/(w_den - w_num)
    long double r = (long double)w_num / (long double)(w_den - w_num);
    long double ratio = (long double)X / (long double)Xp;  // X / Xp < 1
    long double factor = std::pow(ratio, (double)r);       // (X/Xp)^r
    long double Yp_ld = (long double)Y * factor;           // new virtual output balance

    // Round Yp up (pool favors pool: pays less).
    uint64_t Yp = (uint64_t)std::ceil(Yp_ld);
    if (Yp > (uint64_t)Y) Yp = (uint64_t)Y;  // clamp
    if (Yp < yv) Yp = yv;                     // cannot go below virtual offset

    if (Yp >= (uint64_t)Y) return 0;           // no payout

    __uint128_t dy = (uint64_t)Y - Yp;        // virtual payout == real payout
    if (dy > real_y) dy = real_y;             // clamp to reserve
    return (uint64_t)dy;
}

/// Check if a price is within the AB pool's bounds.
inline bool abpool_in_range(uint64_t price_wad, uint64_t p_low, uint64_t p_high)
{
    return price_wad >= p_low && price_wad <= p_high;
}

} } // graphene::chain