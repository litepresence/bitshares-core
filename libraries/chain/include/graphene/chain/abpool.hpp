#pragma once
#include <graphene/chain/types.hpp>
#include <graphene/protocol/asset.hpp>
#include <fc/uint128.hpp>

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
// Integer nth-root (floor) via Newton's method. Returns floor(n^(1/root)).
static uint64_t int_nth_root(__uint128_t n, uint64_t root)
{
    if (root == 0) return 0;
    if (n == 0) return 0;
    if (root == 1) return (uint64_t)n;
    // initial guess
    uint64_t x = 1;
    while (true) {
        // compute x^root approximately; if x^root > n, shrink
        __uint128_t p = 1;
        bool overflow = false;
        for (uint64_t i = 0; i < root; i++) {
            p *= x;
            if (p > n * 2 + 1) { overflow = true; break; }
        }
        if (overflow || p > n) {
            if (x == 1) break;
            x--;
        } else {
            // try x+1
            __uint128_t p2 = 1;
            bool ov2 = false;
            for (uint64_t i = 0; i < root; i++) {
                p2 *= (x + 1);
                if (p2 > n * 2 + 1) { ov2 = true; break; }
            }
            if (ov2 || p2 > n)
                break;
            x++;
        }
    }
    return x;
}

inline std::pair<uint64_t, uint64_t> compute_abpool_virtual_offsets(
    uint64_t w_num, uint64_t w_den,
    uint64_t P_low, uint64_t P_high)
{
    if (w_num == 0 || w_den == 0 || w_num >= w_den ||
        P_low == 0 || P_high == 0 || P_low >= P_high)
        return {0, 0};

    // Balancer derivation: yv = xv * (P_low^w * P_high^(1-w)) / a,  a = w/(1-w).
    // Equivalently (P_low^w_num * P_high^(w_den - w_num))^(1/w_den) / a.
    // xv chosen as P_high*P_low/(P_high-P_low) (harmonic scale), positive.
    uint64_t diff = P_high - P_low;
    __uint128_t num = (__uint128_t)P_high * P_low;
    uint64_t xv = (uint64_t)(num / diff);
    if (xv == 0) xv = 1;

    // Compute P_low^w_num * P_high^(w_den - w_num) as __uint128 (best effort; clamp on overflow).
    __uint128_t prod = 1;
    for (uint64_t i = 0; i < w_num; i++) {
        prod *= P_low;
        if (prod == 0) { prod = 1; break; }
    }
    for (uint64_t i = 0; i < (w_den - w_num); i++) {
        prod *= P_high;
        if (prod == 0) { prod = 1; break; }
    }
    uint64_t geom = int_nth_root(prod, w_den);
    if (geom == 0) geom = 1;

    // yv = xv * geom / a,  a = w_num/(w_den-w_num)  =>  yv = xv * geom * (w_den-w_num) / w_num
    __uint128_t yv_num = (__uint128_t)xv * geom * (w_den - w_num);
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
    if (X >= Xp) return 0;  // no payout if no input added

    // Deterministic integer-only computation of (X/Xp)^r, r = w_num/(w_den-w_num).
    // Fixed-point scale 2^32.
    const __int128_t SCALE = (__int128_t)1 << 32;
    uint64_t a = w_num;
    uint64_t b = w_den - w_num;
    if (b == 0) return 0;

    // t = (Xp - X) / Xp  in fixed point
    __uint128_t t_fixed = (__uint128_t)(Xp - X) * (1ULL << 32) / (uint64_t)Xp;

    // r in fixed point
    __int128_t r_fixed = (__int128_t)a * SCALE / (__int128_t)b;

    // Binomial series: (1-t)^r = sum_{k>=0} C(r,k) * (-t)^k
    __int128_t factor = SCALE; // k=0
    __uint128_t t_pow = SCALE; // t^0
    __int128_t coeff = SCALE;  // C(r,0)=1
    for (int k = 1; k <= 12; k++) {
        // coeff = coeff * (r - (k-1)) / k
        __int128_t rm = r_fixed - (__int128_t)(k - 1) * SCALE;
        coeff = coeff * rm / ((__int128_t)k * SCALE);
        // t_pow = t_pow * t / SCALE
        t_pow = t_pow * t_fixed / (1ULL << 32);
        __int128_t term = coeff * (__int128_t)t_pow / SCALE;
        if (k % 2 == 1) term = -term;
        factor += term;
        if (factor <= 0) { factor = 1; break; }
    }
    if (factor <= 0) factor = 1;
    if (factor > SCALE) factor = SCALE; // clamp (1-t)^r <= 1

    // Yp = ceil(Y * factor / SCALE)
    __uint128_t prod = (__uint128_t)Y * (uint64_t)factor;
    uint64_t Yp = (uint64_t)((prod + (1ULL << 32) - 1) >> 32);
    if (Yp > (uint64_t)Y) Yp = (uint64_t)Y;  // clamp
    if (Yp < yv) Yp = (uint64_t)yv;           // cannot go below virtual offset

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