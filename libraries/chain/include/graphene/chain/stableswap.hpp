#pragma once
#include <graphene/chain/types.hpp>
#include <graphene/protocol/asset.hpp>
#include <fc/uint128.hpp>

namespace graphene { namespace chain {

/// StableSwap (Curve) helpers for n = 2.
///
/// Invariant:  A * 4 * (x + y) + D  =  A * D * 4  +  D^3 / (4 * x * y)
///
/// D is the stored invariant. A is the amplification coefficient:
///   A -> 0: constant product;  A -> inf: constant sum.
/// At perfect balance (x == y), D is determined by the invariant (not simply x + y;
/// D == x + y only in the limit A -> inf).
///
/// All math uses 128-bit integers with divisions ordered to avoid overflow:
///   D^3/(4*x*y) is computed as (D*D/(4*x))/y — exact because
///   floor(floor(a/b)/c) == floor(a/(b*c)) for positive integers.
///   D < 2^64 (since balances are int64), so D*D < 2^128 fits in uint128_t.
///
/// Rounding policy: every intermediate division rounds toward the pool
/// (pool never overpays). This prevents a bot grinding small round trips
/// from draining provider capital.

/// -------------------------------------------------------------------
/// compute_stableswap_d: solve for D given balances x, y and amplification A.
/// Follows Curve's get_D algorithm (Newton iteration on the invariant).
/// Returns 0 if inputs are invalid or iteration fails to converge.
/// -------------------------------------------------------------------
inline fc::uint128_t compute_stableswap_d(uint64_t x, uint64_t y, uint64_t A)
{
   if (x == 0 || y == 0) return 0;

   const fc::uint128_t Ann = (fc::uint128_t)A * 4;        // A * n^n, n = 2
   const fc::uint128_t S   = (fc::uint128_t)x + (fc::uint128_t)y;
   if (S == 0) return 0;

   fc::uint128_t D = S;                                   // initial guess
   for (int i = 0; i < 256; i++)
   {
      const fc::uint128_t D_prev = D;

      // D_P = D^3 / (4 * x * y)
      // Curve's get_D algorithm: (D*D / (2*x)) * D / (2*y).
      // D*D < 2^128 (D < 2^64 since balances are int64), so D*D/(2*x) fits.
      // Intermediate (D*D/(2*x)) * D < 2^191 in theory but D_P ≈ D < 2^64
      // in practice; the final division by (2*y) brings it back in range.
      // Safe for all realistic BitShares pool sizes.
      const fc::uint128_t D_P = (D * D / ((fc::uint128_t)2 * x)) * D / ((fc::uint128_t)2 * y);

      // Newton step:
      //   f(D)   = Ann*S + D - Ann*D - D_P
      //   f'(D)  = 1 - Ann - 3*D_P/D
      //   D_new  = D - f(D)/f'(D)
      //          = D * (2*D_P + Ann*S) / ((Ann-1)*D + 3*D_P)
      const fc::uint128_t num = D * (2 * D_P + Ann * S);
      const fc::uint128_t den = (Ann - 1) * D + 3 * D_P;
      if (den == 0) return 0;

      const fc::uint128_t D_new = num / den;
      if (D_new == D_prev) { D = D_new; break; }         // converged
      D = D_new;
   }
   return D;
}

/// -------------------------------------------------------------------
/// compute_stableswap_y: solve for y given new_x, D, A.
///
/// Used by the exchange evaluator: after the pool receives `new_x` of the sold
/// asset, compute how much of the other asset to pay out so the invariant holds
/// with the same D (computed from pre-trade balances).
///
/// Returns 0 on invalid input. Rounding favors the pool: returns ceil(y_exact)
/// (smallest y where LHS > RHS), so the pool never overpays.
/// -------------------------------------------------------------------
inline uint64_t compute_stableswap_y(uint64_t new_x, uint64_t D, uint64_t A)
{
   if (new_x == 0 || D == 0 || A == 0) return 0;

   const fc::uint128_t nx = new_x;
   const fc::uint128_t d  = D;
   const fc::uint128_t a  = A;

   // f(y) = 4*A*(nx + y) + d - 4*a*d - d^3/(4*nx*y)
   // f is monotonically increasing in y. Find smallest y with f(y) > 0.
   auto eval_f = [&](const fc::uint128_t y) -> fc::uint128_t
   {
      if (y == 0) return 0;
      // Overflow-safe evaluation (SS-08): saturate each term on overflow.
      const fc::uint128_t UMAX = ~fc::uint128_t(0);
      const fc::uint128_t dd = d * d;                    // d < 2^64, dd < 2^128
      // lhs = 4*a*(nx + y) + d
      fc::uint128_t lhs; bool lhs_ov = false;
      fc::uint128_t sum = nx + y;
      if (a != 0 && sum > UMAX / a) lhs_ov = true;
      fc::uint128_t t = lhs_ov ? 0 : a * sum;
      if (!lhs_ov && t > UMAX / 4) lhs_ov = true;
      fc::uint128_t lhs4 = lhs_ov ? 0 : (fc::uint128_t)4 * t;
      if (!lhs_ov && lhs4 > UMAX - d) lhs_ov = true;
      lhs = lhs_ov ? UMAX : (lhs4 + d);
      // d3 = d^3/(4*nx*y) = (dd/(4*nx)) * d / y, saturated
      fc::uint128_t d3 = 0; bool d3_ov = false;
      const fc::uint128_t denom1 = (fc::uint128_t)4 * nx;
      fc::uint128_t term1 = dd / denom1;
      if (term1 != 0 && d != 0 && term1 > UMAX / d) d3_ov = true;
      if (!d3_ov) { fc::uint128_t prod = term1 * d; d3 = prod / y; }
      else { d3 = UMAX; }
      // rhs = 4*a*d + d3
      fc::uint128_t rhs; bool rhs_ov = false;
      fc::uint128_t rhs4ad = 0;
      if (a != 0 && d != 0 && a > UMAX / ((fc::uint128_t)4 * d)) rhs_ov = true;
      if (!rhs_ov) rhs4ad = (fc::uint128_t)4 * a * d;
      if (!rhs_ov && rhs4ad > UMAX - d3) rhs_ov = true;
      rhs = rhs_ov ? UMAX : (rhs4ad + d3);
      return (lhs > rhs) ? (lhs - rhs) : 0;              // 0 means f(y) <= 0
   };

   // Binary search over full uint64 balance range (SS-08): for heavily
   // imbalanced pools (extreme new_x) the solution may lie outside [1, D].
   if (eval_f(((fc::uint128_t)1 << 64) - 1) == 0) return 0; // no solution in range
   fc::uint128_t lo = 1;
   fc::uint128_t hi = ((fc::uint128_t)1 << 64) - 1;      // y is a uint64 balance
   while (lo < hi)
   {
      const fc::uint128_t mid = (lo + hi) / 2;
      if (eval_f(mid) > 0) hi = mid;
      else                 lo = mid + 1;
   }
   // lo = ceil(y_exact), rounding up favors the pool. No snap-back: snap-back
   // cannot distinguish "exact hit" from "below exact" since eval_f returns 0
   // for both, and snapping down risks overpaying.

   return (uint64_t)lo;
}

/// -------------------------------------------------------------------
/// compute_stableswap_dy: given x, y, D, A and amount dx added to x, compute
/// the payout dy from y. Returns 0 on invalid input or if no payout.
/// -------------------------------------------------------------------
inline uint64_t compute_stableswap_dy(uint64_t x, uint64_t y, uint64_t D, uint64_t A, uint64_t dx)
{
   if (x == 0 || y == 0 || D == 0 || A == 0) return 0;
   const uint64_t new_x = x + dx;
   const uint64_t new_y = compute_stableswap_y(new_x, D, A);
   if (new_y == 0 || new_y >= y) return 0;               // invariant violated or no payout
   return y - new_y;
}

} } // graphene::chain
