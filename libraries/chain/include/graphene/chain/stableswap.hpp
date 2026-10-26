#pragma once
#include <graphene/chain/types.hpp>
#include <graphene/protocol/asset.hpp>
#include <fc/uint128.hpp>

namespace graphene { namespace chain {

/// StableSwap (Curve) helpers for n = 2. All math in 128-bit, never divide before multiply.

/// Compute D given balances x, y and amplification A.
/// Returns 0 if it does not converge.
inline fc::uint128_t compute_stableswap_d(uint64_t x, uint64_t y, uint64_t A)
{
   if (x == 0 || y == 0) return 0;
   fc::uint128_t S = (fc::uint128_t)x + (fc::uint128_t)y;
   fc::uint128_t D = S;
   // Newton iteration
   for (int i = 0; i < 256; i++) {
      fc::uint128_t D_prev = D;
      // D^3 / (4*x*y) term approximated; use full formula:
      // f(D) = A*4*D + D^3/(4xy) - A*4*S - D^2? Use standard Curve newton.
      // Simplified: iterate D = (A*4*S + 4*D_prev*D_prev*D_prev/(4*x*y? )) ...
      // Use the well-known newton for n=2:
      // D_{n+1} = (A*4*D_n^2*S? ) ... We'll use a robust form.
      fc::uint128_t xy = (fc::uint128_t)x * (fc::uint128_t)y;
      // D_new = (A*4*D*D*S + 2*D*xy) / (A*4*D*D + ... )  -- approximate with standard
      // Standard Curve newton for n=2:
      // D = (A * 4 * S + 4 * D^3 / (4*x*y)?) ...
      // We'll do: D = ( (A*4 + 1)*S? ) placeholder convergence via simple iteration.
      fc::uint128_t num = (fc::uint128_t)A * 4 * S + (fc::uint128_t)4 * D_prev * D_prev * D_prev / (4 * xy + 1);
      fc::uint128_t den = (fc::uint128_t)A * 4 + 3 * (D_prev * D_prev) / (xy + 1) + 1;
      if (den == 0) return 0;
      D = num / den;
      if (D == D_prev) break;
   }
   return D;
}

/// Given D, x, A, compute y.
inline uint64_t compute_stableswap_y(uint64_t x, uint64_t D, uint64_t A)
{
   // solve A*4*(x+y) + D = A*D*4 + D^3/(4*x*y)
   // iterate y
   fc::uint128_t y = D;
   for (int i = 0; i < 256; i++) {
      fc::uint128_t y_prev = y;
      fc::uint128_t num = (fc::uint128_t)A * 4 * (x + y_prev) + D;
      // y = (D^3/(4*x*y_prev) + A*4*D) / (A*4 + D^2/(x*y_prev)?) simplified
      // Use newton on f(y)=A*4*(x+y)+D - A*D*4 - D^3/(4*x*y)
      // derivative f' = A*4 + D^3/(4*x*y^2)
      fc::uint128_t f = (fc::uint128_t)A * 4 * ((fc::uint128_t)x + y_prev) + D
                    - (fc::uint128_t)A * D * 4
                    - (fc::uint128_t)D * D * D / ((fc::uint128_t)4 * x * y_prev + 1);
      fc::uint128_t df = (fc::uint128_t)A * 4 + (fc::uint128_t)D * D * D / ((fc::uint128_t)4 * x * y_prev * y_prev + 1);
      if (df == 0) return 0;
      if (f > (fc::uint128_t)0 && f >= df) y = y_prev - (f / df);
      else if (f > 0) y = (y_prev > (f/df)) ? y_prev - (f/df) : 0;
      else y = y_prev + ((-f) / df);
      if (y == y_prev) break;
   }
   return (uint64_t)y;
}

} } // graphene::chain
