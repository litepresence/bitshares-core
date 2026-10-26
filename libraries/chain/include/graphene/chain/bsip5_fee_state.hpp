#pragma once
#include <graphene/chain/types.hpp>
#include <graphene/protocol/asset.hpp>

namespace graphene { namespace chain {

/// Prism TSP constants (adapted to 3-second BitShares blocks).
/// MIN_T: ~5 minutes = 100 blocks at 3s.
/// MAX_T: ~1 hour = 1200 blocks at 3s.
/// PROXIMITY_THRESHOLD: 0.9 WAD.
constexpr uint64_t BSIP5_MIN_T_BLOCKS = 100;
constexpr uint64_t BSIP5_MAX_T_BLOCKS = 1200;
constexpr uint64_t BSIP5_PROXIMITY_THRESHOLD_WAD = 900000000000000000ULL; // 0.9 * 1e18
constexpr uint64_t BSIP5_WAD = 1000000000000000000ULL;
constexpr uint64_t BSIP5_MAX_PAYOUT_ORDERS = 256;

/// Time component: capped at MAX_T, excluded below MIN_T.
inline uint64_t bsip5_time_component(uint64_t placement_block, uint64_t payout_block) {
   if (payout_block <= placement_block) return 0;
   uint64_t raw = payout_block - placement_block;
   if (raw < BSIP5_MIN_T_BLOCKS) return 0;
   return (raw > BSIP5_MAX_T_BLOCKS) ? BSIP5_MAX_T_BLOCKS : raw;
}

/// Proximity: P = min(price,oracle)/max(price,oracle) in WAD.
/// Pk = 10*P - 9*WAD. Returns 0 if P < threshold.
inline uint64_t bsip5_proximity_weight(uint64_t price_wad, uint64_t oracle_wad) {
   if (price_wad == 0 || oracle_wad == 0) return 0;
   uint64_t lo = (price_wad < oracle_wad) ? price_wad : oracle_wad;
   uint64_t hi = (price_wad < oracle_wad) ? oracle_wad : price_wad;
   // P = lo/hi in WAD
   __uint128_t p = (__uint128_t)lo * BSIP5_WAD / hi;
   if (p < BSIP5_PROXIMITY_THRESHOLD_WAD) return 0;
   // Pk = 10*P - 9*WAD
   __uint128_t pk = 10 * p - 9 * BSIP5_WAD;
   if (pk > BSIP5_WAD) pk = BSIP5_WAD;
   return (uint64_t)pk;
}

/// TSP = S * T * Pk / WAD
inline __uint128_t bsip5_tsp(uint64_t size, uint64_t t, uint64_t pk) {
   return (__uint128_t)size * t * pk / BSIP5_WAD;
}

} } // graphene::chain
