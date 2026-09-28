/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#pragma once

#include <graphene/protocol/base.hpp>
#include <graphene/protocol/oracle.hpp>

namespace graphene { namespace protocol {

   /// Consumer-fee routing proposals (BSIP-1 section 7b): 50% oracle / 30%
   /// vault / 20% reserve. The oracle leg funds the per-oracle reward pool;
   /// the vault and reserve legs are accounting rules for the issuance
   /// engine, which reads them from the pool object it settles through.
   constexpr uint16_t GRAPHENE_H2E_REWARD_ORACLE_BPS  = 5000;
   constexpr uint16_t GRAPHENE_H2E_REWARD_VAULT_BPS   = 3000;
   constexpr uint16_t GRAPHENE_H2E_REWARD_RESERVE_BPS = 2000;
   /// Joint fee-diversion cap proposal: the oracle-rewards program and the
   /// stealth parity pool share one denominator and must not starve each
   /// other (inventory section 2.3).
   constexpr uint16_t GRAPHENE_H2E_FEE_DIVERSION_CAP_BPS = 7000;

   /// Promotion rate-limit proposal: promotions (consumed-value advances) per
   /// oracle per maintenance interval. Past this count the H2 read path holds
   /// fail-closed until the next window. Sized above honest pilot publishing
   /// (manual producers, minute-scale cadence) and below flood rates.
   constexpr uint32_t GRAPHENE_H2E_PROMOTION_LIMIT_PER_INTERVAL = 512;

   /// Tripwire deviation threshold proposal: market-vs-feed past 5% breaches
   /// (same basis as the Track A guard band GRAPHENE_ORACLE_GUARD_MAX_MOVE_PPM).
   constexpr uint32_t GRAPHENE_H2E_TRIPWIRE_DEVIATION_PPM = 50000;
   /// Minimum-depth qualifier proposal: a tripwire window counts only with at
   /// least 1e8 bond-asset smallest units of sampled volume (10,000 BTS at
   /// precision 5, ~$10 at the pilot basis: dust-resistant, book-trivial).
   constexpr uint64_t GRAPHENE_H2E_TRIPWIRE_MIN_DEPTH_RAW = 100000000ULL;
   /// State bound: samples per tripwire window (FIFO ring, oldest evicted).
   constexpr uint32_t GRAPHENE_H2E_TRIPWIRE_MAX_SAMPLES = 64;
   /// Halt ladder stages: protocol door first, debt second, redemptions last.
   constexpr uint8_t GRAPHENE_H2E_TRIPWIRE_STAGE_NONE        = 0;
   constexpr uint8_t GRAPHENE_H2E_TRIPWIRE_STAGE_DOOR        = 1;
   constexpr uint8_t GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT        = 2;
   constexpr uint8_t GRAPHENE_H2E_TRIPWIRE_STAGE_REDEMPTIONS = 3;
   /// Reopen rule: this many consecutive clean evaluations clear the halt.
   constexpr uint8_t GRAPHENE_H2E_TRIPWIRE_REOPEN_WINDOWS = 2;

   /// Recovery trigger proposal: system collateral below 150% suspends new
   /// debt (inventory section 3.4, BSIP-1 section 3).
   constexpr uint32_t GRAPHENE_H2E_RECOVERY_TRIGGER_BPS = 15000;

   /// @return whether a routing triple is consensus-legal: sums to 10000 bps
   /// with the oracle share inside the joint diversion cap.
   inline bool h2_routing_valid( uint16_t oracle_bps, uint16_t vault_bps,
                                 uint16_t reserve_bps, uint16_t cap_bps )
   {
      const uint32_t sum = uint32_t( oracle_bps ) + uint32_t( vault_bps )
                         + uint32_t( reserve_bps );
      return sum == 10000 && oracle_bps <= cap_bps;
   }

   /**
    * OSM bucket anchor: the absolute-grid bucket containing second @p t under
    * delay @p delay_sec. Buckets are delay/16 wide (the guard-queue divisor),
    * minimum 1 second. Anchoring to the epoch grid -- never to the first
    * sample or the maintenance interval -- is the H2 hardening: interval
    * changes cannot shift promotion provenance.
    */
   inline uint32_t h2_osm_bucket_anchor( uint32_t t, uint32_t delay_sec )
   {
      const uint32_t bucket = std::max<uint32_t>(
            1, delay_sec / uint32_t( GRAPHENE_ORACLE_GUARD_MAX_PENDING ) );
      return ( t / bucket ) * bucket;
   }

   /**
    * Exact deviation predicate: does |market/feed - 1| exceed @p threshold_ppm?
    * Both legs are ratios, so this is 256-bit cross-multiplication, no floats,
    * no division, no rounding: two nodes cannot disagree. Equality with the
    * bound is NOT a breach (the bound is inclusive headroom).
    */
   bool h2_deviation_breaches( const oracle_value& market, const oracle_value& feed,
                               uint32_t threshold_ppm );

   /**
    * Pro-rata share with declared rounding DOWN against the payee:
    * pool * weight / total_weight, truncating. Zero total weight pays zero
    * (no division by zero, no NaN: an empty live set simply accrues).
    */
   share_type h2_pro_rata( share_type pool, uint64_t weight, uint64_t total_weight );

   /**
    * Face-to-bond conversion with declared truncation: face * price.base /
    * price.quote. Used for the USD-terms wind-down leg (face in pair units,
    * price read as bond-per-pair by binding convention).
    */
   share_type h2_convert_face_to_bond( share_type face, const oracle_value& price );

   /**
    * One tripwire market observation: the pool-side execution ratio of a
    * direct pair<->core pool leg, read as (bond_units, pair_units) to match
    * the binding convention, with the bond-side volume as its weight and the
    * contributing pool disclosed on-chain (publishers-disclose-sources rule).
    */
   struct h2_tripwire_sample
   {
      oracle_value            price;       ///< (bond_units, pair_units), both > 0
      uint64_t                volume = 0;  ///< bond-side execution volume, > 0
      liquidity_pool_id_type  source_pool; ///< disclosing pool, immutable

      void validate()const;
   };

   bool operator==( const h2_tripwire_sample& a, const h2_tripwire_sample& b );
   inline bool operator!=( const h2_tripwire_sample& a, const h2_tripwire_sample& b )
   { return !( a == b ); }

   /**
    * Volume-weighted median SELECTION over @p samples (consensus law:
    * select-don't-compute). Sorts by price via exact 128-bit cross-products
    * with total tie-breaks (quote, base, volume, pool id: integer fields, so
    * the order is total and deterministic), then returns the first sample
    * whose cumulative weight strictly exceeds half the total -- the same
    * upper-median rule as the H1 weighted median, so single-sample windows
    * return their sample. Empty input returns an empty optional (caller
    * fails closed); it never invents a price.
    */
   optional<h2_tripwire_sample> h2_volume_weighted_median(
         const vector<h2_tripwire_sample>& samples );

   /**
    * @brief Names the single backup series consumed when the primary is stale.
    * @ingroup operations
    *
    * Set and cleared by the oracle's owner (never by producers: policy, not
    * price). Depth is exactly one: the read path falls from the primary to
    * this backup and then halts on dual-stale -- chains are refused
    * structurally (no recursion in the reader) and self-reference is refused
    * in validate. Clearing (empty fallback) returns the oracle to halt-on-
    * primary-stale.
    */
   struct oracle_fallback_set_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset                   fee;
      account_id_type         owner;   ///< Must own the oracle; pays the fee
      oracle_id_type          oracle;  ///< Primary whose backup is (un)set
      optional<price_oracle>  fallback;///< Backup (oracle, series); empty clears
      extensions_type         extensions; ///< Appended-last rule

      account_id_type fee_payer()const { return owner; }
      void            validate()const;
   };

} } // graphene::protocol

FC_REFLECT( graphene::protocol::h2_tripwire_sample,
            (price)(volume)(source_pool) )

FC_REFLECT( graphene::protocol::oracle_fallback_set_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::oracle_fallback_set_operation,
            (fee)(owner)(oracle)(fallback)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::h2_tripwire_sample )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_fallback_set_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_fallback_set_operation )
