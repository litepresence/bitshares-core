// SPDX-License-Identifier: MIT
#pragma once

#include <graphene/chain/types.hpp>
#include <graphene/db/generic_index.hpp>

#include <graphene/protocol/asset.hpp>

#include <boost/multi_index/composite_key.hpp>

namespace graphene { namespace chain {

using namespace graphene::db;

constexpr uint64_t FOUNDER_ROYALTY = 250;
constexpr uint64_t PROMOTER_ROYALTY = 250;

class reciprocity_pool_object : public abstract_object<reciprocity_pool_object, protocol_ids, reciprocity_pool_object_type>
{
   public:
      // Core pool state (parallel vectors, n <= 8)
      vector<asset_id_type>   tokens;              ///< Pool token IDs (sorted)
      vector<share_type>      balances;            ///< Current balances per token
      vector<share_type>      genesis;             ///< Initial (genesis) balances per token
      vector<uint64_t>        weights;             ///< Pool weights (GCD-normalized)
      uint64_t                sum_weights = 0;     ///< Cached sum of weights
      uint64_t                factors = 0;         ///< Number of tokens in pool

      // Invariant state
      fc::uint128_t           scale = 0;           ///< Dynamic scale for K computation
      share_type              supply = 0;          ///< Total LP share count
      uint64_t                transactions = 0;    ///< Swap counter
      bool                    initialized = false; ///< Pool has been initialized (never reset on drain)

      // LP token
      asset_id_type           lp_token;            ///< LP token asset

      // Spread governor state (dual EMA+ATR)
      uint64_t                atr_spread_target = 0;  ///< ATR spread target in BASIS
      uint64_t                ema_spread_target = 0;  ///< EMA spread target in BASIS
      uint64_t                atr_period = 0;         ///< ATR period
      uint64_t                ema_period = 0;         ///< EMA period
      uint64_t                atr_spread = 0;         ///< Current ATR spread
      int64_t                 atr_spread_rem = 0;     ///< ATR fractional carry
      int64_t                 spread_additive = 0;    ///< Spread additive governor
      uint64_t                spread_multiplier = 0;  ///< Current spread multiplier (BASIS = 1.0)
      uint64_t                avg_spread = 0;         ///< EMA of recent spreads
      int64_t                 avg_spread_rem = 0;     ///< EMA fractional carry
      uint64_t                spread_count = 0;       ///< Number of spread observations
      uint64_t                last_spread = 0;        ///< Last observed spread from aequitas
        uint64_t                duty = 0;               ///< Post-governor pre-warmup aequitas spread; last_spread is post-warmup — differs when warmup overrides spread

      // LP royalty accumulator (per token)
      vector<share_type>      lp_royalties;           ///< LP royalty accumulator per token

      // Fee accumulators (per token)
      vector<share_type>      founder_fees;      ///< Accumulated founder fees per token
      vector<share_type>      promoter_fees;       ///< Accumulated promoter fees per token

      // TVWAP oracle — 3 precomputed windows (15m, 1hr, 24hr)
      uint64_t                last_timestamp = 0;  ///< Block timestamp of last operation
      fc::uint128_t           acc_k_15m = 0;       ///< Cumulative K × seconds for 15m window
      fc::uint128_t           acc_w_15m = 0;       ///< Cumulative Σw × seconds for 15m window
      fc::uint128_t           tvwap_15m = 0;       ///< Precomputed TVWAP K for 15m window
      uint64_t                window_start_15m = 0;///< Start timestamp for 15m window
      fc::uint128_t           acc_k_1hr = 0;       ///< Cumulative K × seconds for 1hr window
      fc::uint128_t           acc_w_1hr = 0;       ///< Cumulative Σw × seconds for 1hr window
      fc::uint128_t           tvwap_1hr = 0;       ///< Precomputed TVWAP K for 1hr window
      uint64_t                window_start_1hr = 0;///< Start timestamp for 1hr window
      fc::uint128_t           acc_k_24hr = 0;      ///< Cumulative K × seconds for 24hr window
      fc::uint128_t           acc_w_24hr = 0;      ///< Cumulative Σw × seconds for 24hr window
      fc::uint128_t           tvwap_24hr = 0;      ///< Precomputed TVWAP K for 24hr window
      uint64_t                window_start_24hr = 0;///< Start timestamp for 24hr window

      // Factory reference
      reciprocity_factory_id_type factory;         ///< Immutable factory reference
};

struct by_reciprocity_lp_token;
struct by_reciprocity_tokens;

typedef multi_index_container<
   reciprocity_pool_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_reciprocity_lp_token>,
                      member< reciprocity_pool_object, asset_id_type, &reciprocity_pool_object::lp_token > >,
      ordered_unique< tag<by_reciprocity_tokens>,
         composite_key< reciprocity_pool_object,
            member< reciprocity_pool_object, vector<asset_id_type>, &reciprocity_pool_object::tokens >,
            member< object, object_id_type, &object::id>
         >
      >
   >
 > reciprocity_pool_multi_index_type;

typedef generic_index<reciprocity_pool_object, reciprocity_pool_multi_index_type> reciprocity_pool_index;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::reciprocity_pool_object )

FC_REFLECT_DERIVED( graphene::chain::reciprocity_pool_object, (graphene::db::object),
                    (tokens)
                    (balances)
                    (genesis)
                    (weights)
                    (sum_weights)
                    (factors)
                    (scale)
                    (supply)
                    (transactions)
                    (initialized)
                    (lp_token)
                    (atr_spread_target)
                    (ema_spread_target)
                    (atr_period)
                    (ema_period)
                    (atr_spread)
                    (atr_spread_rem)
                    (spread_additive)
                    (spread_multiplier)
                    (avg_spread)
                    (avg_spread_rem)
                    (spread_count)
                    (last_spread)
                    (duty)
                    (founder_fees)
                    (promoter_fees)
                    (lp_royalties)
                    (last_timestamp)
                    (acc_k_15m)
                    (acc_w_15m)
                    (tvwap_15m)
                    (window_start_15m)
                    (acc_k_1hr)
                    (acc_w_1hr)
                    (tvwap_1hr)
                    (window_start_1hr)
                    (acc_k_24hr)
                    (acc_w_24hr)
                    (tvwap_24hr)
                    (window_start_24hr)
                    (factory)
                  )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::reciprocity_pool_object )
