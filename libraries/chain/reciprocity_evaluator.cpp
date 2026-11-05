// SPDX-License-Identifier: MIT
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/reciprocity_pool_object.hpp>
#include <graphene/chain/reciprocity_factory_object.hpp>

#include <graphene/chain/reciprocity_evaluator.hpp>

#include <graphene/chain/database.hpp>
#include <graphene/chain/exceptions.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/is_authorized_asset.hpp>

#include <graphene/protocol/reciprocity_operations.hpp>

#include <cmath>

namespace graphene { namespace chain {

// ==========================================================================
//  Math Helpers — matching liquidity_pool_evaluator.cpp
// ==========================================================================

using uint128_t = fc::uint128_t;
using int128_t = fc::int128_t;

// Out-of-line definitions of the P4-02 consensus bounds (static constexpr
// members are odr-used by the FC_ASSERT comparisons in this evaluator).
constexpr uint64_t reciprocity_factory_object::MAX_POOLS;
constexpr uint64_t reciprocity_factory_object::MAX_POOLS_PER_ACCOUNT;
constexpr uint64_t reciprocity_factory_object::MAX_KNOWN_TOKENS;

static uint128_t r_safe_mul( uint128_t a, uint128_t b )
{
   if( a == 0 || b == 0 ) return 0;
   uint128_t c = a * b;
   FC_ASSERT( c / a == b, "Overflow in safe_mul" );
   return c;
}

static uint128_t r_safe_div( uint128_t a, uint128_t b )
{
   FC_ASSERT( b != 0, "Division by zero" );
   return a / b;
}

static uint128_t r_safe_add( uint128_t a, uint128_t b )
{
   uint128_t c = a + b;
   FC_ASSERT( c >= a, "Overflow in safe_add" );
   return c;
}

static uint64_t r_gcd(uint64_t a, uint64_t b) {
    while (b != 0) { uint64_t t = b; b = a % b; a = t; }
    return a;
}

static std::pair<vector<uint64_t>, uint64_t> r_normalize_weights(const vector<uint64_t>& raw) {
    // ponytail: caller validates non-empty + non-zero weights, but guard for safety
    if (raw.empty()) return {{}, 0};
    uint64_t g = raw[0];
    for (size_t i = 1; i < raw.size(); i++) g = r_gcd(g, raw[i]);
    if (g == 0) g = 1;
    vector<uint64_t> norm; uint64_t sum = 0;
    for (auto w : raw) { norm.push_back(w / g); sum += w / g; }
    return {norm, sum};
}

static uint128_t r_sqrt_fixed( uint128_t value )
{
   if( value == 0 ) return 0;
   uint128_t target = value * RECIPROCITY_BASIS;
   if( target == 0 ) return 0;
   uint128_t g = target;
   for( int iter = 0; iter < 50; iter++ ) {
      uint128_t ng = ( g + r_safe_div( target, g ) ) / 2;
      if( ng == g ) break;
      g = ng;
   }
   return g;
}

// ---- konstant_weighted_log (weighted invariant via Padé [1/1]) -------------

static uint128_t r_konstant_weighted_log(
    const vector<uint64_t>& bals, const vector<uint64_t>& gens, uint64_t n, uint128_t scale,
    const vector<uint64_t>& weights
) {
    constexpr uint64_t BASIS = RECIPROCITY_BASIS;
    if( n == 0 || bals.empty() || gens.empty() ) return scale;
    bool has_weights = !weights.empty() && weights.size() >= n;
    uint64_t sum_w = 0;
    int128_t sum_ln = 0;
    for (uint64_t i = 0; i < n; i++) {
        if (gens[i] == 0) continue;
        uint128_t r = r_safe_mul(uint128_t(bals[i]), uint128_t(BASIS)) / gens[i];
        // REPAIR-07 (Critical, BSIP4-25-N): a token drained to bals[i]==0 with
        // gens[i]>0 must terminate the konstant (return 0), not vanish from the
        // log average. The r==0 case is kept in the average: r=0 drives ln to
        // -2*BASIS, pulling avg down until pade_num <= 0 and the konstant
        // returns 0 (pool terminated). Skipping it (the old `if (r == 0)
        // continue`) let a drained token disappear from the invariant, enabling
        // drain theft.
        // P4-06 (Important, CODE): overflow guard on the int128 intermediates.
        // Proven bound: bals[i] <= INT64_MAX (~2^63) and BASIS = 10^4, so
        //   r = bals*BASIS/gens <= (2^63-1)*10^4 < 2^77, comfortably inside int128.
        // Each ln term is a Padé[1/1] log approximation: ln ≈ BASIS*2*(x-1)/(x+1)
        // with x = r/BASIS > 0, hence |ln| < 2*BASIS = 20000. With at most
        // MAX_TOKENS (= 8) terms and weights summing to <= RECIPROCITY_MAX_SUM_WEIGHTS
        // (= 100, all positive), |sum_ln| <= 8 * 100 * 20000 = 1.6*10^7, which
        // fits in int128 and even int64. These assertions document the bound;
        // they are enforced by the create/swap/liquidity evaluators upstream.
        FC_ASSERT( r <= (uint128_t(1) << 120), "r exceeds proven int128 bound" );
        int128_t r_i128 = static_cast<int128_t>( r );
        int128_t ln = 2 * (r_i128 - (int128_t)BASIS) * (int128_t)BASIS / ((int128_t)r + (int128_t)BASIS);
        FC_ASSERT( ln >= -int128_t( 2 * BASIS ) && ln <= int128_t( 2 * BASIS ),
                   "ln term outside proven bound [-2*BASIS, 2*BASIS]" );
        if( has_weights && weights[i] > 0 ) {
            int128_t wln = static_cast<int128_t>( weights[i] ) * ln;
            FC_ASSERT( wln >= -(int128_t(1) << 62) && wln <= (int128_t(1) << 62),
                       "weighted ln term exceeds proven bound" );
            sum_ln += wln;
            sum_w += weights[i];
        } else {
            sum_ln += ln;
            sum_w++;
        }
    }
    uint64_t denom = has_weights ? sum_w : n;
    if (denom == 0) return scale;
    int128_t avg128 = sum_ln / (int128_t)denom;
    // |avg| <= 2*BASIS since each |ln| <= 2*BASIS and an average preserves the bound
    FC_ASSERT( avg128 >= -int128_t( 2 * BASIS ) && avg128 <= int128_t( 2 * BASIS ),
               "average ln outside proven bound" );
    int64_t avg = static_cast<int64_t>( avg128 );
    int128_t pade_num = 2 * (int128_t)BASIS + avg;
    int128_t pade_den = 2 * (int128_t)BASIS - avg;
    if (pade_den <= 0) return scale;
    if (pade_num <= 0) return 0;
    return r_safe_mul(scale, uint128_t((uint64_t)pade_num)) / uint128_t((uint64_t)pade_den);
}

uint128_t r_compute_konstant( const vector<share_type>& balances,
                                     const vector<share_type>& genesis,
                                     uint64_t factors,
                                     uint128_t scale,
                                     const vector<uint64_t>& weights )
{
   // P4-06: the former `precision` parameter (fixed-point scale) was unused —
   // the konstant math operates at RECIPROCITY_BASIS precision and the scale is
   // passed in explicitly. Parameter removed; fixed-point precision scaling is
   // reserved for a future, explicitly-versioned change.
   vector<uint64_t> bals( factors ), gens( factors );
   for( uint64_t i = 0; i < factors; i++ ) {
      bals[i] = static_cast<uint64_t>( std::max<int64_t>( 0, balances[i].value ) );
      gens[i] = static_cast<uint64_t>( std::max<int64_t>( 0, genesis[i].value ) );
   }
   return r_konstant_weighted_log( bals, gens, factors, scale, weights );
}

// ---- aequitas --------------------------------------------------------------

static uint64_t r_compute_duty_weighted(
    const vector<uint64_t>& pre, const vector<uint64_t>& post,
    uint64_t pre_k, uint64_t post_k, uint64_t n,
    const vector<uint64_t>& weights,
    uint64_t sum_weights = 0
) {
    constexpr uint64_t BASIS = RECIPROCITY_BASIS;
    if( n == 0 || pre.empty() || post.empty() ) return 0;
    bool has_weights = !weights.empty() && weights.size() >= n;
    uint64_t sum_w = has_weights ? sum_weights : 0;
    bool use_pre = pre_k <= post_k;
    vector<uint64_t> ratios(n, 0);
    for (uint64_t i = 0; i < n; i++) {
        uint64_t s = use_pre ? pre[i] : post[i];
        uint64_t l = use_pre ? post[i] : pre[i];
        if (l > 0) ratios[i] = (uint64_t)(r_safe_mul(uint128_t(s), uint128_t(BASIS)) / l);
    }
    uint64_t sum_total = 0;
    for (uint64_t i = 0; i < n; i++) {
        uint64_t diff = 0;
        for (uint64_t j = 0; j < n; j++) {
            uint64_t abs_dev = ratios[i] > ratios[j] ? ratios[i] - ratios[j] : ratios[j] - ratios[i];
            if( has_weights )
                diff += abs_dev * weights[j];
            else
                diff += abs_dev;
        }
        sum_total += diff;
    }
    uint64_t denom = (sum_w > 0 ? sum_w * n * n : n * n);
    uint64_t avg_err = denom > 0 ? sum_total / denom : 0;
    uint64_t deviation = avg_err > BASIS ? 0 : BASIS - avg_err;
    return 1 + BASIS - (deviation * deviation / BASIS);
}

static uint128_t r_compute_aequitas( const vector<share_type>& pre,
                                     const vector<share_type>& post,
                                     uint128_t pre_k,
                                     uint128_t post_k,
                                     uint64_t factors,
                                     uint64_t spread_multiplier,
                                     int64_t spread_additive,
                                     const vector<uint64_t>& weights = {},
                                     uint64_t sum_weights = 0 )
{
   constexpr uint64_t BASIS = RECIPROCITY_BASIS;
   if( factors == 0 ) return 0;
   vector<uint64_t> pre_u64( factors ), post_u64( factors );
   for( uint64_t i = 0; i < factors; i++ ) {
      pre_u64[i] = static_cast<uint64_t>( std::max<int64_t>( 0, pre[i].value ) );
      post_u64[i] = static_cast<uint64_t>( std::max<int64_t>( 0, post[i].value ) );
   }
   uint128_t raw = uint128_t( r_compute_duty_weighted( pre_u64, post_u64,
             static_cast<uint64_t>( pre_k ), static_cast<uint64_t>( post_k ),
             factors, weights, sum_weights ) );
   int128_t governed = int128_t( r_safe_mul( raw, uint128_t( spread_multiplier ) ) / BASIS );
   governed += int128_t( spread_additive );
   if( governed < 1 ) governed = 1;
   return uint128_t( governed );
}

// ---- compute_fees (spread-based) -------------------------------------------

static vector<share_type> r_compute_fees( const vector<share_type>& amounts_out,
                                          uint64_t spread,
                                          uint64_t factors )
{
   constexpr uint64_t BASIS = RECIPROCITY_BASIS;
   vector<share_type> fees( factors, share_type( 0 ) );
   for( uint64_t i = 0; i < factors; i++ ) {
      if( amounts_out[i] == 0 ) continue;
      if( amounts_out[i].value <= 3 ) {
         fees[i] = amounts_out[i];
      } else {
         uint128_t raw = r_safe_mul( uint128_t( amounts_out[i].value ), uint128_t( spread ) );
         uint128_t fee = ( raw + BASIS - 1 ) / BASIS; // ceil
         if( fee > uint128_t( amounts_out[i].value ) )
            fee = uint128_t( amounts_out[i].value );
         if( fee < 3 ) fee = 3;
         fees[i] = share_type( static_cast<int64_t>( fee ) );
      }
   }
   return fees;
}

// ---- compute_scale ---------------------------------------------------------

static uint128_t r_compute_scale( const vector<share_type>& balances )
{
   int64_t max_bal = 0;
   for( const auto& b : balances )
      if( b.value > max_bal ) max_bal = b.value;
   if( max_bal == 0 ) return 0;
   // Replace std::log10 with integer digit-count (no libm; deterministic across platforms).
   // Count decimal digits by repeated division by 10.
   int d = 0;
   int64_t v = std::max<int64_t>( 1, max_bal );
   while( v > 0 ) { v /= 10; d++; }
   uint128_t s = 1;
    constexpr int SCALE_BUFFER = 4;
   for( int i = 0; i < d + SCALE_BUFFER; i++ )
      s = r_safe_mul( s, 10 );
   return s;
}

// ---- royalty_split ---------------------------------------------------------

static void r_royalty_split( uint128_t raw_fee, uint64_t founder_royalty, uint64_t promoter_royalty,
                              uint128_t& founder_share, uint128_t& promoter_share, uint128_t& lp_share )
{
   constexpr uint128_t BASIS = RECIPROCITY_BASIS;
   uint128_t fg = 0, pg = 0, lg = 0;
   if( raw_fee >= 3 ) { fg = 1; pg = 1; lg = 1; }
   else if( raw_fee >= 2 ) { fg = 1; pg = 1; }
   else if( raw_fee >= 1 ) { fg = 1; }
   uint128_t remaining = raw_fee - fg - pg - lg;
   uint128_t fe = r_safe_mul( remaining, uint128_t( founder_royalty ) ) / BASIS;
   uint128_t pe = r_safe_mul( remaining, uint128_t( promoter_royalty ) ) / BASIS;
   founder_share = fg + fe;
   promoter_share = pg + pe;
   lp_share = lg + remaining - fe - pe;
}

// ---- spread_governor (dual EMA+ATR with fractional carry) -------------------

static void r_spread_governor( reciprocity_pool_object& rpo, uint64_t spread )
{
   constexpr uint64_t BASIS = RECIPROCITY_BASIS;
   rpo.spread_count++;
   uint64_t ema_alpha = 2 * BASIS / ( rpo.ema_period + 1 );
   uint64_t atr_alpha = 2 * BASIS / ( rpo.atr_period + 1 );
   if( rpo.spread_count <= 2 ) {
      rpo.avg_spread = spread;
   } else {
      // avg_spread EMA with fractional carry
      uint128_t numer = r_safe_mul( uint128_t( spread ), uint128_t( ema_alpha ) )
                      + r_safe_mul( uint128_t( rpo.avg_spread ), uint128_t( BASIS - ema_alpha ) );
      rpo.avg_spread = static_cast<uint64_t>( numer / BASIS );
      rpo.avg_spread_rem += static_cast<int64_t>( numer % BASIS );
      if( rpo.avg_spread_rem >= int64_t( BASIS ) ) {
         rpo.avg_spread += 1;
         rpo.avg_spread_rem -= BASIS;
      } else if( rpo.avg_spread_rem <= -int64_t( BASIS ) && rpo.avg_spread > 0 ) {
         rpo.avg_spread -= 1;
         rpo.avg_spread_rem += BASIS;
      }

      // ATR: EMA of |spread - last_spread|
      int64_t spread_tr = int64_t( spread ) - int64_t( rpo.last_spread );
      if( spread_tr < 0 ) spread_tr = -spread_tr;
      int64_t delta_s = ( int64_t( spread_tr ) - int64_t( rpo.atr_spread ) ) * int64_t( atr_alpha );
      {  int64_t atr_delta = delta_s / int64_t( BASIS );
         if( atr_delta >= 0 ) {
            rpo.atr_spread += static_cast<uint64_t>( atr_delta );
         } else {
            uint64_t abs_delta = static_cast<uint64_t>( -atr_delta );
            if( abs_delta >= rpo.atr_spread ) {
               rpo.atr_spread = 1;
            } else {
               rpo.atr_spread -= abs_delta;
            }
         }
      }
      rpo.atr_spread_rem += delta_s % int64_t( BASIS );
      if( rpo.atr_spread_rem >= int64_t( BASIS ) ) {
         rpo.atr_spread += 1;
         rpo.atr_spread_rem -= BASIS;
      } else if( rpo.atr_spread_rem <= -int64_t( BASIS ) && rpo.atr_spread > 0 ) {
         rpo.atr_spread -= 1;
         rpo.atr_spread_rem += BASIS;
      }
      if( rpo.atr_spread < 1 ) rpo.atr_spread = 1;
   }

   if( rpo.spread_count > 1 ) {
      // ATR → multiplier (wide/narrow negative feedback)
      if( rpo.atr_spread > rpo.atr_spread_target ) {
         rpo.spread_multiplier = static_cast<uint64_t>(
            r_safe_mul( uint128_t( rpo.spread_multiplier ),
                        uint128_t( BASIS - RECIPROCITY_SPREAD_STEP ) ) / BASIS );
      } else if( rpo.atr_spread < rpo.atr_spread_target ) {
         rpo.spread_multiplier = static_cast<uint64_t>(
            r_safe_mul( uint128_t( rpo.spread_multiplier ),
                        uint128_t( BASIS + RECIPROCITY_SPREAD_STEP ) ) / BASIS );
      }

      // EMA avg_spread → additive (up/down)
      // ponytail: spread_additive is int64_t with no hard bound — grows at ±1/trade.
      // Reaching ±2^63 requires ~10^18 trades at 1 block each (practically unreachable).
      // Clamp to ±100 bps to match cross-port MAX_SPREAD_TARGET.
      if( rpo.avg_spread > rpo.ema_spread_target ) {
         rpo.spread_additive -= 1;
      } else if( rpo.avg_spread < rpo.ema_spread_target ) {
         rpo.spread_additive += 1;
      }
      if( rpo.spread_additive > 100 )  rpo.spread_additive = 100;
      if( rpo.spread_additive < -100 ) rpo.spread_additive = -100;
      // Clamp spread_multiplier to prevent extreme drift
      if( rpo.spread_multiplier < 1000 )  rpo.spread_multiplier = 1000;
      if( rpo.spread_multiplier > 100000 ) rpo.spread_multiplier = 100000;
   }
}

// ---- TVWAP oracle helpers --------------------------------------------------

static void r_reset_tvwap_state( reciprocity_pool_object& rpo )
{
   rpo.last_timestamp = 0;
   rpo.acc_k_15m = 0; rpo.acc_w_15m = 0; rpo.tvwap_15m = 0; rpo.window_start_15m = 0;
   rpo.acc_k_1hr = 0; rpo.acc_w_1hr = 0; rpo.tvwap_1hr = 0; rpo.window_start_1hr = 0;
   rpo.acc_k_24hr = 0; rpo.acc_w_24hr = 0; rpo.tvwap_24hr = 0; rpo.window_start_24hr = 0;
}

static void r_update_tvwap( reciprocity_pool_object& rpo,
                            uint128_t pre_k,
                            uint128_t post_k_stake,
                            uint64_t now )
{
   constexpr uint128_t BASIS = RECIPROCITY_BASIS;
   constexpr uint64_t TVWAP_15M = 900;
   constexpr uint64_t TVWAP_1HR = 3600;
   constexpr uint64_t TVWAP_24HR = 86400;

   uint64_t dt = now > rpo.last_timestamp ? (now - rpo.last_timestamp) : 0;
   // ponytail: 30-day dt cap prevents accumulator overflow after long idle periods;
   // remove if per-operation overflow bound analysis permits unbounded dt
   if( dt > TVWAP_24HR ) dt = TVWAP_24HR;
   if( dt == 0 ) return;
   if( pre_k == 0 ) { rpo.last_timestamp = now; return; }

   uint128_t delta;
   if( post_k_stake > pre_k ) delta = post_k_stake - pre_k;
   else delta = pre_k - post_k_stake;

   if( delta == 0 ) { rpo.last_timestamp = now; return; }

   uint128_t product = r_safe_mul( r_safe_mul( delta, BASIS ), uint128_t( dt ) );

   // Window 1: 15m
    if( now >= rpo.window_start_15m && now - rpo.window_start_15m >= TVWAP_15M ) {
       rpo.acc_k_15m = 0; rpo.acc_w_15m = 0; rpo.window_start_15m = now;
    }
    rpo.acc_k_15m = r_safe_add( rpo.acc_k_15m, product );
    rpo.acc_w_15m = r_safe_add( rpo.acc_w_15m, r_safe_div( product, pre_k ) );
    if( rpo.acc_w_15m > 0 ) rpo.tvwap_15m = rpo.acc_k_15m / rpo.acc_w_15m;

    // Window 2: 1hr
    if( now >= rpo.window_start_1hr && now - rpo.window_start_1hr >= TVWAP_1HR ) {
       rpo.acc_k_1hr = 0; rpo.acc_w_1hr = 0; rpo.window_start_1hr = now;
    }
    rpo.acc_k_1hr = r_safe_add( rpo.acc_k_1hr, product );
    rpo.acc_w_1hr = r_safe_add( rpo.acc_w_1hr, r_safe_div( product, pre_k ) );
    if( rpo.acc_w_1hr > 0 ) rpo.tvwap_1hr = rpo.acc_k_1hr / rpo.acc_w_1hr;

    // Window 3: 24hr
    if( now >= rpo.window_start_24hr && now - rpo.window_start_24hr >= TVWAP_24HR ) {
       rpo.acc_k_24hr = 0; rpo.acc_w_24hr = 0; rpo.window_start_24hr = now;
    }
   rpo.acc_k_24hr = r_safe_add( rpo.acc_k_24hr, product );
   rpo.acc_w_24hr = r_safe_add( rpo.acc_w_24hr, r_safe_div( product, pre_k ) );
   if( rpo.acc_w_24hr > 0 ) rpo.tvwap_24hr = rpo.acc_k_24hr / rpo.acc_w_24hr;

   rpo.last_timestamp = now;
}

// ==========================================================================
//  CREATE EVALUATOR — permissionless, with provenance
// ==========================================================================

void_result reciprocity_pool_create_evaluator::do_evaluate( const reciprocity_pool_create_operation& op )
{ try {
   FC_ASSERT( op.account != account_id_type(), "Invalid account address" );
   const database& d = db();
   // P4-07 (Important, CODE): explicit BSIP-4 hardfork gate in do_evaluate, in
   // addition to the visitor-only gating in hardfork_visitor.hpp (§6). Defense
   // in depth: every BSIP-4 operation refuses to evaluate before the flag has
   // passed, matching the established liquidity-pool pattern.
   // Decision: explicit assert chosen over visitor-only (recorded in the task
   // report and ACTIVATION-CHECKLIST); visitor gating remains as the primary
   // operation-validity gate.
   FC_ASSERT( HARDFORK_BSIP4_PASSED(d.head_block_time()),
              "Not allowed until the BSIP-4 hardfork" );

   // Validate asset count
   FC_ASSERT( op.assets.size() >= 2 && op.assets.size() <= MAX_TOKENS,
               "Pool must have 2..${max} assets", ("max", MAX_TOKENS) );

   // Validate all assets exist and are sorted/unique
   for( uint64_t i = 0; i < op.assets.size(); i++ ) {
      op.assets[i](d);
      if( i > 0 )
          FC_ASSERT( op.assets[i-1] < op.assets[i], "Assets must be sorted and unique" );
   }

   // Validate share asset
   _share_asset = &op.share_asset(d);
   FC_ASSERT( _share_asset->issuer == op.account,
              "Only the asset owner can set an asset as the share asset" );
   FC_ASSERT( !_share_asset->is_market_issued(),
              "Can not use a market-issued asset as the share asset" );
   FC_ASSERT( !_share_asset->is_liquidity_pool_share_asset(),
              "The share asset is already bound to another liquidity pool" );
   FC_ASSERT( !_share_asset->for_reciprocity_pool.valid(),
              "The share asset is already bound to another reciprocity pool" );
   FC_ASSERT( _share_asset->dynamic_data(d).current_supply == 0,
               "Current supply of the share asset must be zero" );

    // Validate factory (singleton)
    const auto& factory_idx = d.get_index_type<reciprocity_factory_index>().indices().get<by_id>();
    FC_ASSERT( !factory_idx.empty(), "No factory exists" );
    _factory = &(*factory_idx.begin());

    // P4-02: enforce pool creation ceiling before any state mutation.
    // Defends against unbounded state bloat and denial of service via
    // unrestricted pool creation.
    // Invariant: factory->pool_count < MAX_POOLS at creation time.
    // Spec: docs/superpowers/specs/2026-10-25-bsip4-n-asset-pools-design.md §8
    FC_ASSERT( _factory->pool_count < reciprocity_factory_object::MAX_POOLS,
               "Pool creation ceiling reached: max ${n} pools",
               ("n", reciprocity_factory_object::MAX_POOLS) );

    // P4-08 (Important, CODE): per-account pool cap, enforced at creation time
    // before any state mutation. Defends against a single account exhausting
    // the global MAX_POOLS ceiling and locking every other account out of
    // pool creation (the unbounded-state lesson from BSIP-3, applied per
    // creator).
    // Invariant: factories->pools_by_creator[op.account] < MAX_POOLS_PER_ACCOUNT
    // at creation time.
    // Spec: docs/superpowers/specs/2026-10-25-bsip4-n-asset-pools-design.md §8
    auto creator_itr = _factory->pools_by_creator.find( op.account );
    uint64_t creator_pools = ( creator_itr != _factory->pools_by_creator.end() )
                             ? creator_itr->second
                             : 0;
    FC_ASSERT( creator_pools < reciprocity_factory_object::MAX_POOLS_PER_ACCOUNT,
               "Per-account pool cap reached: max ${n} pools per account",
               ("n", reciprocity_factory_object::MAX_POOLS_PER_ACCOUNT) );

    // Validate weights
   FC_ASSERT( op.weights.size() > 0, "Weights must not be empty" );
   for( const auto& w : op.weights )
      FC_ASSERT( w > 0, "Individual weight must be positive" );
   FC_ASSERT( op.weights.size() == op.assets.size(), "Weights count must match assets count" );
   auto norm = r_normalize_weights( op.weights );
   FC_ASSERT( norm.second <= RECIPROCITY_MAX_SUM_WEIGHTS, "Sum of weights exceeds MAX_SUM_WEIGHTS" );

   // Provenance: validate genesis or known token
   if( _factory->pool_count == 0 ) {
      // First pool: must use the factory's configured genesis tokens
      vector<asset_id_type> genesis = {
          _factory->genesis_1,
          _factory->genesis_2,
          _factory->genesis_3
      };
      std::sort( genesis.begin(), genesis.end() );
      FC_ASSERT( op.assets.size() == genesis.size(),
                 "First pool must have exactly ${n} assets", ("n", genesis.size()) );
      for( uint64_t i = 0; i < genesis.size(); i++ )
      FC_ASSERT( op.assets[i] == genesis[i],
                 "First pool assets must match the factory genesis tokens" );
   } else {
      // Subsequent pools: must share >=1 known token
      bool has_known = false;
      for( const auto& asset_id : op.assets ) {
         if( std::find( _factory->known_tokens.begin(), _factory->known_tokens.end(), asset_id )
             != _factory->known_tokens.end() ) {
            has_known = true;
            break;
         }
      }
      FC_ASSERT( has_known, "Pool must share at least 1 known token with existing pools" );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

generic_operation_result reciprocity_pool_create_evaluator::do_apply( const reciprocity_pool_create_operation& op )
{ try {
   FC_ASSERT( RECIPROCITY_ATR_SPREAD_TARGET > 0 && RECIPROCITY_ATR_SPREAD_TARGET <= RECIPROCITY_BASIS,
              "ATR spread target out of range" );
   FC_ASSERT( RECIPROCITY_EMA_SPREAD_TARGET > 0 && RECIPROCITY_EMA_SPREAD_TARGET <= RECIPROCITY_BASIS,
              "EMA spread target out of range" );
   FC_ASSERT( RECIPROCITY_ATR_PERIOD > 0, "Invalid ATR period" );
   FC_ASSERT( RECIPROCITY_EMA_PERIOD > 0, "Invalid EMA period" );
   database& d = db();
   generic_operation_result result;

   uint64_t n = op.assets.size();
   auto norm = r_normalize_weights( op.weights );

   const auto& new_pool = d.create<reciprocity_pool_object>( [&]( reciprocity_pool_object& obj ){
       obj.tokens = op.assets;
       obj.balances.resize( n, share_type( 0 ) );
       obj.genesis.resize( n, share_type( 0 ) );
       obj.weights = norm.first;
       obj.sum_weights = norm.second;
       obj.factors = n;
       obj.lp_token = op.share_asset;
        obj.atr_spread_target = RECIPROCITY_ATR_SPREAD_TARGET;
        obj.ema_spread_target = RECIPROCITY_EMA_SPREAD_TARGET;
        obj.atr_period = RECIPROCITY_ATR_PERIOD;
        obj.ema_period = RECIPROCITY_EMA_PERIOD;
        obj.atr_spread = RECIPROCITY_ATR_SPREAD_TARGET;
        obj.atr_spread_rem = 0;
        obj.spread_additive = 0;
        obj.spread_multiplier = RECIPROCITY_BASIS;
         obj.avg_spread = RECIPROCITY_EMA_SPREAD_TARGET;
         obj.avg_spread_rem = 0;
         obj.spread_count = 1;
         obj.last_spread = 0;
      obj.duty = 0;
      obj.founder_fees.resize( n, share_type( 0 ) );
      obj.promoter_fees.resize( n, share_type( 0 ) ); // ponytail: no promoter_fund — BitShares uses token issuer as fee recipient
      obj.lp_royalties.resize( n, share_type( 0 ) );
      obj.factory = _factory->id;  // singleton factory reference
   });
   result.new_objects.insert( new_pool.id );

   // Bind share asset to pool
   result.updated_objects.insert( _share_asset->id );
   d.modify( *_share_asset, [&new_pool]( asset_object& ao ) {
      ao.for_reciprocity_pool = new_pool.id;
   });

   // Register pool tokens as known in factory
   // P4-02: bounded mutation of the factory registry. Defends against
   // unbounded growth of the known-token set.
   // Invariant: known_tokens.size() <= MAX_KNOWN_TOKENS; pool registry
   // vectors stay within MAX_POOLS (ceiling checked in do_evaluate).
   // Spec: docs/superpowers/specs/2026-10-25-bsip4-n-asset-pools-design.md §8
   d.modify( *_factory, [&op, &n]( reciprocity_factory_object& rfo ) {
      FC_ASSERT( rfo.pool_count < reciprocity_factory_object::MAX_POOLS,
                 "Pool creation ceiling reached: max ${n} pools",
                 ("n", reciprocity_factory_object::MAX_POOLS) );
      rfo.pool_count++;
      rfo.pools_by_creator[op.account]++;
      rfo.pool_tokens.push_back( op.assets );
      // Register all pool tokens as known, bounded by MAX_KNOWN_TOKENS
      size_t new_tokens = 0;
      for( const auto& asset_id : op.assets ) {
         if( std::find( rfo.known_tokens.begin(), rfo.known_tokens.end(), asset_id )
             == rfo.known_tokens.end() ) {
            new_tokens++;
         }
      }
      FC_ASSERT( rfo.known_tokens.size() + new_tokens <= reciprocity_factory_object::MAX_KNOWN_TOKENS,
                 "Known-token registry ceiling reached: max ${n} tokens",
                 ("n", reciprocity_factory_object::MAX_KNOWN_TOKENS) );
      for( const auto& asset_id : op.assets ) {
         if( std::find( rfo.known_tokens.begin(), rfo.known_tokens.end(), asset_id )
             == rfo.known_tokens.end() ) {
            rfo.known_tokens.push_back( asset_id );
         }
      }
   });

   return result;
} FC_CAPTURE_AND_RETHROW( (op) ) }

// ==========================================================================
//  SWAP EVALUATOR — fee on output only
// ==========================================================================

void_result reciprocity_pool_swap_evaluator::do_evaluate( const reciprocity_pool_swap_operation& op )
{ try {
   FC_ASSERT( op.account != account_id_type(), "Unauthorized account" );
   const database& d = db();
   // P4-07: explicit BSIP-4 hardfork gate (see create evaluator for rationale).
   FC_ASSERT( HARDFORK_BSIP4_PASSED(d.head_block_time()),
              "Not allowed until the BSIP-4 hardfork" );
   _pool = &op.pool(d);
   uint64_t n = _pool->factors;

   FC_ASSERT( op.deadline == 0 || d.head_block_time().sec_since_epoch() <= op.deadline, "Deadline expired" );
   FC_ASSERT( _pool->initialized, "Pool has not been initialized" );
   FC_ASSERT( _pool->supply > 0, "Pool drained" );
   FC_ASSERT( op.amounts_to_sell.size() == n, "amounts_to_sell size mismatch" );
   FC_ASSERT( op.min_to_receive.size() == n, "min_to_receive size mismatch" );
   FC_ASSERT( op.target <= RECIPROCITY_BASIS, "Target exceeds 100%" );

   _pool_receives.resize( n );
   _pool_pays.resize( n );
   _fees.resize( n );

   for( uint64_t i = 0; i < n; i++ ) {
      FC_ASSERT( op.amounts_to_sell[i].asset_id == _pool->tokens[i],
                 "Asset mismatch at index ${idx}", ("idx", i) );
      FC_ASSERT( op.min_to_receive[i].asset_id == _pool->tokens[i],
                 "Asset mismatch at index ${idx}", ("idx", i) );
      _pool_receives[i] = op.amounts_to_sell[i];
      _pool_pays[i] = asset( 0, _pool->tokens[i] );
      _fees[i] = asset( 0, _pool->tokens[i] );
   }

   // Check that at least something is being sold
   bool has_sell = op.shares_in > 0;
   for( uint64_t i = 0; i < n; i++ ) {
      if( op.amounts_to_sell[i].amount > 0 ) has_sell = true;
      FC_ASSERT( op.amounts_to_sell[i].amount >= 0, "Invalid amount" );
   }
   FC_ASSERT( has_sell, "Nothing to sell" );

   // D5: same token cannot be both input and output
   for( uint64_t i = 0; i < n; i++ ) {
      FC_ASSERT( !(op.amounts_to_sell[i].amount > 0 && op.min_to_receive[i].amount > 0),
                 "Same token cannot be both input and output" );
   }

   _share_asset_dyn_data = &_pool->lp_token(d).dynamic_data(d);

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

generic_exchange_operation_result reciprocity_pool_swap_evaluator::do_apply(
      const reciprocity_pool_swap_operation& op )
{ try {
   database& d = db();
   generic_exchange_operation_result result;
   uint64_t n = _pool->factors;

   // Pre-swap state
   vector<share_type> pre_bals( n );
   vector<share_type> genesis( n );
   for( uint64_t i = 0; i < n; i++ ) {
      pre_bals[i] = _pool->balances[i];
      genesis[i]  = _pool->genesis[i];
   }

   vector<share_type> tokens_in( n, share_type( 0 ) );
   vector<share_type> tokens_out( n, share_type( 0 ) );
   for( uint64_t i = 0; i < n; i++ ) {
      tokens_in[i]  = _pool_receives[i].amount;
      tokens_out[i] = op.min_to_receive[i].amount;
   }

     share_type shares_in = op.shares_in;
     uint128_t pre_k = r_compute_konstant( pre_bals, genesis, n, _pool->scale,
                                           _pool->weights );
     FC_ASSERT( _pool->scale > 0, "Compute limit exceeded" );
     FC_ASSERT( pre_k > 0 || _pool->supply == 0, "Invalid K consultation" );

     // Compute post-swap balances
   vector<share_type> post_bals( n );
   for( uint64_t i = 0; i < n; i++ )
      post_bals[i] = share_type( pre_bals[i].value + tokens_in[i].value - tokens_out[i].value );

   uint128_t post_k = r_compute_konstant( post_bals, genesis, n, _pool->scale,
                                          _pool->weights );

      // Aequitas — governed spread (governance applied inside)
      uint128_t raw_spread = r_compute_aequitas( pre_bals, post_bals, pre_k, post_k, n,
                                                 _pool->spread_multiplier,
                                                 _pool->spread_additive,
                                                 _pool->weights,
                                                 _pool->sum_weights );
     uint64_t spread = static_cast<uint64_t>( raw_spread );

     // Warmup: first trades use ema_spread_target
      if( _pool->spread_count <= 2 )
         spread = _pool->ema_spread_target;

    // Fee on output token only — spread-based (spec §4.1)
    vector<share_type> final_fees( n, share_type( 0 ) );
    final_fees = r_compute_fees( tokens_out, spread, n );

    // Fetch factory (singleton — first object in the factory index)
    {
       const auto& factory_idx = d.get_index_type<reciprocity_factory_index>().indices().get<by_id>();
   FC_ASSERT( !factory_idx.empty(), "No factory exists" );
       _factory = &(*factory_idx.begin());
    }

    // Tithed balances = post + LP share of fees (spec §4.1, per-token split)
   vector<share_type> tithed_bals( n );
   vector<share_type> final_tokens_out( n, share_type( 0 ) );
   vector<uint128_t> cached_founder_shares( n, 0 );
   vector<uint128_t> cached_promoter_shares( n, 0 );
   vector<uint128_t> cached_lp_shares( n, 0 );
   for( uint64_t i = 0; i < n; i++ ) {
      uint128_t raw_fee = uint128_t( final_fees[i].value );
      r_royalty_split( raw_fee, FOUNDER_ROYALTY, PROMOTER_ROYALTY,
                       cached_founder_shares[i], cached_promoter_shares[i], cached_lp_shares[i] );
      FC_ASSERT( cached_lp_shares[i] <= std::numeric_limits<int64_t>::max(), "LP share overflow int64" );
      FC_ASSERT( cached_founder_shares[i] <= std::numeric_limits<int64_t>::max(), "Founder share overflow int64" );
      FC_ASSERT( cached_promoter_shares[i] <= std::numeric_limits<int64_t>::max(), "Promoter share overflow int64" );
        int64_t tithed_i = post_bals[i].value + static_cast<int64_t>( cached_lp_shares[i] )
                         - static_cast<int64_t>( cached_founder_shares[i] ) - static_cast<int64_t>( cached_promoter_shares[i] );
        // ponytail: clamp to 0 — edge case when fee floor (3) makes fs+ps > lp_share for a single-output token
        if( tithed_i < 0 ) tithed_i = 0;
        tithed_bals[i] = share_type( tithed_i );
       final_tokens_out[i] = share_type(
             std::max<int64_t>( 0, tokens_out[i].value - static_cast<int64_t>( cached_lp_shares[i] ) ) );
    }

   uint128_t tithed_k = r_compute_konstant( tithed_bals, genesis, n, _pool->scale,
                                            _pool->weights );

     // Reciprocity (base: sharesIn + tithedK - preK)
     uint128_t reciprocity_u128 = tithed_k + uint128_t( shares_in.value );
     FC_ASSERT( reciprocity_u128 >= pre_k, "Negative reciprocity" );
     reciprocity_u128 = reciprocity_u128 - pre_k;
     FC_ASSERT( reciprocity_u128 <= std::numeric_limits<int64_t>::max(), "Reciprocity overflow" );
     int64_t reciprocity_val = static_cast<int64_t>( reciprocity_u128 );
      FC_ASSERT( reciprocity_val >= op.min_shares_out.value, "Shares out below minimum" );

     // ponytail: removed self-contradicting min_to_receive assertion — final_tokens_out = min_to_receive - lp_share
     // violates its own premise for any positive-fee swap. Existing balance checks prevent underflow.

   // post_k_stake for TVWAP
   vector<share_type> stake_post_bals( n );
   for( uint64_t i = 0; i < n; i++ )
      stake_post_bals[i] = share_type( pre_bals[i].value + tokens_in[i].value );
    uint128_t post_k_stake = r_compute_konstant( stake_post_bals, genesis, n, _pool->scale,
                                                 _pool->weights );

      // Cache immutable pool fields before modify (tokens/lp_token never change)
      const auto _pool_tokens = _pool->tokens;
      const auto _pool_lp_token = _pool->lp_token;

      // Fee accumulation deltas — batch factory updates (one d.modify instead of up to 16)
      vector<share_type> founder_delta( n, share_type( 0 ) );
      vector<share_type> promoter_delta( n, share_type( 0 ) );

      // === CEI: Effects (state updates BEFORE transfers) ===

     // Update pool state
     d.modify( *_pool, [&]( reciprocity_pool_object& rpo ){
      // Balances
      for( uint64_t i = 0; i < n; i++ )
         rpo.balances[i] = tithed_bals[i];

      // Supply = LP share count, updated by K change minus burned LP shares
      {
          FC_ASSERT( tithed_k <= std::numeric_limits<int64_t>::max() &&
                     pre_k <= std::numeric_limits<int64_t>::max(),
                     "K overflow int64" );
          int64_t supply_delta = static_cast<int64_t>( tithed_k ) - static_cast<int64_t>( pre_k );
         rpo.supply += supply_delta;
      }

      // Detect drain: supply <= 0 (canonical, not tithed_bals — those go negative with drip fees)
      {
          if( rpo.supply <= 0 ) {
             rpo.supply = share_type( 0 );
             for( uint64_t i = 0; i < n; i++ ) {
                rpo.balances[i] = share_type( 0 );
                rpo.lp_royalties[i] = share_type( 0 );
             }
          }
      }

        for( uint64_t i = 0; i < n; i++ ) {
           if( final_fees[i] > 0 ) {
              uint128_t founder_share = cached_founder_shares[i];
              uint128_t promoter_share = cached_promoter_shares[i];
              uint128_t lp_share = cached_lp_shares[i];
               if( founder_share > 0 ) {
                  share_type founder_val( static_cast<int64_t>( founder_share ) );
                  rpo.founder_fees[i] += founder_val;
                  founder_delta[i] += founder_val;
              }
               if( promoter_share > 0 ) {
                  share_type promoter_val( static_cast<int64_t>( promoter_share ) );
                  rpo.promoter_fees[i] += promoter_val;
                  promoter_delta[i] += promoter_val;
              }
               if( lp_share > 0 ) {
                  rpo.lp_royalties[i] += share_type( static_cast<int64_t>( lp_share ) );
              }
           }
        }

        // Persist raw duty and run spread governor with last_spread after
       rpo.duty = static_cast<uint64_t>( raw_spread );
       r_spread_governor( rpo, spread );
       rpo.last_spread = spread;

      // TVWAP update (only on K change, not on fee claims)
      uint64_t now = d.head_block_time().sec_since_epoch();
      if( rpo.supply <= 0 ) {
         r_reset_tvwap_state( rpo );
         rpo.last_timestamp = now;
         rpo.window_start_15m = now;
         rpo.window_start_1hr = now;
         rpo.window_start_24hr = now;
      } else
         r_update_tvwap( rpo, pre_k, post_k_stake, now );

      rpo.transactions++;
   });
      // _pool pointer invalid after d.modify — use cached _pool_tokens / _pool_lp_token
      // for all reads after this point.

      // Batch factory fee accumulation (single d.modify, not one per token)
      {
         bool has_factory_fees = false;
         for( uint64_t i = 0; i < n; i++ )
            if( founder_delta[i] > 0 || promoter_delta[i] > 0 ) { has_factory_fees = true; break; }
         if( has_factory_fees ) {
            d.modify( *_factory, [&]( reciprocity_factory_object& f ){
               for( uint64_t i = 0; i < n; i++ ) {
                  if( founder_delta[i] > 0 )
                     f.founder_fees[ _pool_tokens[i] ] += founder_delta[i];
                  if( promoter_delta[i] > 0 )
                     f.promoter_fees[ _pool_tokens[i] ] += promoter_delta[i];
               }
            });
         }
      }

      // Update share asset supply
     if( shares_in > 0 || reciprocity_val != 0 ) {
        d.modify( *_share_asset_dyn_data, [&]( asset_dynamic_data_object& data ){
           if( shares_in > 0 )
              data.current_supply -= shares_in;
           if( reciprocity_val > 0 )
              data.current_supply += reciprocity_val;
        });
     }

    // === CEI: Interactions (transfers AFTER state updates) ===

    // Transfer sold tokens from user to pool
    for( uint64_t i = 0; i < n; i++ ) {
       if( _pool_receives[i].amount > 0 )
          d.adjust_balance( op.account, -_pool_receives[i] );
    }

     // Transfer received tokens to user
     for( uint64_t i = 0; i < n; i++ ) {
        if( final_tokens_out[i] > 0 )
           d.adjust_balance( op.account, asset( final_tokens_out[i], _pool_tokens[i] ) );
     }

      // Adjust LP shares
      if( shares_in > 0 )
         d.adjust_balance( op.account, -asset( shares_in, _pool_lp_token ) );
      if( reciprocity_val > 0 )
         d.adjust_balance( op.account, asset( reciprocity_val, _pool_lp_token ) );

    // Build result
   for( uint64_t i = 0; i < n; i++ )
      if( _pool_receives[i].amount > 0 )
         result.paid.emplace_back( _pool_receives[i] );
    for( uint64_t i = 0; i < n; i++ )
       if( final_tokens_out[i] > 0 )
          result.received.emplace_back( asset( final_tokens_out[i], _pool_tokens[i] ) );
    if( reciprocity_val > 0 )
       result.received.emplace_back( asset( reciprocity_val, _pool_lp_token ) );

   return result;
} FC_CAPTURE_AND_RETHROW( (op) ) }

// ==========================================================================
//  ADD LIQUIDITY EVALUATOR
// ==========================================================================

void_result reciprocity_pool_add_liquidity_evaluator::do_evaluate(
      const reciprocity_pool_add_liquidity_operation& op )
{ try {
   const database& d = db();
   // P4-07: explicit BSIP-4 hardfork gate (see create evaluator for rationale).
   FC_ASSERT( HARDFORK_BSIP4_PASSED(d.head_block_time()),
              "Not allowed until the BSIP-4 hardfork" );
   _pool = &op.pool(d);
   uint64_t n = _pool->factors;

   FC_ASSERT( op.deadline == 0 || d.head_block_time().sec_since_epoch() <= op.deadline, "Deadline expired" );
   FC_ASSERT( op.amounts.size() == n, "Amounts count must match pool factors" );

   for( uint64_t i = 0; i < n; i++ )
      FC_ASSERT( op.amounts[i].asset_id == _pool->tokens[i],
                 "Asset ID mismatch at index ${idx}", ("idx", i) );

   const asset_object& share_asset_obj = _pool->lp_token(d);
   FC_ASSERT( share_asset_obj.can_create_new_supply(), "Can not create new supply" );

   _share_asset_dyn_data = &share_asset_obj.dynamic_data(d);

    if( _pool->supply == 0 ) {
      // Promoter-only: only the LP token issuer can make the initial deposit
      FC_ASSERT( share_asset_obj.issuer == op.account,
                 "Only the LP token issuer can make the initial deposit" );

      // Initial deposit: LP shares = K of deposit amounts
      vector<share_type> init_bals( n );
      for( uint64_t i = 0; i < n; i++ )
         init_bals[i] = op.amounts[i].amount;

      uint128_t scale = r_compute_scale( init_bals );
      uint128_t k = r_compute_konstant( init_bals, init_bals, n, scale,
                                         _pool->weights );

      FC_ASSERT( k <= uint128_t( share_asset_obj.options.max_supply.value ),
                 "Initial deposit exceeds max supply" );

      _pool_receives = op.amounts;
      _account_receives = asset( static_cast<int64_t>( k ), _pool->lp_token );
   } else {
      // Subsequent deposit: K-delta formula (matches reference add_liquidity normal path)
      // shares = post_k - pre_k, pool receives full op.amounts (no proportional scaling)
      vector<share_type> cur_bals( n );
      for( uint64_t i = 0; i < n; i++ )
         cur_bals[i] = _pool->balances[i];
      uint128_t pre_k = r_compute_konstant( cur_bals, _pool->genesis, n,
                                            _pool->scale, _pool->weights );
      vector<share_type> post_bals( n );
      for( uint64_t i = 0; i < n; i++ )
         post_bals[i] = share_type( cur_bals[i].value + op.amounts[i].amount.value );
      uint128_t post_k = r_compute_konstant( post_bals, _pool->genesis, n,
                                             _pool->scale, _pool->weights );
      uint128_t new_shares = post_k > pre_k ? post_k - pre_k : 0;
      FC_ASSERT( new_shares > 0, "Aborting due to zero outcome" );

      share_type max_new = share_asset_obj.options.max_supply - _share_asset_dyn_data->current_supply;
      if( new_shares > uint128_t( max_new.value ) ) new_shares = uint128_t( max_new.value );

      _pool_receives.resize( n );
      for( uint64_t i = 0; i < n; i++ )
         _pool_receives[i] = op.amounts[i];

      _account_receives = asset( static_cast<int64_t>( new_shares ), _pool->lp_token );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

generic_exchange_operation_result reciprocity_pool_add_liquidity_evaluator::do_apply(
      const reciprocity_pool_add_liquidity_operation& op )
{ try {
   database& d = db();
   generic_exchange_operation_result result;
   uint64_t n = _pool->factors;

    // === CEI: Effects (state updates BEFORE transfers) ===

    share_type expected_supply;
    d.modify( *_pool, [this, n, &expected_supply, &d]( reciprocity_pool_object& rpo ){
       if( rpo.supply == 0 ) {
          // Initial deposit
          vector<share_type> init_share_bals( n );
           for( uint64_t i = 0; i < n; i++ )
              init_share_bals[i] = _pool_receives[i].amount;
           uint128_t scale = r_compute_scale( init_share_bals );
           for( uint64_t i = 0; i < n; i++ ) {
               FC_ASSERT( _pool_receives[i].amount > 0, "Zero amount on re-init at index ${idx}", ("idx", i) );
              rpo.balances[i] = _pool_receives[i].amount;
              rpo.genesis[i]  = _pool_receives[i].amount;
          }
          rpo.scale = scale;

          uint128_t k = r_compute_konstant( rpo.balances, rpo.genesis, n, scale,
                                            rpo.weights );
           rpo.supply   = share_type( static_cast<int64_t>( k ) );
             rpo.initialized = true;
               rpo.avg_spread = rpo.ema_spread_target;
                rpo.avg_spread_rem = 0;
                rpo.atr_spread = rpo.atr_spread_target;
                rpo.atr_spread_rem = 0;
                rpo.spread_additive = 0;
                 rpo.spread_count = 1;
                rpo.last_spread = 0;
               rpo.spread_multiplier = RECIPROCITY_BASIS;
            // TVWAP init
           uint64_t now_init = d.head_block_time().sec_since_epoch();
          r_reset_tvwap_state( rpo );
          rpo.last_timestamp = now_init;
           rpo.window_start_15m = now_init;
           rpo.window_start_1hr = now_init;
           rpo.window_start_24hr = now_init;
           for( uint64_t i = 0; i < n; i++ ) {
              rpo.lp_royalties[i] = share_type( 0 );
              // ponytail: founder_fees and promoter_fees intentionally NOT
              // zeroed — fees earned before drain remain claimable per spec §7 Q8.
              // The authoritative accumulators live at the factory level;
              // pool-level mirrors persist for consistency.
           }
           expected_supply = rpo.supply;
         } else {
           vector<share_type> cur_bals( n );
           for( uint64_t i = 0; i < n; i++ )
              cur_bals[i] = rpo.balances[i];
           uint128_t pre_k = r_compute_konstant( cur_bals, rpo.genesis, n,
                                                 rpo.scale, rpo.weights );
           for( uint64_t i = 0; i < n; i++ )
               rpo.balances[i] += _pool_receives[i].amount;
            uint128_t new_k = r_compute_konstant( rpo.balances, rpo.genesis, n,
                                                  rpo.scale, rpo.weights );
           share_type delta_supply = share_type( static_cast<int64_t>(
                 new_k > pre_k ? new_k - pre_k : 0 ) );

            rpo.supply += delta_supply;
            expected_supply = rpo.supply;

          // TVWAP update
          uint64_t now = d.head_block_time().sec_since_epoch();
          r_update_tvwap( rpo, pre_k, new_k, now );
       }
    });

    d.modify( *_share_asset_dyn_data, [&]( asset_dynamic_data_object& data ){
         data.current_supply += _account_receives.amount;
      });
    FC_ASSERT( _share_asset_dyn_data->current_supply == expected_supply, "LPSyncDrift" );

     // === CEI: Interactions (transfers AFTER state updates) ===

    // Transfer tokens from user to pool
    for( uint64_t i = 0; i < n; i++ )
       d.adjust_balance( op.account, -_pool_receives[i] );
    d.adjust_balance( op.account, _account_receives );

    for( uint64_t i = 0; i < n; i++ )
       result.paid.emplace_back( _pool_receives[i] );
   result.received.emplace_back( _account_receives );

   return result;
} FC_CAPTURE_AND_RETHROW( (op) ) }

// ==========================================================================
//  REMOVE LIQUIDITY EVALUATOR
// ==========================================================================

void_result reciprocity_pool_remove_liquidity_evaluator::do_evaluate(
      const reciprocity_pool_remove_liquidity_operation& op )
{ try {
   const database& d = db();
   // P4-07: explicit BSIP-4 hardfork gate (see create evaluator for rationale).
   FC_ASSERT( HARDFORK_BSIP4_PASSED(d.head_block_time()),
              "Not allowed until the BSIP-4 hardfork" );
   _pool = &op.pool(d);
   uint64_t n = _pool->factors;

   FC_ASSERT( op.deadline == 0 || d.head_block_time().sec_since_epoch() <= op.deadline, "Deadline expired" );
   FC_ASSERT( op.share_amount.asset_id == _pool->lp_token, "Share asset mismatch" );
   FC_ASSERT( _pool->supply > 0, "Pool has not been initialized" );

   const asset_object& share_asset_obj = _pool->lp_token(d);
   _share_asset_dyn_data = &share_asset_obj.dynamic_data(d);

    FC_ASSERT( _share_asset_dyn_data->current_supply >= op.share_amount.amount,
               "Can not withdraw more than current supply" );
    FC_ASSERT( op.share_amount.amount > 0, "Share amount must be positive" );
    FC_ASSERT( op.share_amount.amount <= _pool->supply,
               "Can not withdraw more than total LP supply" );

    _pool_pays.resize( n );
    _fees.resize( n );

    uint128_t share128( op.share_amount.amount.value );
    uint128_t supply128( _pool->supply.value );

    if( share128 >= supply128 || _pool->supply == 0 ) {
      // Full exit
      for( uint64_t i = 0; i < n; i++ ) {
         _pool_pays[i] = asset( _pool->balances[i], _pool->tokens[i] );
         _fees[i] = asset( 0, _pool->tokens[i] );
      }
   } else {
      for( uint64_t i = 0; i < n; i++ ) {
          uint128_t amount = r_safe_mul( share128, uint128_t( _pool->balances[i].value ) )
                           / supply128;
          // ponytail: balance-1 cap prevents full-drain race with concurrent remove
          // (share128 < supply128 by this branch, so -- is safe; upgrade path:
          //  move to share-is-authority drain like the swap evaluator)
          if( amount >= uint128_t( _pool->balances[i].value ) )
             amount = uint128_t( _pool->balances[i].value ) - 1;
          _pool_pays[i] = asset( static_cast<int64_t>( amount ), _pool->tokens[i] );
         _fees[i] = asset( 0, _pool->tokens[i] );
      }
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

generic_exchange_operation_result reciprocity_pool_remove_liquidity_evaluator::do_apply(
      const reciprocity_pool_remove_liquidity_operation& op )
{ try {
   database& d = db();
   generic_exchange_operation_result result;
   uint64_t n = _pool->factors;

    // === CEI: Effects (state updates BEFORE transfers) ===

    d.modify( *_share_asset_dyn_data, [&op]( asset_dynamic_data_object& data ){
       data.current_supply -= op.share_amount.amount;
    });

      d.modify( *_pool, [this, n, &d, &op]( reciprocity_pool_object& rpo ){
       uint128_t pre_k = r_compute_konstant( rpo.balances, rpo.genesis, n,
                                             rpo.scale, rpo.weights );
        for( uint64_t i = 0; i < n; i++ )
           rpo.balances[i] -= _pool_pays[i].amount;

      uint128_t new_k = r_compute_konstant( rpo.balances, rpo.genesis, n,
                                            rpo.scale, rpo.weights );

      rpo.supply -= op.share_amount.amount;

        bool drain = ( rpo.supply <= 0 );
         if( drain ) {
            rpo.supply = share_type( 0 );
            for( uint64_t i = 0; i < n; i++ ) {
               rpo.balances[i] = share_type( 0 );
               rpo.lp_royalties[i] = share_type( 0 );
            }
          }

         // TVWAP update
      uint64_t now = d.head_block_time().sec_since_epoch();
      if( drain ) {
         r_reset_tvwap_state( rpo );
         rpo.last_timestamp = now;
         rpo.window_start_15m = now;
         rpo.window_start_1hr = now;
         rpo.window_start_24hr = now;
      } else
          r_update_tvwap( rpo, pre_k, new_k, now );
    });

    // === CEI: Interactions (transfers AFTER state updates) ===

    d.adjust_balance( op.account, -op.share_amount );

    for( uint64_t i = 0; i < n; i++ ) {
       if( _pool_pays[i].amount > 0 )
          d.adjust_balance( op.account, _pool_pays[i] );
    }

    result.paid.emplace_back( op.share_amount );
   for( uint64_t i = 0; i < n; i++ )
      result.received.emplace_back( _pool_pays[i] );

   return result;
} FC_CAPTURE_AND_RETHROW( (op) ) }

// ==========================================================================
//  CLAIM FOUNDER ROYALTY — committee only
// ==========================================================================

void_result reciprocity_claim_founder_royalty_evaluator::do_evaluate(
      const reciprocity_claim_founder_royalty_operation& op )
{ try {
   const database& d = db();
   // P4-07: explicit BSIP-4 hardfork gate (see create evaluator for rationale).
   FC_ASSERT( HARDFORK_BSIP4_PASSED(d.head_block_time()),
              "Not allowed until the BSIP-4 hardfork" );
    FC_ASSERT( op.account == GRAPHENE_COMMITTEE_ACCOUNT, "Only committee can claim founder fees" );

    // Find factory (singleton)
    const auto& factory_idx = d.get_index_type<reciprocity_factory_index>().indices().get<by_id>();
    FC_ASSERT( !factory_idx.empty(), "No factory exists" );
    _factory = &(*factory_idx.begin());

    FC_ASSERT( _factory->founder_fees.count( op.token ) && _factory->founder_fees.at( op.token ) > 0,
               "Nothing to claim" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result reciprocity_claim_founder_royalty_evaluator::do_apply(
      const reciprocity_claim_founder_royalty_operation& op )
{ try {
   database& d = db();

   share_type amount = _factory->founder_fees.at( op.token );
   account_id_type dest = GRAPHENE_COMMITTEE_ACCOUNT;

   // CEI: state updates before balance transfer
   d.modify( *_factory, [&op, &amount]( reciprocity_factory_object& rfo ) {
      rfo.founder_fees[op.token] = share_type( 0 );
   });

   // Transfer to committee
   d.adjust_balance( dest, asset( amount, op.token ) );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

// ==========================================================================
//  CLAIM PROMOTER ROYALTY — token issuer only
// ==========================================================================

void_result reciprocity_claim_promoter_royalty_evaluator::do_evaluate(
      const reciprocity_claim_promoter_royalty_operation& op )
{ try {
   const database& d = db();
   // P4-07: explicit BSIP-4 hardfork gate (see create evaluator for rationale).
   FC_ASSERT( HARDFORK_BSIP4_PASSED(d.head_block_time()),
              "Not allowed until the BSIP-4 hardfork" );
    const auto& token_obj = op.token(d);
    FC_ASSERT( token_obj.issuer == op.account, "Only token issuer can claim promoter fees" );

    // Find factory (singleton)
    const auto& factory_idx = d.get_index_type<reciprocity_factory_index>().indices().get<by_id>();
    FC_ASSERT( !factory_idx.empty(), "No factory exists" );
    _factory = &(*factory_idx.begin());

    FC_ASSERT( _factory->promoter_fees.count( op.token ) && _factory->promoter_fees.at( op.token ) > 0,
               "Nothing to claim" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result reciprocity_claim_promoter_royalty_evaluator::do_apply(
      const reciprocity_claim_promoter_royalty_operation& op )
{ try {
   database& d = db();

   share_type amount = _factory->promoter_fees.at( op.token );
   account_id_type dest = op.account;

   // CEI: state updates before balance transfer
   d.modify( *_factory, [&op, &amount]( reciprocity_factory_object& rfo ) {
      rfo.promoter_fees[op.token] = share_type( 0 );
   });

   // Transfer to token issuer
   d.adjust_balance( dest, asset( amount, op.token ) );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }



} } // graphene::chain

#include <fc/io/raw.hpp>

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::reciprocity_pool_object )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::reciprocity_factory_object )
