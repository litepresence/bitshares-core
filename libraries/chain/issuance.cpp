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
#include <graphene/chain/issuance_evaluator.hpp>
#include <graphene/chain/issuance_object.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_activation.hpp>
#include <graphene/chain/h2_economics_evaluator.hpp>
#include <graphene/chain/h2_economics_object.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/chain/winddown_object.hpp>

#include <boost/multiprecision/cpp_int.hpp>
#include <fc/io/raw.hpp>
#include <fc/uint128.hpp>

namespace graphene { namespace chain {

namespace {

using boost::multiprecision::uint256_t;
using graphene::protocol::GRAPHENE_H2_ISSUE_CONVERSION_FEE_BPS;
using graphene::protocol::GRAPHENE_H2_ISSUE_DOOR_CAP_BTS;
using graphene::protocol::GRAPHENE_H2_ISSUE_FXR_GENESIS_PARITY;
using graphene::protocol::GRAPHENE_H2_ISSUE_REDEEM_VEST_SEC;
using graphene::protocol::GRAPHENE_H2_ISSUE_RMIN_BPS;
using graphene::protocol::GRAPHENE_H2_ISSUE_TARGET_BPS;

/// Conversion-fee slice (declared, floored, exact): floor(amount * 30 /
/// 10000) in 256-bit with one truncating division. The slice never leaves
/// the reserve: on mints it backs the book while buying no stable (the
/// per-request coverage check prices the NET deposit); on redeems it is
/// withheld from the vesting payout (the payout legs below subtract it
/// before booking escrow). Rounding favors the protocol (the slice floors,
/// the minter/redeemer pays the truncation). Non-positive input yields 0.
share_type h2_issue_fee_slice( share_type amount )
{
   if( amount <= share_type( 0 ) )
      return share_type( 0 );
   const uint256_t slice = uint256_t( uint64_t( amount.value ) )
                         * uint256_t( GRAPHENE_H2_ISSUE_CONVERSION_FEE_BPS )
                         / uint256_t( 10000 );
   return share_type( int64_t( uint64_t( slice ) ) );
}

/// Saturating share addition (Recovery-scope h2_sat_add precedent):
/// pair-level totals can in principle exceed int64 while comparisons only
/// need monotonicity. Checked share math (+=) still throws on overflow at
/// the object write; this helper is for read-side sums only.
share_type h2_issue_sat_add( share_type a, share_type b )
{
   if( a <= share_type( 0 ) )
      return b;
   if( b <= share_type( 0 ) )
      return a;
   const uint256_t sum = uint256_t( uint64_t( a.value ) )
                       + uint256_t( uint64_t( b.value ) );
   if( sum > uint256_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ) )
      return share_type( GRAPHENE_MAX_SHARE_SUPPLY );
   return share_type( int64_t( uint64_t( sum ) ) );
}

/**
 * rmin gate (declared, exact, no floats, no division): does reserve
 * @p bts_raw BTS backing @p supply_face face at @p price at or above
 * @p rmin_bps? Face value of the reserve is bts_raw * quote / base, so
 * value/supply >= rmin/10000 cross-multiplies (256-bit) to
 * bts_raw * quote * 10000 >= supply_face * base * rmin_bps.
 * Equality MEETS (the floor is inclusive headroom, tripwire-breach
 * precedent). Every factor is non-negative by construction; callers
 * guarantee supply_face > 0 and a non-degenerate price.
 */
bool h2_issue_meets_rmin( share_type bts_raw, share_type supply_face,
                          const protocol::oracle_value& price, uint32_t rmin_bps )
{
   if( bts_raw < share_type( 0 ) || supply_face <= share_type( 0 ) )
      return false;
   const uint256_t lhs = uint256_t( uint64_t( bts_raw.value ) )
                       * uint256_t( uint64_t( price.quote_amount.value ) )
                       * uint256_t( 10000 );
   const uint256_t rhs = uint256_t( uint64_t( supply_face.value ) )
                       * uint256_t( uint64_t( price.base_amount.value ) )
                       * uint256_t( rmin_bps );
   return lhs >= rhs;
}

/**
 * Target surplus (declared, floored, exact): max(0, value_face -
 * floor(target_bps * supply_face / 10000)), the face value above the
 * surplus target. 256-bit products, one truncating division: every node
 * computes the same surplus.
 */
uint256_t h2_issue_surplus_face( share_type bts_raw, share_type supply_face,
                                 const protocol::oracle_value& price,
                                 uint32_t target_bps )
{
   if( bts_raw <= share_type( 0 ) || supply_face < share_type( 0 ) )
      return uint256_t( 0 );
   // value_face = floor(bts_raw * quote / base): same truncation as the
   // bts_to_face conversion (one formula, one rounding, shared with it).
   const uint256_t value_face =
         uint256_t( uint64_t( bts_raw.value ) )
         * uint256_t( uint64_t( price.quote_amount.value ) )
         / uint256_t( uint64_t( price.base_amount.value ) );
   const uint256_t target_face =
         uint256_t( uint64_t( supply_face.value ) )
         * uint256_t( target_bps ) / uint256_t( 10000 );
   return value_face > target_face ? value_face - target_face : uint256_t( 0 );
}

/// Door accounting: the counter belongs to @p head_block iff the reserve
/// exists and stamped this block; otherwise the block opens at zero.
share_type h2_issue_door_used( const reserve_object* reserve, uint32_t head_block )
{
   if( reserve == nullptr || reserve->door_block != head_block )
      return share_type( 0 );
   return reserve->door_used_bts;
}

} // namespace

const reserve_object* h2_find_reserve( const database& d, asset_id_type pair )
{
   const auto& idx = d.get_index_type<reserve_index>().indices().get<by_reserve_pair>();
   const auto itr = idx.find( pair );
   return itr == idx.end() ? nullptr : &*itr;
}

share_type h2_issue_bts_to_face( share_type bts_raw,
                                 const protocol::oracle_value& price )
{
   if( bts_raw <= share_type( 0 ) || price.base_amount <= share_type( 0 ) || price.quote_amount <= share_type( 0 ) )
      return share_type( 0 );
   // floor(bts_raw * quote / base), 256-bit product, truncating division:
   // declared round-DOWN against the receiver (favoring the protocol).
   // Same conversion style as the H1 consumers and h2_convert_face_to_bond
   // (inverted leg), read through the same bonded gate as every H2 price.
   const uint256_t face =
         uint256_t( uint64_t( bts_raw.value ) )
         * uint256_t( uint64_t( price.quote_amount.value ) )
         / uint256_t( uint64_t( price.base_amount.value ) );
   if( face > uint256_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ) )
      return share_type( GRAPHENE_MAX_SHARE_SUPPLY );
   return share_type( int64_t( uint64_t( face ) ) );
}

share_type h2_issue_face_to_bts( share_type face_raw,
                                 const protocol::oracle_value& price )
{
   if( face_raw <= share_type( 0 ) || price.base_amount <= share_type( 0 ) || price.quote_amount <= share_type( 0 ) )
      return share_type( 0 );
   // floor(face_raw * base / quote), 256-bit, truncating: declared
   // round-DOWN against the receiver (the redeemer: the payout floors,
   // favoring the protocol). h2_convert_face_to_bond's exact formula.
   const uint256_t bts =
         uint256_t( uint64_t( face_raw.value ) )
         * uint256_t( uint64_t( price.base_amount.value ) )
         / uint256_t( uint64_t( price.quote_amount.value ) );
   if( bts > uint256_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ) )
      return share_type( GRAPHENE_MAX_SHARE_SUPPLY );
   return share_type( int64_t( uint64_t( bts ) ) );
}

uint32_t h2_issue_coverage_bps( share_type value_face, share_type supply_face )
{
   constexpr uint32_t saturate = 0xFFFFFFFF;
   if( supply_face <= share_type( 0 ) )
      return saturate; // nothing to secure: covered by vacuity
   if( value_face <= share_type( 0 ) )
      return 0;
   const fc::uint128_t q = fc::uint128_t( uint64_t( value_face.value ) )
                         * fc::uint128_t( 10000 )
                         / fc::uint128_t( uint64_t( supply_face.value ) );
   if( q >= fc::uint128_t( uint64_t( saturate ) ) )
      return saturate;
   return uint32_t( fc::uint128_lo64( q ) );
}

void_result hybrid_mint_evaluator::do_evaluate( const hybrid_mint_operation& op )
{ try {
   database& d = db();
   const time_point_sec now = d.head_block_time();
   const uint32_t head_block = d.head_block_num();

   // Price leg (H2e): minting values through bonded prices, so it admits
   // at the price height. Ordering asserted inside.
   h2_require_price_leg( now );

   _vault = d.find( op.vault );
   FC_ASSERT( nullptr != _vault, "Vault ${v} does not exist", ("v", op.vault) );
   FC_ASSERT( _vault->maintenance_state != GRAPHENE_H2_VAULT_WINDDOWN,
              "Vault is wound down; exits go through wind-down claims, never mints" );
   // The door hold blocks mints (vault_object contract: while frozen, mint
   // blocked). Exits are the redeem path, never this op.
   FC_ASSERT( !_vault->frozen,
              "Vault door is held shut; mints refused until it reopens" );
   // Recovery suspends new debt (H2d rule, extended from vault_register to
   // every debt tap): a mint grows outstanding, so it is new debt. Exits
   // (redeems, wind-down claims) stay open: this gate touches entry only.
   const auto& rec_idx = d.get_index_type<recovery_state_index>().indices();
   if( !rec_idx.empty() )
      FC_ASSERT( !rec_idx.begin()->new_debt_suspended,
                 "Recovery is active: new debt suspended until scope restores" );

   // Genesis BTS-only (basket timing is a later task): the deposit, the
   // vault's bond asset, and the door unit are all core BTS.
   FC_ASSERT( op.deposit.asset_id == asset_id_type(),
              "Mint deposits are BTS-only at genesis" );
   FC_ASSERT( _vault->bond_asset == asset_id_type(),
              "Mint vaults are BTS-bonded at genesis" );
   FC_ASSERT( nullptr != d.find( op.minter ),
              "Minter account ${a} does not exist", ("a", op.minter) );
   FC_ASSERT( d.get_balance( op.minter, asset_id_type() ).amount >= op.deposit.amount,
              "Minter holds insufficient BTS for the deposit" );

   // The pair is the senior stable: a vault-backed UIA, never the bond
   // asset itself (minting the bond asset as "stable" is reflexive mint
   // and is refused here, not priced downstream).
   const asset_object* pair_asset = d.find( _vault->vault_pair );
   FC_ASSERT( nullptr != pair_asset,
              "Vault pair asset ${a} does not exist", ("a", _vault->vault_pair) );
   FC_ASSERT( !pair_asset->is_market_issued(),
              "Mint pairs are vault-backed UIAs: market-issued assets never mint here" );
   FC_ASSERT( !pair_asset->is_liquidity_pool_share_asset(),
              "Liquidity pool share assets never mint here" );
   FC_ASSERT( _vault->vault_pair != asset_id_type(),
              "The bond asset is never its own stable: reflexive mint refused" );
   FC_ASSERT( pair_asset->can_create_new_supply(), "Pair asset can create no new supply" );

   // Junior token: pinned at reserve creation (first-freeze precedent),
   // matched thereafter. Same non-reflexive shape: neither the pair nor
   // the bond asset, same precision (parity math is unit-exact).
   _reserve = h2_find_reserve( d, _vault->vault_pair );
   _creates_reserve = ( _reserve == nullptr );
   const asset_object* fxr_asset = d.find( op.fxr_asset );
   FC_ASSERT( nullptr != fxr_asset,
              "FXR asset ${a} does not exist", ("a", op.fxr_asset) );
   if( _creates_reserve )
   {
      FC_ASSERT( op.fxr_asset != _vault->vault_pair,
                 "FXR token must differ from the senior pair: reflexive junior refused" );
      FC_ASSERT( op.fxr_asset != asset_id_type(),
                 "FXR token is never the bond asset: reflexive junior refused" );
      FC_ASSERT( !fxr_asset->is_market_issued(),
                 "FXR tokens are plain UIAs: market-issued assets never back juniors" );
      FC_ASSERT( !fxr_asset->is_liquidity_pool_share_asset(),
                 "Liquidity pool share assets never back juniors" );
      FC_ASSERT( fxr_asset->precision == pair_asset->precision,
                 "FXR/pair precision must match: parity math is unit-exact" );
      FC_ASSERT( fxr_asset->can_create_new_supply(), "FXR asset can create no new supply" );
   }
   else
      FC_ASSERT( op.fxr_asset == _reserve->fxr_asset,
                 "Pair ${p} is pinned to FXR ${f}; minting ${g} refused",
                 ("p", _vault->vault_pair)("f", _reserve->fxr_asset)("g", op.fxr_asset) );

   // Bonded read (X-01 reuse, never a new price path): unbonded oracles
   // refuse mints here, so unbonded inputs can never mint bonded stable.
   // Unbound vaults have no price leg by construction (h2_read_pair_price
   // returns absent without a binding).
   const auto price = h2_read_pair_price( d, *_vault, 0, now );
   FC_ASSERT( price.valid(),
              "No bonded live price for this pair; mints halt on unbonded inputs" );
   FC_ASSERT( price->base_amount > share_type( 0 ) && price->quote_amount > share_type( 0 ),
              "Degenerate bonded price; mints refused" );
   _price = *price;

    // Deposit coverage at the bonded price (declared round-DOWN: the floor
    // favors the protocol -- the minter must over-collateralize in fact,
    // not in rounding). The conversion-fee slice (30bps, floored) stays
    // inside the deposit for the rmin book check below but buys NO stable:
    // the request must be covered by the NET deposit alone, so a full
    // mint/redeem cycle costs the fee twice while coverage rises. Both legs
    // of the comparison floor against the minter.
    const share_type fee_slice = h2_issue_fee_slice( op.deposit.amount );
    const share_type net_deposit = op.deposit.amount - fee_slice;
    const share_type net_face = h2_issue_bts_to_face( net_deposit, *price );
    FC_ASSERT( net_face >= op.stable_amount,
               "Net deposit covers ${c} face at the bonded price after the "
               "30bps conversion fee; ${m} requested",
               ("c", net_face)("m", op.stable_amount) );

    // rmin gate (the Terra prohibition): the POST-mint ratio must stay at
    // or above 13000bps. The FULL deposit counts (fee slice included: the
    // slice accrues to the reserve, so it backs the book -- it is only the
    // per-request coverage above that prices the net deposit). Naming the
    // request is load-bearing: a price-derived mint on an empty book opens
    // at ~100% backing and could never clear this gate, so issuance could
    // never start; the minter's chosen over-collateralization opens every
    // book, and this gate holds every later one. Equality meets (inclusive
    // floor).
   const share_type post_bts = h2_issue_sat_add(
         _creates_reserve ? share_type( 0 ) : _reserve->bts_balance, op.deposit.amount );
   const share_type post_supply = h2_issue_sat_add(
         _creates_reserve ? share_type( 0 ) : _reserve->stable_supply, op.stable_amount );
   FC_ASSERT( h2_issue_meets_rmin( post_bts, post_supply, *price,
                                   GRAPHENE_H2_ISSUE_RMIN_BPS ),
              "Post-mint reserve ratio breaks the rmin floor (${r}bps); "
              "over-collateralize or reduce the request",
              ("r", GRAPHENE_H2_ISSUE_RMIN_BPS) );
   // Supply headroom (asset_issue precedent): consensus never mints past max.
   {
      const auto& pair_dyn = pair_asset->dynamic_asset_data_id( d );
      FC_ASSERT( ( pair_dyn.current_supply + op.stable_amount ) <= pair_asset->options.max_supply,
                 "Mint exceeds the pair asset's maximum supply" );
   }

   // Per-block door cap (load-bearing, R2 audit): mint deposits plus
   // redeem payouts per pair per block, in BTS base units, must not exceed
   // $2,000 pilot-basis. Head-block-number-keyed reset: a reserve stamped
   // for an older block opens at zero. 256-bit compare, no floats.
   {
      const uint256_t used = uint256_t( uint64_t( h2_issue_door_used(
            _reserve, head_block ).value ) );
      const uint256_t leg = uint256_t( uint64_t( op.deposit.amount.value ) );
      FC_ASSERT( used + leg <= uint256_t( GRAPHENE_H2_ISSUE_DOOR_CAP_BTS ),
                 "Per-block door conversion cap exceeded for this pair; "
                 "retry next block" );
   }

   // FXR junior mint (minimal shippable): only the deposit's surplus
   // contribution above the target prices junior coin. contrib is the rise
   // in above-target surplus this deposit creates (pre-existing surplus
   // never mints to newcomers: its holders already own it). At-par mints
   // weakly REDUCE surplus (adding ~1:1 value-to-face against a >100%
   // target), so they mint no FXR; over-collateralized deposits (and the
   // fee slice inside every deposit) lift it and mint. FXR_price is the
   // pre-mint surplus per FXR (floored; genesis parity 1:1); a floored-0
   // price mints nothing (fail-closed, never divide-by-zero). Cap: the
   // fee slice already sits inside the door-counted deposit, so the FXR
   // leg rides the same door cap by construction.
   _fxr_to_mint = share_type( 0 );
   {
      const share_type r_before = _creates_reserve ? share_type( 0 ) : _reserve->bts_balance;
      const share_type s_before = _creates_reserve ? share_type( 0 ) : _reserve->stable_supply;
      const share_type fxr_supply_before =
            _creates_reserve ? share_type( 0 ) : _reserve->fxr_supply;
      const uint256_t surplus_pre = h2_issue_surplus_face(
            r_before, s_before, *price, GRAPHENE_H2_ISSUE_TARGET_BPS );
      const uint256_t surplus_new = h2_issue_surplus_face(
            post_bts, post_supply, *price, GRAPHENE_H2_ISSUE_TARGET_BPS );
      if( surplus_new > surplus_pre )
      {
         const uint256_t contrib = surplus_new - surplus_pre;
         uint256_t fxr_price = uint256_t( GRAPHENE_H2_ISSUE_FXR_GENESIS_PARITY );
         if( fxr_supply_before > share_type( 0 ) )
            fxr_price = surplus_pre / uint256_t( uint64_t( fxr_supply_before.value ) );
         if( fxr_price > uint256_t( 0 ) )
         {
            const uint256_t fxr = contrib / fxr_price;
            if( fxr > uint256_t( 0 ) )
            {
               FC_ASSERT( fxr <= uint256_t( uint64_t( GRAPHENE_MAX_SHARE_SUPPLY ) ),
                          "FXR mint exceeds maximum share supply" );
               const share_type fxr_mint = share_type( int64_t( uint64_t( fxr ) ) );
               const auto& fxr_dyn = fxr_asset->dynamic_asset_data_id( d );
               FC_ASSERT( ( fxr_dyn.current_supply + fxr_mint ) <= fxr_asset->options.max_supply,
                          "FXR mint exceeds the junior asset's maximum supply" );
               _fxr_to_mint = fxr_mint;
            }
         }
      }
   }

   // No reflexive mint between legs: this evaluator issues stable/FXR
   // balances only (never a nested redeem, never a nested mint); the
   // redeem evaluator burns stable only (never mints). The only shared
   // path is the bonded read above. Structural, asserted here in prose
   // and pinned by the round-trip accounting test.
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

object_id_type hybrid_mint_evaluator::do_apply( const hybrid_mint_operation& op )
{ try {
   database& d = db();
   const uint32_t head_block = d.head_block_num();
   const asset_id_type core = asset_id_type();

   d.adjust_balance( op.minter, -asset( op.deposit.amount, core ) );

   const share_type fxr = _fxr_to_mint;
   const protocol::oracle_value snap_price = _price;
   const reserve_object* reserve = nullptr;
   if( _creates_reserve )
   {
      const auto& created = d.create<reserve_object>(
            [&]( reserve_object& r ) {
         r.pair          = _vault->vault_pair;
         r.fxr_asset     = op.fxr_asset;
         r.bts_balance   = op.deposit.amount;
         r.stable_supply = op.stable_amount;
         r.fxr_supply    = fxr;
         r.door_used_bts = op.deposit.amount;
         r.door_block    = head_block;
      } );
      reserve = &created;
   }
   else
   {
      d.modify( *_reserve, [&]( reserve_object& r ) {
         r.bts_balance += op.deposit.amount;
         r.stable_supply += op.stable_amount;
         r.fxr_supply += fxr;
         if( r.door_block != head_block )
         {
            r.door_block = head_block;
            r.door_used_bts = op.deposit.amount;
         }
         else
            r.door_used_bts += op.deposit.amount;
      } );
      reserve = _reserve;
   }
   // Coverage snapshot (face terms, saturating bps): every door conversion
   // re-stamps what the rmin gate just proved, so explorers read backing
   // without replaying conversions.
   d.modify( *reserve, [&]( reserve_object& r ) {
      r.last_ratio_bps = h2_issue_coverage_bps(
            h2_issue_bts_to_face( r.bts_balance, snap_price ), r.stable_supply );
      r.snapshot_block = head_block;
   } );

   d.adjust_balance( op.minter, asset( op.stable_amount, _vault->vault_pair ) );
   {
      const asset_object& pair_asset = _vault->vault_pair( d );
      const auto& pair_dyn = pair_asset.dynamic_asset_data_id( d );
      d.modify( pair_dyn, [&op]( asset_dynamic_data_object& data ) {
         data.current_supply += op.stable_amount;
      } );
   }
   if( fxr > share_type( 0 ) )
   {
      d.adjust_balance( op.minter, asset( fxr, op.fxr_asset ) );
      const asset_object& fxr_asset = op.fxr_asset( d );
      const auto& fxr_dyn = fxr_asset.dynamic_asset_data_id( d );
      d.modify( fxr_dyn, [&fxr]( asset_dynamic_data_object& data ) {
         data.current_supply += fxr;
      } );
   }
   d.modify( *_vault, [&op]( vault_object& v ) {
      v.outstanding += op.stable_amount;
   } );
   return object_id_type( reserve->id );
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result hybrid_redeem_evaluator::do_evaluate( const hybrid_redeem_operation& op )
{ try {
   database& d = db();
   const time_point_sec now = d.head_block_time();
   const uint32_t head_block = d.head_block_num();

   // Price leg (H2e): the payout values through bonded prices, symmetric
   // with mint. Ordering asserted inside.
   h2_require_price_leg( now );

   _vault = d.find( op.vault );
   FC_ASSERT( nullptr != _vault, "Vault ${v} does not exist", ("v", op.vault) );
   FC_ASSERT( _vault->maintenance_state != GRAPHENE_H2_VAULT_WINDDOWN,
              "Vault is wound down; exits go through wind-down claims, never redeems" );
   // Exits continue through a held door (H2c top-up precedent: frozen
   // blocks mints, redemptions continue pro-rata). Only the tripwire's
   // stage-3 redemptions latch and terminal wind-down shut this path.
   FC_ASSERT( !h2_redemptions_halted( d, _vault->vault_pair ),
              "Redemptions for this pair are held shut by the tripwire" );
   _reserve = h2_find_reserve( d, _vault->vault_pair );
   FC_ASSERT( nullptr != _reserve,
              "Pair carries no issuance reserve; nothing to redeem" );

   FC_ASSERT( op.burn.asset_id == _vault->vault_pair,
              "Redeem burns the vault's senior stable, never another asset" );
   FC_ASSERT( op.burn.amount <= _reserve->stable_supply,
              "Redeem burns more stable than the reserve issued" );
   FC_ASSERT( op.burn.amount <= _vault->outstanding,
              "Redeem burns more stable than the vault's outstanding" );
   FC_ASSERT( nullptr != d.find( op.redeemer ),
              "Redeemer account ${a} does not exist", ("a", op.redeemer) );
   FC_ASSERT( d.get_balance( op.redeemer, _vault->vault_pair ).amount >= op.burn.amount,
              "Redeemer holds insufficient stable for the burn" );

   // Same bonded read as mint (X-01 reuse): dual-stale refuses conversion-
   // dependent exits rather than paying on a dead price (wind-down-claim
   // precedent).
   const auto price = h2_read_pair_price( d, *_vault, 0, now );
   FC_ASSERT( price.valid(),
              "No bonded live price for this pair; conversion exits halt" );
   FC_ASSERT( price->base_amount > share_type( 0 ) && price->quote_amount > share_type( 0 ),
              "Degenerate bonded price; redeems refused" );

    // Payout (declared round-DOWN against the redeemer twice over: the
    // conversion floors, then the 30bps conversion fee withholds -- both
    // favor the protocol, and a full mint/redeem cycle costs the fee on
    // both legs while coverage rises). The withheld slice never leaves the
    // reserve: it is simply not subtracted below, so fee routing needs no
    // account and no map. Dust that pays nothing -- including a gross the
    // fee eats whole -- is refused, never vested.
    const share_type gross = h2_issue_face_to_bts( op.burn.amount, *price );
    _payout = gross - h2_issue_fee_slice( gross );
    FC_ASSERT( _payout > share_type( 0 ),
               "Dust redeems that pay nothing are refused" );
    FC_ASSERT( _payout <= _reserve->bts_balance,
               "Reserve cannot cover the payout; shortfall exits go through wind-down" );

    // rmin floor on the remainder (same constant as mint: one floor, both
    // doors). The retained fee slice stays in the remainder, strengthening
    // it. Partial redeems must leave the book above the floor; an exact
    // full-book exit (burning the entire outstanding, which mirrors the
    // reserve supply across every door conversion) bypasses it -- nothing
    // remains to secure, and any FXR surplus stays for juniors. A burn that
    // equals the supply while the mirrors drift is refused fail-closed
    // (unreachable through the door ops, which move both together).
    if( op.burn.amount < _reserve->stable_supply )
       FC_ASSERT( h2_issue_meets_rmin( _reserve->bts_balance - _payout,
                                       _reserve->stable_supply - op.burn.amount,
                                       *price, GRAPHENE_H2_ISSUE_RMIN_BPS ),
                  "Post-redeem reserve ratio breaks the rmin floor (${r}bps); "
                  "exit the remainder through wind-down",
                  ("r", GRAPHENE_H2_ISSUE_RMIN_BPS) );
    else
       FC_ASSERT( _reserve->stable_supply == _vault->outstanding,
                  "Full-book exits burn the entire outstanding; mirror drift refused" );

    // Door cap, same counter as mint (mint deposits plus redeem payouts per
    // block, BTS base units, head-block-number-keyed reset). The redeem leg
    // counts the NET payout -- the BTS that actually leaves the reserve;
    // the withheld fee never moves, so it consumes no door.
   {
      const uint256_t used = uint256_t( uint64_t( h2_issue_door_used(
            _reserve, head_block ).value ) );
      const uint256_t leg = uint256_t( uint64_t( _payout.value ) );
      FC_ASSERT( used + leg <= uint256_t( GRAPHENE_H2_ISSUE_DOOR_CAP_BTS ),
                 "Per-block door conversion cap exceeded for this pair; "
                 "retry next block" );
   }
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

object_id_type hybrid_redeem_evaluator::do_apply( const hybrid_redeem_operation& op ) const
{ try {
   database& d = db();
   const time_point_sec now = d.head_block_time();
   const uint32_t head_block = d.head_block_num();
   const asset_id_type core = asset_id_type();

   // Burn the senior: supply and outstanding fall together (the mirror
   // invariant the round-trip test pins: stable_supply == outstanding
   // across every door conversion).
   d.adjust_balance( op.redeemer, -asset( op.burn.amount, _vault->vault_pair ) );
   {
      const asset_object& pair_asset = _vault->vault_pair( d );
      const auto& pair_dyn = pair_asset.dynamic_asset_data_id( d );
      d.modify( pair_dyn, [&op]( asset_dynamic_data_object& data ) {
         data.current_supply -= op.burn.amount;
      } );
   }
   d.modify( *_vault, [&op]( vault_object& v ) {
      v.outstanding -= op.burn.amount;
   } );

   // Reserve pays into vesting escrow: BTS leaves the reserve the same
   // block the liability burns. Unvested outputs are escrow, never
   // capitalization -- no supply credit anywhere for them (BTS supply is
   // unchanged: still-counted funds move reserve -> escrow, wind-down
   // seizure precedent). On halt the escrow simply vests out under normal
   // vesting rules: no REVERT-vs-ABSORB transition exists in this phase
   // (ISSUANCE-2), so there is nothing to rebook -- that absence is the
   // property the brief pins.
   d.modify( *_reserve, [&]( reserve_object& r ) {
      r.bts_balance -= _payout;
      r.stable_supply -= op.burn.amount;
      if( r.door_block != head_block )
      {
         r.door_block = head_block;
         r.door_used_bts = _payout;
      }
      else
         r.door_used_bts += _payout;
   } );
   const auto& escrow = d.create<vesting_balance_object>(
         [&]( vesting_balance_object& o ) {
      o.owner = op.redeemer;
      o.balance = asset( _payout, core );
      linear_vesting_policy policy;
      policy.begin_timestamp = now;
      policy.vesting_cliff_seconds = 0;
      policy.vesting_duration_seconds = GRAPHENE_H2_ISSUE_REDEEM_VEST_SEC;
      policy.begin_balance = _payout;
      o.policy = policy;
   } );
   // Re-stamp the snapshot the gate just proved (post-payout book).
   {
      const auto price = h2_read_pair_price( d, *_vault, 0, now );
      FC_ASSERT( price.valid(), "Bonded price leg vanished inside redeem apply" );
      d.modify( *_reserve, [&]( reserve_object& r ) {
         r.last_ratio_bps = h2_issue_coverage_bps(
               h2_issue_bts_to_face( r.bts_balance, *price ), r.stable_supply );
         r.snapshot_block = head_block;
      } );
   }
   return object_id_type( escrow.id );
} FC_CAPTURE_AND_RETHROW( (op) ) }

} } // graphene::chain

FC_REFLECT_DERIVED_NO_TYPENAME( graphene::chain::reserve_object, (graphene::db::object),
                    (pair)
                    (fxr_asset)
                    (bts_balance)
                    (stable_supply)
                    (fxr_supply)
                    (last_ratio_bps)
                    (snapshot_block)
                    (door_used_bts)
                    (door_block)
                  )

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::chain::reserve_object )
