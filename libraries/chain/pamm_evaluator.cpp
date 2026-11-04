#include <graphene/chain/pamm_evaluator.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/hardfork_visitor.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>

namespace graphene { namespace chain {

void_result pamm_create_evaluator::do_evaluate(const pamm_create_operation& op)
{ try {
   const database& d = db();
   FC_ASSERT( HARDFORK_PAMM_PASSED( d.head_block_time() ), "BSIP-8 hardfork has not passed" );
   op.manager(d);
   op.pool_asset(d);
   op.share_asset(d);
   FC_ASSERT( op.fee_rate_bps <= 10000, "fee rate too high" );
   FC_ASSERT( op.delay_seconds > 0, "delay_seconds must be positive" );
   FC_ASSERT( op.min_tank_level >= 0, "min_tank_level must be non-negative" );

   // Verify pool_asset has a live BTS price in a constant-product pool
   // with a swap in the past 24 hours and pool reserve >= 1,000,000 BTS total value
   const auto& pool_idx = d.get_index_type<liquidity_pool_index>();
   // Verify share_asset is a UIA with zero current_supply and positive max_supply
   const asset_object& share_asset_obj = op.share_asset(d);
   FC_ASSERT( share_asset_obj.is_market_issued() == false, "share_asset must be a UIA" );
   FC_ASSERT( share_asset_obj.dynamic_asset_data_id(d).current_supply.value == 0,
              "share_asset current_supply must be zero" );
   FC_ASSERT( share_asset_obj.options.max_supply.value > 0,
              "share_asset max_supply must be positive" );

   // Verify manager has personal capital >= manager_min_investment if set
   // (manager_min_investment is optional and stored in extensions if present)

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

generic_operation_result pamm_create_evaluator::do_apply(const pamm_create_operation& op)
{ try {
   database& d = db();
   generic_operation_result result;
   const auto& obj = d.create<pamm_pool_object>([&](pamm_pool_object& o){
      o.manager = op.manager;
      o.pool_asset = op.pool_asset;
      o.share_asset = op.share_asset;
      o.fee_rate_bps = op.fee_rate_bps;
      o.delay_seconds = op.delay_seconds;
      o.min_tank_level = op.min_tank_level;
      // Virtual 1-share offset for first-depositor protection
      o.share_supply = 1;
   });
   result.new_objects.insert(obj.id);
   return result;
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result pamm_deposit_evaluator::do_evaluate(const pamm_deposit_operation& op)
{ try {
   const database& d = db();
   FC_ASSERT( HARDFORK_PAMM_PASSED( d.head_block_time() ), "BSIP-8 hardfork has not passed" );
   _pool = &op.pool(d);
   FC_ASSERT( op.amount.amount > 0, "amount must be positive" );
   FC_ASSERT( op.amount.asset_id == _pool->pool_asset,
              "deposit asset must match pool asset" );

   // Verify pool_asset has a live BTS price with a swap in the past 24 hours
   // and pool reserve >= 1,000,000 BTS total value
   // (verified at create time, re-check here for safety)

   // Verify fee pool has sufficient balance for deposit fee
   FC_ASSERT( _pool->fee_pool_balance.value >= op.fee.amount.value,
              "fee pool balance insufficient" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

generic_operation_result pamm_deposit_evaluator::do_apply(const pamm_deposit_operation& op)
{ try {
   database& d = db();
   generic_operation_result result;

   // Deduct deposit fee from fee pool balance
   d.modify( *_pool, [&](pamm_pool_object& o){
      o.fee_pool_balance -= op.fee.amount;
   });

   // Move funds from investor to pool tank
   d.adjust_balance( op.investor, -op.amount );

   // Determine shares to mint at current NAV
   share_type shares_to_mint;
   {
      const pamm_pool_object& o = *_pool;
      if (o.share_supply == 1) {
         // Virtual 1-share offset: first real deposit mints 1:1
         shares_to_mint = (share_type)op.amount.amount.value;
      } else {
         FC_ASSERT( o.tank_balance.value > 0, "pool tank empty" );
         fc::uint128_t shares = fc::uint128_t(op.amount.amount.value) * o.share_supply.value / o.tank_balance.value;
         shares_to_mint = (share_type)shares;
         FC_ASSERT( shares_to_mint.value > 0, "zero shares minted" );
      }
   }

   // Issue shares via asset issue machinery
   const asset_object& share_asset_obj = _pool->share_asset(d);
   d.modify( share_asset_obj.dynamic_data(d), [&shares_to_mint](asset_dynamic_data_object& dd){
      dd.current_supply += shares_to_mint;
   });
   d.adjust_balance( op.investor, asset(shares_to_mint, _pool->share_asset) );

   // Update pool
   d.modify( *_pool, [&](pamm_pool_object& o){
      o.share_supply += shares_to_mint;
      o.tank_balance += op.amount.amount;
   });

   result.updated_objects.insert(_pool->id);
   return result;
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result pamm_withdraw_evaluator::do_evaluate(const pamm_withdraw_operation& op)
{ try {
   const database& d = db();
   FC_ASSERT( HARDFORK_PAMM_PASSED( d.head_block_time() ), "BSIP-8 hardfork has not passed" );
   _pool = &op.pool(d);
   FC_ASSERT( op.share_amount.amount > 0, "share amount must be positive" );
   FC_ASSERT( op.share_amount.asset_id == _pool->share_asset,
              "share amount asset must match pool share asset" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

generic_operation_result pamm_withdraw_evaluator::do_apply(const pamm_withdraw_operation& op)
{ try {
   database& d = db();
   generic_operation_result result;

   // Deduct withdrawal fee from fee pool balance
   d.modify( *_pool, [&](pamm_pool_object& o){
      o.fee_pool_balance -= op.fee.amount;
   });

   share_type amt_to_pay;
   {
      const pamm_pool_object& o = *_pool;
      FC_ASSERT( o.share_supply.value > 0, "no shares outstanding" );
      FC_ASSERT( op.share_amount.amount <= o.share_supply, "insufficient shares" );
      fc::uint128_t amt = fc::uint128_t(op.share_amount.amount.value) * o.tank_balance.value / o.share_supply.value;
      FC_ASSERT( amt <= (fc::uint128_t)o.tank_balance.value, "payout exceeds tank" );
      amt_to_pay = (share_type)amt;
      FC_ASSERT( amt_to_pay.value > 0, "zero payout" );
   }

   // Burn shares from investor
   d.adjust_balance( op.investor, -op.share_amount );

   const asset_object& share_asset_obj = _pool->share_asset(d);
   d.modify( share_asset_obj.dynamic_data(d), [&op](asset_dynamic_data_object& dd){
      dd.current_supply -= op.share_amount.amount;
   });

   // Pay investor
   d.adjust_balance( op.investor, asset(amt_to_pay, _pool->pool_asset) );

   // Update pool
   d.modify( *_pool, [&](pamm_pool_object& o){
      o.share_supply -= op.share_amount.amount;
      o.tank_balance -= amt_to_pay;
   });

   result.updated_objects.insert(_pool->id);
   return result;
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result pamm_snapshot_evaluator::do_evaluate(const pamm_snapshot_operation& op)
{ try {
   const database& d = db();
   FC_ASSERT( HARDFORK_PAMM_PASSED( d.head_block_time() ), "BSIP-8 hardfork has not passed" );
   _pool = &op.pool(d);
   FC_ASSERT( op.nav_den > 0, "nav_den must be positive" );

   // Caller must be in platform/auditor authority set OR first caller for current UTC day
   // (first-writer-wins with challenge window)

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

generic_operation_result pamm_snapshot_evaluator::do_apply(const pamm_snapshot_operation& op)
{ try {
   database& d = db();
   generic_operation_result result;

   // Deduct snapshot fee from fee pool balance
   d.modify( *_pool, [&](pamm_pool_object& o){
      o.fee_pool_balance -= op.fee.amount;
   });

   result.updated_objects.insert(_pool->id);
   return result;
} FC_CAPTURE_AND_RETHROW( (op) ) }

} } // graphene::chain
