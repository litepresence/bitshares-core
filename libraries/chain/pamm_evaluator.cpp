#include <graphene/chain/pamm_evaluator.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/hardfork_visitor.hpp>

namespace graphene { namespace chain {

void_result pamm_create_evaluator::do_evaluate(const pamm_create_operation& op)
{ try {
   const database& d = db();
   FC_ASSERT( HARDFORK_PAMM_PASSED( d.head_block_time() ), "BSIP-8 hardfork has not passed" );
   op.manager(d);
   op.pool_asset(d);
   op.share_asset(d);
   FC_ASSERT( op.fee_rate_bps <= 10000, "fee rate too high" );
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
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

generic_operation_result pamm_deposit_evaluator::do_apply(const pamm_deposit_operation& op)
{ try {
   database& d = db();
   generic_operation_result result;
   // determine shares to mint first (read-only)
   share_type shares_to_mint;
   {
      const pamm_pool_object& o = *_pool;
      if (o.share_supply == 0) {
         shares_to_mint = (share_type)op.amount.amount.value;
      } else {
         FC_ASSERT( o.tank_balance.value > 0, "pool tank empty" );
         fc::uint128_t shares = fc::uint128_t(op.amount.amount.value) * o.share_supply.value / o.tank_balance.value;
         shares_to_mint = (share_type)shares;
      }
      FC_ASSERT( shares_to_mint.value > 0, "zero shares minted" );
   }
   // move funds
   d.adjust_balance( op.investor, -op.amount );
   // issue shares
   const asset_object& share_asset_obj = _pool->share_asset(d);
   d.modify( share_asset_obj.dynamic_data(d), [&shares_to_mint](asset_dynamic_data_object& dd){
      dd.current_supply += shares_to_mint;
   });
   d.adjust_balance( op.investor, asset(shares_to_mint, _pool->share_asset) );
   // update pool
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
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

generic_operation_result pamm_withdraw_evaluator::do_apply(const pamm_withdraw_operation& op)
{ try {
   database& d = db();
   generic_operation_result result;
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
   // burn shares from investor
   d.adjust_balance( op.investor, -op.share_amount );
   const asset_object& share_asset_obj = _pool->share_asset(d);
   d.modify( share_asset_obj.dynamic_data(d), [&op](asset_dynamic_data_object& dd){
      dd.current_supply -= op.share_amount.amount;
   });
   // pay investor
   d.adjust_balance( op.investor, asset(amt_to_pay, _pool->pool_asset) );
   // update pool
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
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

generic_operation_result pamm_snapshot_evaluator::do_apply(const pamm_snapshot_operation& op)
{ try {
   database& d = db();
   generic_operation_result result;
   result.updated_objects.insert(_pool->id);
   d.modify( *_pool, [&](pamm_pool_object& o){
      pamm_pool_object::nav_entry e;
      e.day = (uint32_t)(d.head_block_time().sec_since_epoch() / 86400);
      e.nav_num = op.nav_num;
      e.nav_den = op.nav_den;
      // replace if same day
      bool replaced = false;
      for (auto& x : o.nav_history) {
         if (x.day == e.day) { x = e; replaced = true; break; }
      }
      if (!replaced) {
         o.nav_history.push_back(e);
         if (o.nav_history.size() > 365) o.nav_history.erase(o.nav_history.begin());
      }
      // update high water mark
      if (o.high_water_mark == 0 || (fc::uint128_t)op.nav_num * o.high_water_mark > (fc::uint128_t)op.nav_den * 1) {
         // simplified: update HWM to nav_num/nav_den scaled
         o.high_water_mark = op.nav_num;
      }
   });
   return result;
} FC_CAPTURE_AND_RETHROW( (op) ) }

} } // graphene::chain