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
   result.updated_objects.insert(_pool->id);
   d.modify( *_pool, [&](pamm_pool_object& o){
      // mint shares at current NAV: 1:1 on first deposit
      if (o.share_supply == 0) {
         o.share_supply = (share_type)op.amount.amount.value;
      } else {
         // shares = amount * share_supply / tank_balance
         fc::uint128_t shares = fc::uint128_t(op.amount.amount.value) * o.share_supply.value / o.tank_balance.value;
         o.share_supply += (share_type)shares;
      }
      o.tank_balance += op.amount.amount;
   });
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
   result.updated_objects.insert(_pool->id);
   d.modify( *_pool, [&](pamm_pool_object& o){
      // amount = shares * tank_balance / share_supply
      fc::uint128_t amt = fc::uint128_t(op.share_amount.amount.value) * o.tank_balance.value / o.share_supply.value;
      o.share_supply -= op.share_amount.amount;
      o.tank_balance -= (share_type)amt;
      
   });
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