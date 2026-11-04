#include <cstdint>
#include <graphene/chain/pamm_evaluator.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/hardfork_visitor.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/chain/liquidity_pool_object.hpp>
#include <graphene/protocol/types.hpp>

namespace graphene { namespace chain {

static bool pool_has_recent_swap( const database& d, asset_id_type asset_a, asset_id_type asset_b )
{
   const auto& pool_idx = d.get_index_type<liquidity_pool_index>();
   auto itr = pool_idx.indices().get<by_asset_a>().find( boost::make_tuple( asset_a, object_id_type() ) );
   return itr != pool_idx.indices().get<by_asset_a>().end() && itr->asset_b == asset_b;
}

static bool pool_has_min_tvl( const database& d, asset_id_type asset_a, asset_id_type asset_b )
{
   const auto& pool_idx = d.get_index_type<liquidity_pool_index>();
   auto itr = pool_idx.indices().get<by_asset_a>().find( boost::make_tuple( asset_a, object_id_type() ) );
   if (itr != pool_idx.indices().get<by_asset_a>().end() && itr->asset_a == asset_a && itr->asset_b == asset_id_type())
      return itr->balance_b.value >= share_type(1000000 * GRAPHENE_BLOCKCHAIN_PRECISION);
   return false;
}

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
   FC_ASSERT( op.fee_pool_balance >= 0, "fee_pool_balance must be non-negative" );

   const asset_object& share_asset_obj = op.share_asset(d);
   FC_ASSERT( op.pool_asset != op.share_asset, "pool_asset and share_asset must differ" );
   FC_ASSERT( !share_asset_obj.is_market_issued(), "share_asset must be a UIA" );
   FC_ASSERT( share_asset_obj.issuer == op.manager,
              "share_asset issuer must be the PAMM manager (P8-02: only issuer may mint/burn)" );
   FC_ASSERT( share_asset_obj.dynamic_asset_data_id(d).current_supply.value == 0,
              "share_asset current_supply must be zero" );
   FC_ASSERT( share_asset_obj.options.max_supply.value > 0,
              "share_asset max_supply must be positive" );

   FC_ASSERT( pool_has_recent_swap( d, op.pool_asset, asset_id_type() ),
              "pool_asset must have a live BTS price with a swap in the past 24 hours" );
   FC_ASSERT( pool_has_min_tvl( d, op.pool_asset, asset_id_type() ),
              "pool_asset pool must have >= 1,000,000 BTS total value" );

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
      o.share_supply = 1;
      o.fee_pool_balance = op.fee_pool_balance;
      o.last_withdrawal_time = d.head_block_time();
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
   FC_ASSERT( _pool->fee_pool_balance.value >= op.fee.amount.value,
              "fee pool balance insufficient" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

generic_operation_result pamm_deposit_evaluator::do_apply(const pamm_deposit_operation& op)
{ try {
   database& d = db();
   generic_operation_result result;
   const pamm_pool_object& pool_obj = op.pool(d);

   d.modify( pool_obj, [&](pamm_pool_object& p){
      p.fee_pool_balance -= op.fee.amount;
   });

   d.adjust_balance( op.investor, -op.amount );

   share_type shares_to_mint;
   {
      const pamm_pool_object& o = pool_obj;
      if (o.share_supply == 1) {
         shares_to_mint = (share_type)op.amount.amount.value;
      } else {
         FC_ASSERT( o.tank_balance.value > 0, "pool tank empty" );
         fc::uint128_t shares = fc::uint128_t(op.amount.amount.value) * o.share_supply.value / o.tank_balance.value;
         shares_to_mint = (share_type)shares;
         FC_ASSERT( shares_to_mint.value > 0, "zero shares minted" );
      }
   }

   const asset_object& share_asset_obj = pool_obj.share_asset(d);
   d.modify( share_asset_obj.dynamic_data(d), [&shares_to_mint](asset_dynamic_data_object& dd){
      dd.current_supply += shares_to_mint;
   });
   d.adjust_balance( op.investor, asset(shares_to_mint, pool_obj.share_asset) );

   d.modify( pool_obj, [&](pamm_pool_object& o){
      o.share_supply += shares_to_mint;
      o.tank_balance += op.amount.amount;
   });

   result.updated_objects.insert(object_id_type(op.pool));
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
   FC_ASSERT( d.head_block_time() >= _pool->last_withdrawal_time + fc::seconds(_pool->delay_seconds),
              "withdrawal delay not elapsed (P8-01)" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

generic_operation_result pamm_withdraw_evaluator::do_apply(const pamm_withdraw_operation& op)
{ try {
   database& d = db();
   generic_operation_result result;
   const pamm_pool_object& pool_obj = op.pool(d);

   d.modify( pool_obj, [&](pamm_pool_object& p){
      p.fee_pool_balance -= op.fee.amount;
   });

   share_type amt_to_pay;
   {
      const pamm_pool_object& o = pool_obj;
      FC_ASSERT( o.share_supply.value > 0, "no shares outstanding" );
      FC_ASSERT( op.share_amount.amount <= o.share_supply, "insufficient shares" );
      fc::uint128_t amt = fc::uint128_t(op.share_amount.amount.value) * o.tank_balance.value / o.share_supply.value;
      FC_ASSERT( amt <= (fc::uint128_t)o.tank_balance.value, "payout exceeds tank" );
      amt_to_pay = (share_type)amt;
      FC_ASSERT( amt_to_pay.value > 0, "zero payout" );
      FC_ASSERT( o.tank_balance.value - amt_to_pay.value >= o.min_tank_level.value,
                 "withdrawal would breach min_tank_level (P8-01)" );
   }

   d.adjust_balance( op.investor, -op.share_amount );

   const asset_object& share_asset_obj = pool_obj.share_asset(d);
   d.modify( share_asset_obj.dynamic_data(d), [&op](asset_dynamic_data_object& dd){
      dd.current_supply -= op.share_amount.amount;
   });

   d.adjust_balance( op.investor, asset(amt_to_pay, pool_obj.pool_asset) );

   d.modify( pool_obj, [&](pamm_pool_object& o){
      o.share_supply -= op.share_amount.amount;
      o.tank_balance -= amt_to_pay;
      o.last_withdrawal_time = d.head_block_time();
   });

   result.updated_objects.insert(object_id_type(op.pool));
   return result;
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result pamm_snapshot_evaluator::do_evaluate(const pamm_snapshot_operation& op)
{ try {
   const database& d = db();
   FC_ASSERT( HARDFORK_PAMM_PASSED( d.head_block_time() ), "BSIP-8 hardfork has not passed" );
   _pool = &op.pool(d);
   FC_ASSERT( op.nav_den > 0, "nav_den must be positive" );
   FC_ASSERT( op.caller == _pool->manager, "snapshot caller must be pool manager (P8-07)" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

generic_operation_result pamm_snapshot_evaluator::do_apply(const pamm_snapshot_operation& op)
{ try {
   database& d = db();
   generic_operation_result result;
   const pamm_pool_object& pool_obj = op.pool(d);

   d.modify( pool_obj, [&](pamm_pool_object& p){
      p.fee_pool_balance -= op.fee.amount;
   });

   d.modify( pool_obj, [&](pamm_pool_object& o){
      pamm_pool_object::nav_entry e;
      e.day = (uint32_t)(d.head_block_time().sec_since_epoch() / 86400);
      e.nav_num = op.nav_num;
      e.nav_den = op.nav_den;
      for (const auto& x : o.nav_history) {
         FC_ASSERT( x.day != e.day, "same-day snapshot already exists; refused (P8-07)" );
      }
      o.nav_history.push_back(e);
      if (o.nav_history.size() > 365) o.nav_history.erase(o.nav_history.begin());
      if (o.high_water_mark == 0 || (fc::uint128_t)op.nav_num * o.high_water_mark > (fc::uint128_t)op.nav_den * 1) {
         o.high_water_mark = op.nav_num;
      }
      if (o.high_water_mark > 0) {
         fc::uint128_t equity = (fc::uint128_t)op.nav_num * o.tank_balance.value / op.nav_den;
         fc::uint128_t hwm = (fc::uint128_t)o.high_water_mark * o.tank_balance.value / op.nav_den;
         if (equity > hwm) {
            fc::uint128_t profit = equity - hwm;
            fc::uint128_t fee = profit * o.fee_rate_bps / 10000;
            o.fee_pool_balance += (share_type)fee;
         }
      }
   });

   result.updated_objects.insert(object_id_type(op.pool));
   return result;
} FC_CAPTURE_AND_RETHROW( (op) ) }

} } // graphene::chain
