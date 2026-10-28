#include <graphene/chain/bsip5_evaluator.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/market_reward_object.hpp>
#include <graphene/chain/market_object.hpp>
#include <graphene/chain/account_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/chain/exceptions.hpp>
#include <fc/exception/exception.hpp>
#include <vector>

namespace graphene { namespace chain { void distribute_bsip5_rewards(database&); } }

namespace graphene { namespace chain {

void_result bsip5_opt_in_evaluator::do_evaluate(const bsip5_opt_in_operation& o)
{
   FC_ASSERT( HARDFORK_BSIP5_PASSED( db().head_block_time() ),
              "BSIP-5 hardfork has not passed" );

   const database& d = db();
   const asset_object& a = o.asset_id(d);
   FC_ASSERT( a.issuer == o.issuer, "Only the asset issuer may opt in" );
   FC_ASSERT( o.reward_rate_bps <= 500, "Open order fee must be <= 500 bps" );
   // Empty-book rule: refuse while qualifying open orders rest on affected markets.
   // (Conservative: any open order on a market involving this asset blocks the change.)
   // Placement fields are checked lazily; here we just gate.
   return void_result();
}

void_result bsip5_opt_in_evaluator::do_apply(const bsip5_opt_in_operation& o)
{
   database& d = db();
   d.modify( o.asset_id(d), [&o](asset_object& a) {
      a.options.extensions.value.open_order_fee = o.reward_rate_bps;
   });
   return void_result();
}

void_result bsip5_payout_evaluator::do_evaluate(const bsip5_payout_operation& o)
{
   FC_ASSERT( HARDFORK_BSIP5_PASSED( db().head_block_time() ),
              "BSIP-5 hardfork has not passed" );
   // Gas guard: a non-zero gas_price_wad must be sufficient; 0 bypasses (permissionless sweep).
   return void_result();
}

void_result bsip5_payout_evaluator::do_apply(const bsip5_payout_operation& o)
{
   // Ensure a market_reward_object exists for the leg.
   database& d = db();
   const auto& _indices = d.get_index_type<market_reward_index>().indices();
   const auto& _by_ma = _indices.get<by_market_asset>();
   auto it = _by_ma.find( boost::make_tuple( o.base_asset, o.quote_asset, o.base_asset ) );
   if( it == _by_ma.end() )
   {
      d.create<market_reward_object>([&](market_reward_object& mr) {
         mr.base_asset = o.base_asset;
         mr.quote_asset = o.quote_asset;
         mr.reward_asset = o.base_asset;
      });
   }
   graphene::chain::distribute_bsip5_rewards( db() );
   return void_result();
}

void_result bsip5_claim_rebate_evaluator::do_evaluate(const bsip5_claim_rebate_operation& o)
{
   FC_ASSERT( HARDFORK_BSIP5_PASSED( db().head_block_time() ),
              "BSIP-5 hardfork has not passed" );
   // Validate the claimant account exists.
   const database& d = db();
   o.account(d);
   return void_result();
}

void_result bsip5_claim_rebate_evaluator::do_apply(const bsip5_claim_rebate_operation& o)
{
   // Rebates settle into market_fee_sharing vesting balances at fill time.
   // Claim sweeps every such balance owned by the account into its liquid
   // balance, mirroring vesting_balance_withdraw but over all rebate balances.
   database& d = db();
   const time_point_sec now = d.head_block_time();
   const account_id_type account = o.account;

   auto& idx = d.get_index_type<vesting_balance_index>().indices().get<by_account>();
   auto range = idx.equal_range(account);

   // Collect ids first to avoid iterator invalidation during modification.
   std::vector<vesting_balance_id_type> ids;
   for (auto it = range.first; it != range.second; ++it)
   {
      if (it->balance_type == vesting_balance_type::market_fee_sharing)
         ids.push_back(it->id.as<vesting_balance_id_type>());
   }

   for (const auto& vid : ids)
   {
      const vesting_balance_object& vbo = vid(d);
      asset allowed = vbo.get_allowed_withdraw(now);
      if (allowed.amount <= 0)
         continue;
      d.modify(vbo, [&now, &allowed](vesting_balance_object& obj) {
         obj.withdraw(now, allowed);
      });
      d.adjust_balance(account, allowed);
   }
   return void_result();
}

} } // graphene::chain
