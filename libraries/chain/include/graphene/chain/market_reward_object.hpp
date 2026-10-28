#pragma once

#include <graphene/chain/types.hpp>
#include <graphene/db/generic_index.hpp>

#include <graphene/protocol/asset.hpp>

#include <boost/multi_index/composite_key.hpp>

namespace graphene { namespace chain {

using namespace graphene::db;

/**
 *  @brief Per-market, per-asset reward state for BSIP-5 open order rewards.
 *
 *  One object per participating market leg. Holds the provider pool accumulator
 *  (funded by fills), a rolling one-hour fill accumulator used as the
 *  proximity reference price, and sweep bookkeeping. Bounded: one object per
 *  participating market leg; pool accumulators are bounded by supply.
 *  @ingroup object
 */
class market_reward_object : public abstract_object<market_reward_object, protocol_ids, market_reward_object_type>
{
   public:
      asset_id_type   base_asset;          ///< market base asset
      asset_id_type   quote_asset;         ///< market quote asset
      asset_id_type   reward_asset;        ///< asset this pool is denominated in (one leg)

      share_type      pool_balance = 0;    ///< accrued provider pool, in reward_asset
      uint64_t        reference_price_wad = 0; ///< rolling 1h TWAP of fills (WAD), 0 = no data
      uint64_t        last_sweep_block = 0;    ///< last distribution block
      uint64_t        total_distributed = 0;  ///< lifetime distributed (audit)
};

struct by_market_asset;
struct by_market;

typedef multi_index_container<
   market_reward_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_market_asset>,
         composite_key< market_reward_object,
            member< market_reward_object, asset_id_type, &market_reward_object::base_asset >,
            member< market_reward_object, asset_id_type, &market_reward_object::quote_asset >,
            member< market_reward_object, asset_id_type, &market_reward_object::reward_asset >,
            member< object, object_id_type, &object::id>
         >
      >
   >
> market_reward_multi_index_type;

typedef generic_index<market_reward_object, market_reward_multi_index_type> market_reward_index;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::market_reward_object )

FC_REFLECT_DERIVED( graphene::chain::market_reward_object, (graphene::db::object),
                    (base_asset)(quote_asset)(reward_asset)(pool_balance)
                    (reference_price_wad)
                    (last_sweep_block)(total_distributed)
                  )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::market_reward_object )
