#pragma once
#include <graphene/chain/types.hpp>
#include <graphene/protocol/pamm.hpp>
#include <graphene/db/generic_index.hpp>
#include <boost/multi_index/composite_key.hpp>

namespace graphene { namespace chain {

class pamm_pool_object : public abstract_object<pamm_pool_object, protocol_ids, pamm_pool_object_type>
{
   public:
      account_id_type manager;
      asset_id_type   pool_asset;
      asset_id_type   share_asset;
      uint16_t        fee_rate_bps = 0;
      uint32_t        delay_seconds = 86400;
      share_type      min_tank_level = 0;
      share_type      tank_balance = 0;
      share_type      share_supply = 0;
      uint64_t        high_water_mark = 0; // NAV scaled 1e8

      struct nav_entry { uint32_t day; uint64_t nav_num; uint64_t nav_den; };
      std::vector<nav_entry> nav_history; // capped at 365
};

struct by_manager;

using pamm_pool_multi_index_type = multi_index_container<
   pamm_pool_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
      ordered_unique< tag<by_manager>,
         composite_key< pamm_pool_object,
            member< pamm_pool_object, account_id_type, &pamm_pool_object::manager >,
            member< object, object_id_type, &object::id >
         >
      >
   >
>;

using pamm_pool_index = generic_index<pamm_pool_object, pamm_pool_multi_index_type>;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::pamm_pool_object )

FC_REFLECT_TYPENAME( graphene::chain::pamm_pool_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::pamm_pool_object )