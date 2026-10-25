#include <graphene/chain/oracle_substrate.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/chain/types.hpp>
#include <graphene/protocol/h2_economics.hpp>

#include <boost/multiprecision/cpp_int.hpp>

namespace graphene { namespace chain {

const guard_state_object* h2_find_guard( const database& d, oracle_id_type oid )
{
   const auto& idx = d.get_index_type<guard_state_index>().indices().get<by_guard_oracle>();
   const auto itr = idx.find( oid );
   return itr == idx.end() ? nullptr : &*itr;
}

bool h2_oracle_has_bonded_live_set( const database& d, const oracle_object& oracle,
                                    time_point_sec now )
{
   const auto& bond_idx = d.get_index_type<producer_bond_index>()
                             .indices().get<by_oracle_producer>();
   size_t scanned = 0;
   for( auto bitr = bond_idx.lower_bound( boost::make_tuple( oracle_id_type( oracle.id ) ) );
         bitr != bond_idx.end() && bitr->oracle == oracle.id; ++bitr )
   {
      if( ++scanned > GRAPHENE_ORACLE_MAX_PRODUCERS )
         break;
      if( bitr->slashed )
         continue;
      const auto pitr = oracle.options.producers.find( bitr->producer );
      if( pitr == oracle.options.producers.end() )
         continue;
      if( pitr->second.weight == 0 )
         continue;
      if( bitr->bond_amount <= share_type( 0 ) || now >= bitr->unlock_time )
         continue;
      const vesting_balance_object* vb = d.find( bitr->vesting_balance );
      if( vb == nullptr || vb->balance.asset_id != asset_id_type()
          || vb->balance.amount < bitr->bond_amount )
         continue;
      const auto sitr = oracle.submissions.find( bitr->producer );
      const auto fitr = oracle.foreign_submissions.find( bitr->producer );
      const bool price_live = ( sitr != oracle.submissions.end()
                                && oracle.is_submission_live( sitr->second.first, now ) );
      const bool foreign_live = ( fitr != oracle.foreign_submissions.end()
                                  && oracle.is_submission_live( fitr->second.first, now ) );
      if( !price_live && !foreign_live )
         continue;
      return true;
   }
   return false;
}

bool h2_oracle_has_any_bond( const database& d, const oracle_object& oracle )
{
   const auto& bond_idx = d.get_index_type<producer_bond_index>()
                            .indices().get<by_oracle_producer>();
   for( auto bitr = bond_idx.lower_bound( boost::make_tuple( oracle_id_type( oracle.id ) ) );
         bitr != bond_idx.end() && bitr->oracle == oracle.id; ++bitr )
   {
      if( bitr->slashed )
         continue;
      if( bitr->bond_amount <= share_type( 0 ) )
         continue;
      return true;
   }
   return false;
}

} } // graphene::chain
