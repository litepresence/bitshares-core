// SPDX-License-Identifier: MIT
#pragma once

#include <graphene/chain/types.hpp>
#include <graphene/db/generic_index.hpp>

#include <graphene/protocol/asset.hpp>

#include <boost/multi_index/composite_key.hpp>

namespace graphene { namespace chain {

using namespace graphene::db;

class reciprocity_factory_object : public abstract_object<reciprocity_factory_object, protocol_ids, reciprocity_factory_object_type>
{
   public:
      // Fee destinations (hardcoded)
      account_id_type         committee_account;   ///< Founder fees go here (1.2.0)

      // Pool registry
      // P4-02 (Important, CODE): reciprocity_factory_object carried unbounded
      // growth vectors with no pool-count ceiling. Defends against unbounded
      // state bloat and denial of service through unrestricted pool creation.
      // Invariant: pool_count <= MAX_POOLS; pool_addresses, pool_token_counts
      // and pool_tokens each hold at most MAX_POOLS entries; known_tokens and
      // is_known each hold at most MAX_KNOWN_TOKENS entries.
      // Spec: docs/superpowers/specs/2026-10-25-bsip4-n-asset-pools-design.md §8
      static constexpr uint64_t MAX_POOLS = 1024;      ///< Consensus bound: maximum pools
      static constexpr uint64_t MAX_KNOWN_TOKENS = 8192; ///< Consensus bound: maximum distinct known tokens
      uint64_t                pool_count = 0;      ///< Total pools created (<= MAX_POOLS)
      bool                    genesis_enforced = true; ///< Require genesis tokens for first pool
      asset_id_type           genesis_1;           ///< First genesis token (BTS)
      asset_id_type           genesis_2;           ///< Second genesis token (CNY)
      asset_id_type           genesis_3;           ///< Third genesis token (EUR)

      // Known token registry (append-only, capped at MAX_KNOWN_TOKENS)
      vector<asset_id_type>   known_tokens;        ///< All tokens that have appeared in pools (<= MAX_KNOWN_TOKENS)
      flat_map<asset_id_type, bool> is_known;      ///< O(1) lookup: is this token known? (<= MAX_KNOWN_TOKENS)

      // Pool registry (each vector holds <= MAX_POOLS entries)
      vector<reciprocity_pool_id_type> pool_addresses;  ///< Pool object IDs (<= MAX_POOLS)
      vector<uint8_t>         pool_token_counts;   ///< Per-pool token count (<= MAX_POOLS)
      vector<vector<asset_id_type>> pool_tokens;   ///< Per-pool token lists (<= MAX_POOLS)

      // Fee accumulators (per token, aggregated across all pools)
      flat_map<asset_id_type, share_type> founder_fees; ///< Founder fee accumulators
      flat_map<asset_id_type, share_type> promoter_fees;  ///< Promoter fee accumulators
};

typedef multi_index_container<
   reciprocity_factory_object,
   indexed_by<
      ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >
   >
 > reciprocity_factory_multi_index_type;

typedef generic_index<reciprocity_factory_object, reciprocity_factory_multi_index_type> reciprocity_factory_index;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE( graphene::chain::reciprocity_factory_object )

FC_REFLECT_DERIVED( graphene::chain::reciprocity_factory_object, (graphene::db::object),
                    (committee_account)
                    (pool_count)
                    (genesis_enforced)
                    (genesis_1)
                    (genesis_2)
                    (genesis_3)
                    (known_tokens)
                    (is_known)
                    (pool_addresses)
                    (pool_token_counts)
                    (pool_tokens)
                    (founder_fees)
                    (promoter_fees)
                  )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::reciprocity_factory_object )
