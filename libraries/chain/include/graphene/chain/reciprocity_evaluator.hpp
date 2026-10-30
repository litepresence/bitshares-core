// SPDX-License-Identifier: MIT
#pragma once
#include <graphene/chain/evaluator.hpp>

#include <graphene/protocol/reciprocity_operations.hpp>

namespace graphene { namespace chain {

   class asset_object;
   class asset_dynamic_data_object;
   class reciprocity_pool_object;
   class reciprocity_factory_object;

   fc::uint128_t r_compute_konstant( const vector<share_type>& balances,
                                 const vector<share_type>& genesis,
                                 uint64_t factors,
                                 fc::uint128_t scale,
                                 const vector<uint64_t>& weights = {} );


   // ---- Pool lifecycle -------------------------------------------------------

   class reciprocity_pool_create_evaluator : public evaluator<reciprocity_pool_create_evaluator>
   {
      public:
         using operation_type = reciprocity_pool_create_operation;

         void_result do_evaluate( const reciprocity_pool_create_operation& op );
         generic_operation_result do_apply( const reciprocity_pool_create_operation& op );

      private:
         const asset_object* _share_asset = nullptr;
         const reciprocity_factory_object* _factory = nullptr;
   };

   // ---- Core AMM -------------------------------------------------------------

   class reciprocity_pool_swap_evaluator : public evaluator<reciprocity_pool_swap_evaluator>
   {
      public:
         using operation_type = reciprocity_pool_swap_operation;

         void_result do_evaluate( const reciprocity_pool_swap_operation& op );
         generic_exchange_operation_result do_apply( const reciprocity_pool_swap_operation& op );

      private:
         const reciprocity_pool_object* _pool = nullptr;
         const reciprocity_factory_object* _factory = nullptr;
         const asset_dynamic_data_object* _share_asset_dyn_data = nullptr;
         vector<asset> _pool_receives;
         vector<asset> _pool_pays;
         vector<asset> _fees;
         asset _account_receives;
   };

   class reciprocity_pool_add_liquidity_evaluator : public evaluator<reciprocity_pool_add_liquidity_evaluator>
   {
      public:
         using operation_type = reciprocity_pool_add_liquidity_operation;

         void_result do_evaluate( const reciprocity_pool_add_liquidity_operation& op );
         generic_exchange_operation_result do_apply( const reciprocity_pool_add_liquidity_operation& op );

      private:
         const reciprocity_pool_object* _pool = nullptr;
         const asset_dynamic_data_object* _share_asset_dyn_data = nullptr;
         vector<asset> _pool_receives;
         asset _account_receives;
   };

   class reciprocity_pool_remove_liquidity_evaluator : public evaluator<reciprocity_pool_remove_liquidity_evaluator>
   {
      public:
         using operation_type = reciprocity_pool_remove_liquidity_operation;

         void_result do_evaluate( const reciprocity_pool_remove_liquidity_operation& op );
         generic_exchange_operation_result do_apply( const reciprocity_pool_remove_liquidity_operation& op );

      private:
         const reciprocity_pool_object* _pool = nullptr;
         const asset_dynamic_data_object* _share_asset_dyn_data = nullptr;
         vector<asset> _pool_pays;
         vector<asset> _fees;
   };

   // ---- Fee claims -----------------------------------------------------------

   class reciprocity_claim_founder_royalty_evaluator : public evaluator<reciprocity_claim_founder_royalty_evaluator>
   {
      public:
         using operation_type = reciprocity_claim_founder_royalty_operation;

         void_result do_evaluate( const reciprocity_claim_founder_royalty_operation& op );
         void_result do_apply( const reciprocity_claim_founder_royalty_operation& op );

      private:
         const reciprocity_factory_object* _factory = nullptr;
   };

   class reciprocity_claim_promoter_royalty_evaluator : public evaluator<reciprocity_claim_promoter_royalty_evaluator>
   {
      public:
         using operation_type = reciprocity_claim_promoter_royalty_operation;

         void_result do_evaluate( const reciprocity_claim_promoter_royalty_operation& op );
         void_result do_apply( const reciprocity_claim_promoter_royalty_operation& op );

      private:
         const reciprocity_factory_object* _factory = nullptr;
   };

} } // graphene::chain
