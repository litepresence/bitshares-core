#pragma once
#include <graphene/protocol/base.hpp>
#include <graphene/protocol/asset.hpp>
#include <graphene/protocol/authority.hpp>

namespace graphene { namespace protocol {

   /// BSIP-5 (Prism open-order rewards) activation gate handled by hardfork_visitor.

   /// Opt an asset into the open-order reward program.
   struct bsip5_opt_in_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 1000; };
      asset           fee;
      account_id_type issuer;          ///< asset issuer
      asset_id_type   asset_id;        ///< asset opting in
      uint16_t        reward_rate_bps = 100; ///< open order fee in bps (0..500)
      extensions_type extensions;
      account_id_type fee_payer() const { return issuer; }
      void validate() const {}
   };

   /// Trigger a payout distribution for a market (permissionless, gas-guarded).
   struct bsip5_payout_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 1000; };
      asset           fee;
      account_id_type caller;
      asset_id_type   base_asset;
      asset_id_type   quote_asset;
      uint64_t        gas_price_wad = 0; ///< 0 bypasses gas guard
      extensions_type extensions;
      account_id_type fee_payer() const { return caller; }
      void validate() const {}
   };

   /// Claim accumulated rebate vesting for an account.
   struct bsip5_claim_rebate_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 0; };
      asset           fee;
      account_id_type account;
      extensions_type extensions;
      account_id_type fee_payer() const { return account; }
      void validate() const {}
   };

} } // graphene::protocol

FC_REFLECT( graphene::protocol::bsip5_opt_in_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::bsip5_payout_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::bsip5_claim_rebate_operation::fee_params_t, (fee) )

FC_REFLECT( graphene::protocol::bsip5_opt_in_operation, (fee)(issuer)(asset_id)(reward_rate_bps)(extensions) )
FC_REFLECT( graphene::protocol::bsip5_payout_operation, (fee)(caller)(base_asset)(quote_asset)(gas_price_wad)(extensions) )
FC_REFLECT( graphene::protocol::bsip5_claim_rebate_operation, (fee)(account)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip5_opt_in_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip5_payout_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip5_claim_rebate_operation::fee_params_t )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip5_opt_in_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip5_payout_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::bsip5_claim_rebate_operation )
