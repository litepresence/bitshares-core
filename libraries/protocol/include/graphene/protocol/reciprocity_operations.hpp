// SPDX-License-Identifier: MIT
#pragma once
#include <graphene/protocol/base.hpp>
#include <graphene/protocol/asset.hpp>

namespace graphene { namespace protocol {

   constexpr uint64_t MAX_TOKENS = 8; // MAX_TOKENS — see docs/whitepaper/max_tokens.md
   constexpr uint64_t RECIPROCITY_BASIS = 10000;
   constexpr uint64_t RECIPROCITY_DUST_THRESHOLD = 10;
   constexpr uint64_t RECIPROCITY_MAX_SUM_WEIGHTS = 100;
   constexpr uint64_t RECIPROCITY_SCALE_BUFFER = 4;

   // Spread governor (dual EMA+ATR)
   constexpr uint64_t RECIPROCITY_ATR_SPREAD_TARGET = 10;   // 0.1% — ATR spread target
   constexpr uint64_t RECIPROCITY_EMA_SPREAD_TARGET = 50;   // 0.5% — EMA spread target
   constexpr uint64_t RECIPROCITY_ATR_PERIOD = 100;         // ATR period for spread governor
   constexpr uint64_t RECIPROCITY_EMA_PERIOD = 500;         // EMA period for spread governor
   constexpr uint64_t RECIPROCITY_MAX_SPREAD_TARGET = 100;  // 1% — cap on spread target
   constexpr uint64_t RECIPROCITY_SPREAD_STEP = 100;        // 1% — multiplier adjustment step

   // TVWAP windows
   constexpr uint64_t RECIPROCITY_TVWAP_15M = 900;
   constexpr uint64_t RECIPROCITY_TVWAP_1HR = 3600;
   constexpr uint64_t RECIPROCITY_TVWAP_24HR = 86400;

    // (reserved)

   // ---- Pool lifecycle -------------------------------------------------------

   struct reciprocity_pool_create_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 50 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset                    fee;
      account_id_type          account;             ///< Pool creator (permissionless)
       vector<asset_id_type>    assets;              ///< n-asset pool (2..MAX_TOKENS)
      asset_id_type            share_asset;         ///< LP token asset
      vector<uint64_t>         weights;             ///< Pool weights (GCD-normalized)
      reciprocity_factory_id_type factory;          ///< Factory this pool belongs to

      extensions_type extensions;

      account_id_type fee_payer()const { return account; }
      void            validate()const;
   };

   // ---- Core AMM -------------------------------------------------------------

   struct reciprocity_pool_swap_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 1 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset                    fee;
      account_id_type          account;
      reciprocity_pool_id_type pool;
      vector<asset>            amounts_to_sell;     ///< amounts[i] for each pool asset
      vector<asset>            min_to_receive;      ///< min amounts[i] for each pool asset
      share_type               shares_in;           ///< LP shares to sell (for even exit)
      share_type               min_shares_out;      ///< min LP shares to receive (slippage)
       uint64_t                 target = 0;          ///< legacy target spread — retained for serialization backward compatibility; NOT read by INTEGER2 dual governor
      uint32_t                 deadline = 0;         ///< unix timestamp deadline (0 = no deadline)

      extensions_type extensions;

      account_id_type fee_payer()const { return account; }
      void            validate()const;
   };

   struct reciprocity_pool_add_liquidity_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION / 10; };

      asset                    fee;
      account_id_type          account;
      reciprocity_pool_id_type pool;
      vector<asset>            amounts;              ///< amounts[i] for each pool asset
      uint32_t                 deadline = 0;         ///< unix timestamp deadline (0 = no deadline)

      extensions_type extensions;

      account_id_type fee_payer()const { return account; }
      void            validate()const;
   };

   struct reciprocity_pool_remove_liquidity_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset                    fee;
      account_id_type          account;
      reciprocity_pool_id_type pool;
      asset                    share_amount;         ///< LP shares to burn
      uint32_t                 deadline = 0;         ///< unix timestamp deadline (0 = no deadline)

      extensions_type extensions;

      account_id_type fee_payer()const { return account; }
      void            validate()const;
   };

   // ---- Fee claims -----------------------------------------------------------

   struct reciprocity_claim_founder_royalty_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 0; };

      asset                    fee;
      account_id_type          account;             ///< Must be committee_account
      asset_id_type            token;               ///< Which token to claim

      extensions_type extensions;

      account_id_type fee_payer()const { return account; }
      void            validate()const;
   };

   struct reciprocity_claim_promoter_royalty_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 0; };

      asset                    fee;
      account_id_type          account;             ///< Must be token issuer
      asset_id_type            token;               ///< Which token to claim

      extensions_type extensions;

      account_id_type fee_payer()const { return account; }
      void            validate()const;
   };

} } // graphene::protocol

FC_REFLECT( graphene::protocol::reciprocity_pool_create_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reciprocity_pool_swap_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reciprocity_pool_add_liquidity_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reciprocity_pool_remove_liquidity_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reciprocity_claim_founder_royalty_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reciprocity_claim_promoter_royalty_operation::fee_params_t, (fee) )

FC_REFLECT( graphene::protocol::reciprocity_pool_create_operation,
            (fee)(account)(assets)(share_asset)(weights)(factory)(extensions) )
FC_REFLECT( graphene::protocol::reciprocity_pool_swap_operation,
            (fee)(account)(pool)(amounts_to_sell)(min_to_receive)(shares_in)(min_shares_out)(target)(deadline)(extensions) )
FC_REFLECT( graphene::protocol::reciprocity_pool_add_liquidity_operation,
            (fee)(account)(pool)(amounts)(deadline)(extensions) )
FC_REFLECT( graphene::protocol::reciprocity_pool_remove_liquidity_operation,
            (fee)(account)(pool)(share_amount)(deadline)(extensions) )
FC_REFLECT( graphene::protocol::reciprocity_claim_founder_royalty_operation,
            (fee)(account)(token)(extensions) )
FC_REFLECT( graphene::protocol::reciprocity_claim_promoter_royalty_operation,
            (fee)(account)(token)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_create_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_swap_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_add_liquidity_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_remove_liquidity_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_claim_founder_royalty_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_claim_promoter_royalty_operation::fee_params_t )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_create_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_swap_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_add_liquidity_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_pool_remove_liquidity_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_claim_founder_royalty_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reciprocity_claim_promoter_royalty_operation )
