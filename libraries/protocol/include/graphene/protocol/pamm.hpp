#pragma once
#include <graphene/protocol/base.hpp>
#include <graphene/protocol/asset.hpp>

namespace graphene { namespace protocol {

   /**
    * @brief Create a new PAMM pool
    * @ingroup operations
    */
   struct pamm_create_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 1 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset           fee;                   ///< Operation fee
      account_id_type manager;               ///< Manager account
      asset_id_type   pool_asset;            ///< Asset the pool is denominated in
      asset_id_type   share_asset;           ///< Share (UIA) asset
      uint16_t        fee_rate_bps = 0;      ///< Performance fee in basis points
      uint32_t        delay_seconds = 86400; ///< Withdrawal delay
      share_type      min_tank_level = 0;     ///< Minimum balance floor
      share_type      fee_pool_balance = 0;   ///< Manager prepaid fee pool in core asset

      extensions_type extensions;

      account_id_type fee_payer()const { return manager; }
      void            validate()const override;
   };

   /**
    * @brief Deposit into a PAMM pool
    * @ingroup operations
    */
   struct pamm_deposit_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION / 10; };

      asset           fee;
      account_id_type investor;
      pamm_pool_id_type pool;
      asset           amount;

      extensions_type extensions;

      account_id_type fee_payer()const { return investor; }
      void            validate()const override;
   };

   /**
    * @brief Withdraw from a PAMM pool
    * @ingroup operations
    */
   struct pamm_withdraw_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset           fee;
      account_id_type investor;
      pamm_pool_id_type pool;
      asset           share_amount;

      extensions_type extensions;

      account_id_type fee_payer()const { return investor; }
      void            validate()const override;
   };

   /**
    * @brief Snapshot daily NAV
    * @ingroup operations
    */
   struct pamm_snapshot_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION / 10; };

      asset           fee;
      account_id_type caller; // platform/auditor
      pamm_pool_id_type pool;
      uint64_t        nav_num;
      uint64_t        nav_den;

      extensions_type extensions;

      account_id_type fee_payer()const { return caller; }
      void            validate()const override;
   };

} } // graphene::protocol

// FC_REFLECT definitions for pamm operations (pool fields use pamm_pool_id_type).
FC_REFLECT( graphene::protocol::pamm_create_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::pamm_deposit_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::pamm_withdraw_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::pamm_snapshot_operation::fee_params_t, (fee) )

FC_REFLECT( graphene::protocol::pamm_create_operation,
            (fee)(manager)(pool_asset)(share_asset)(fee_rate_bps)(delay_seconds)(min_tank_level)(fee_pool_balance)(extensions) )
FC_REFLECT( graphene::protocol::pamm_deposit_operation,
            (fee)(investor)(pool)(amount)(extensions) )
FC_REFLECT( graphene::protocol::pamm_withdraw_operation,
            (fee)(investor)(pool)(share_amount)(extensions) )
FC_REFLECT( graphene::protocol::pamm_snapshot_operation,
            (fee)(caller)(pool)(nav_num)(nav_den)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_create_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_deposit_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_withdraw_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_snapshot_operation::fee_params_t )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_create_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_deposit_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_withdraw_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::pamm_snapshot_operation )