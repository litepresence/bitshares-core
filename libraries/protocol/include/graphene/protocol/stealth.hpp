/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License
 */
#pragma once

#include <graphene/protocol/base.hpp>
#include <graphene/protocol/asset.hpp>

namespace graphene { namespace protocol {

// Reserved stubs for the G track (stealth transfers). These occupy tags 104-109
// on the H branch until Task 5 replaces them with the full implementations
// from the G track (stealth.hpp real fields, spec cross-references, evaluators).
// They are never applied (no evaluator registered) and carry no consensus state.
struct stealth_transfer_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct freeze_blind_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct turnstile_reproof_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct parity_review_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct stealth_explicit_spend_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct stealth_pool_exchange_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

} } // graphene::protocol

FC_REFLECT( graphene::protocol::stealth_transfer_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::freeze_blind_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::turnstile_reproof_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::parity_review_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::stealth_explicit_spend_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::stealth_pool_exchange_operation::fee_params_t, (fee) )

FC_REFLECT( graphene::protocol::stealth_transfer_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::freeze_blind_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::turnstile_reproof_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::parity_review_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::stealth_explicit_spend_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::stealth_pool_exchange_operation, (fee)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_transfer_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::freeze_blind_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::turnstile_reproof_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::parity_review_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_explicit_spend_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_pool_exchange_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_transfer_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::freeze_blind_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::turnstile_reproof_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::parity_review_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_explicit_spend_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_pool_exchange_operation )