/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <graphene/protocol/vault_ops.hpp>

#include <fc/io/raw.hpp>

namespace graphene { namespace protocol {

void vault_register_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( vault_authority.weight_threshold >= 1,
              "Vault authority must have a positive threshold" );
   FC_ASSERT( min_bond > 0, "Vault min_bond must be positive" );
   FC_ASSERT( min_bond <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Vault min_bond exceeds maximum share supply" );
   FC_ASSERT( min_bond_usd_cents > 0,
              "Vault min_bond_usd_cents records the USD-terms basis and must be positive" );
   // BTS-only at genesis (inventory OQ-05 reversible minimum): the basket join
   // rule is a later task's explicit allow-list, never a silent expansion. The
   // evaluator re-checks this against the registered asset; validate pins the
   // core asset statically.
   FC_ASSERT( bond_asset == asset_id_type(),
              "Vault bond asset is BTS-only at genesis" );
   FC_ASSERT( secure_ratio_bps > 10000,
              "Secure ratio must exceed 100% (10000 bps)" );
   FC_ASSERT( challenge_window_sec > 0,
              "Challenge window must be positive" );
   FC_ASSERT( challenge_window_sec <= GRAPHENE_H2_VAULT_MAX_CHALLENGE_WINDOW_SEC,
              "Challenge window exceeds ${m} seconds",
              ("m", GRAPHENE_H2_VAULT_MAX_CHALLENGE_WINDOW_SEC) );
   if( memo.valid() )
      FC_ASSERT( memo->size() <= GRAPHENE_H2_VAULT_MAX_MEMO_LENGTH,
                 "Memo should not exceed ${m} characters",
                 ("m", GRAPHENE_H2_VAULT_MAX_MEMO_LENGTH) );
}

share_type vault_register_operation::calculate_fee( const fee_params_t& schedule )const
{
   share_type core_fee_required = schedule.fee;
   core_fee_required += calculate_data_fee( fc::raw::pack_size(*this), schedule.price_per_kbyte );
   return core_fee_required;
}

void vault_bond_lock_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( bond_amount > 0, "Bond amount must be positive" );
   FC_ASSERT( bond_amount <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Bond amount exceeds maximum share supply" );
   FC_ASSERT( bond_usd_cents > 0,
              "Bond usd_cents records the USD-terms basis and must be positive" );
}

share_type vault_bond_lock_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void oracle_bond_lock_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( bond_amount > 0, "Bond amount must be positive" );
   FC_ASSERT( bond_amount <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Bond amount exceeds maximum share supply" );
   FC_ASSERT( bond_usd_cents > 0,
              "Bond usd_cents records the USD-terms basis and must be positive" );
   FC_ASSERT( bootstrap_weight <= GRAPHENE_ORACLE_MAX_PRODUCER_WEIGHT,
              "Bootstrap weight exceeds ${m}",
              ("m", GRAPHENE_ORACLE_MAX_PRODUCER_WEIGHT) );
}

share_type oracle_bond_lock_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void oracle_bond_release_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
}

} } // graphene::protocol

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_register_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_bond_lock_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_bond_lock_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_bond_release_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_register_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_bond_lock_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_bond_lock_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_bond_release_operation )
