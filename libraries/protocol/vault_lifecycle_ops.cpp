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
#include <graphene/protocol/vault_lifecycle_ops.hpp>

#include <fc/io/raw.hpp>

namespace graphene { namespace protocol {

void vault_rotate_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( new_authority.weight_threshold >= 1,
              "New vault authority must have a positive threshold" );
   FC_ASSERT( new_authority.num_auths() <= GRAPHENE_H2_VAULT_MAX_AUTHORITY_MEMBERS,
              "New vault authority exceeds ${m} members",
              ("m", GRAPHENE_H2_VAULT_MAX_AUTHORITY_MEMBERS) );
   FC_ASSERT( !new_authority.is_impossible(),
              "New vault authority threshold exceeds the sum of member weights" );
   FC_ASSERT( co_signers.size() <= GRAPHENE_H2_VAULT_MAX_AUTHORITY_MEMBERS,
              "Rotation co-signers exceed ${m} members",
              ("m", GRAPHENE_H2_VAULT_MAX_AUTHORITY_MEMBERS) );
   FC_ASSERT( co_signers.find( rotator ) == co_signers.end(),
              "Rotator is already required; listing it as a co-signer double-counts weight" );
   if( memo.valid() )
      FC_ASSERT( memo->size() <= GRAPHENE_H2_VAULT_MAX_MEMO_LENGTH,
                 "Memo should not exceed ${m} characters",
                 ("m", GRAPHENE_H2_VAULT_MAX_MEMO_LENGTH) );
}

share_type vault_rotate_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void vault_bond_release_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
}

void vault_resolve_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
}

void pair_freeze_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
}

void winddown_claim_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( claim_amount > 0, "Wind-down claim amount must be positive" );
   FC_ASSERT( claim_amount <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Wind-down claim amount exceeds maximum share supply" );
   FC_ASSERT( tranche == GRAPHENE_H2_WINDDOWN_SENIOR
              || tranche == GRAPHENE_H2_WINDDOWN_JUNIOR,
              "Wind-down claim tranche must be senior (0) or junior (1)" );
}

share_type winddown_claim_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void vault_foreign_mint_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( amount > 0, "Foreign mint amount must be positive" );
   FC_ASSERT( amount <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Foreign mint amount exceeds maximum share supply" );
}

share_type vault_foreign_mint_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void vault_foreign_redeem_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( amount > 0, "Foreign redeem amount must be positive" );
   FC_ASSERT( amount <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Foreign redeem amount exceeds maximum share supply" );
}

share_type vault_foreign_redeem_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

} } // graphene::protocol

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_rotate_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_bond_release_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_resolve_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::pair_freeze_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::winddown_claim_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_foreign_mint_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_foreign_redeem_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_rotate_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_bond_release_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_resolve_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::pair_freeze_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::winddown_claim_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_foreign_mint_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_foreign_redeem_operation )
