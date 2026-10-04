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
#include <graphene/protocol/issuance_ops.hpp>

#include <fc/io/raw.hpp>

namespace graphene { namespace protocol {

void hybrid_mint_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( deposit.amount > 0, "Mint deposit must be positive" );
   FC_ASSERT( deposit.amount <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Mint deposit exceeds maximum share supply" );
   FC_ASSERT( stable_amount > 0, "Minted stable must be positive" );
   FC_ASSERT( stable_amount <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Minted stable exceeds maximum share supply" );
}

void hybrid_redeem_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( burn.amount > 0, "Redeem burn must be positive" );
   FC_ASSERT( burn.amount <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Redeem burn exceeds maximum share supply" );
}

void offset_deposit_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( deposit.amount > 0, "Offset deposit must be positive" );
   FC_ASSERT( deposit.amount <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Offset deposit exceeds maximum share supply" );
}

void offset_claim_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( amount > 0, "Offset claim must be positive" );
   FC_ASSERT( amount <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Offset claim exceeds maximum share supply" );
}

void issuance_exit_request_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( face > 0, "Exit face must be positive" );
   FC_ASSERT( face <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Exit face exceeds maximum share supply" );
}

} } // graphene::protocol

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::hybrid_mint_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::hybrid_redeem_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::offset_deposit_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::offset_claim_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::issuance_exit_request_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::hybrid_mint_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::hybrid_redeem_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::offset_deposit_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::offset_claim_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::issuance_exit_request_operation )
