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
#include <graphene/protocol/challenge_ops.hpp>

#include <fc/io/raw.hpp>

namespace graphene { namespace protocol {

void vault_challenge_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( challenge_bond > 0, "Challenge bond must be positive" );
   FC_ASSERT( challenge_bond <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Challenge bond exceeds maximum share supply" );
   FC_ASSERT( challenge_bond_usd_cents > 0,
              "Challenge bond usd_cents records the USD-terms basis and must be positive" );
   FC_ASSERT( !evidence_memo.empty(), "Challenge evidence memo must be present" );
   FC_ASSERT( evidence_memo.size() <= GRAPHENE_H2_EVIDENCE_MAX_LENGTH,
              "Challenge evidence memo should not exceed ${m} characters",
              ("m", GRAPHENE_H2_EVIDENCE_MAX_LENGTH) );
}

share_type vault_challenge_operation::calculate_fee( const fee_params_t& schedule )const
{
   share_type core_fee_required = schedule.fee;
   core_fee_required += calculate_data_fee( fc::raw::pack_size(*this), schedule.price_per_kbyte );
   return core_fee_required;
}

void oracle_dispute_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( dispute_bond > 0, "Dispute bond must be positive" );
   FC_ASSERT( dispute_bond <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Dispute bond exceeds maximum share supply" );
   FC_ASSERT( dispute_bond_usd_cents > 0,
              "Dispute bond usd_cents records the USD-terms basis and must be positive" );
   FC_ASSERT( !evidence_memo.empty(), "Dispute evidence memo must be present" );
   FC_ASSERT( evidence_memo.size() <= GRAPHENE_H2_EVIDENCE_MAX_LENGTH,
              "Dispute evidence memo should not exceed ${m} characters",
              ("m", GRAPHENE_H2_EVIDENCE_MAX_LENGTH) );
}

share_type oracle_dispute_operation::calculate_fee( const fee_params_t& schedule )const
{
   share_type core_fee_required = schedule.fee;
   core_fee_required += calculate_data_fee( fc::raw::pack_size(*this), schedule.price_per_kbyte );
   return core_fee_required;
}

void oracle_dispute_escalate_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( round_bond > 0, "Round bond must be positive" );
   FC_ASSERT( round_bond <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Round bond exceeds maximum share supply" );
   FC_ASSERT( round_bond_usd_cents > 0,
              "Round bond usd_cents records the USD-terms basis and must be positive" );
}

share_type oracle_dispute_escalate_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void challenge_vote_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( decision <= GRAPHENE_H2_DISPUTE_FAST_REJECT,
              "Unknown challenge vote decision ${d}", ("d", decision) );
}

share_type challenge_vote_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

} } // graphene::protocol

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_challenge_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_dispute_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_dispute_escalate_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::challenge_vote_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::vault_challenge_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_dispute_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_dispute_escalate_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::challenge_vote_operation )
