#include <graphene/protocol/stealth.hpp>
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
#include <graphene/protocol/accs_ops.hpp>

#include <fc/io/raw.hpp>

namespace graphene { namespace protocol {

void accs_validate_foreign_recipient( uint8_t chain_id, const std::string& recipient )
{
   // Charset + length bounds per declared chain (0 BTC, 1 ETH, 2 SOL). The
   // bounds deliberately under-specify (no checksums, no prefix parsing) so
   // they can never reject an address that the chain's own rules accept.
   // Spec: docs/superpowers/specs/2026-10-20-f2-accs-orderbook-settlement.md §3.1
   switch( chain_id )
   {
      case 0: // BTC: bech32 (lowercase) and legacy base58 are alnum only
      {
         FC_ASSERT( recipient.size() >= 25 && recipient.size() <= 90,
                    "BTC recipient length out of range" );
         for( const char& c : recipient )
            FC_ASSERT( ( c >= '0' && c <= '9' ) || ( c >= 'a' && c <= 'z' )
                       || ( c >= 'A' && c <= 'Z' ),
                       "BTC recipient has a character outside the alphanumeric set" );
         break;
      }
      case 1: // ETH: 0x plus 40 hex characters (EIP-55 mixed case accepted)
      {
         FC_ASSERT( recipient.size() == 42,
                    "ETH recipient must be 0x plus 40 hex characters" );
         FC_ASSERT( recipient[0] == '0' && recipient[1] == 'x',
                    "ETH recipient must start with 0x" );
         for( size_t i = 2; i < recipient.size(); ++i )
         {
            const char& c = recipient[i];
            FC_ASSERT( ( c >= '0' && c <= '9' ) || ( c >= 'a' && c <= 'f' )
                       || ( c >= 'A' && c <= 'F' ),
                       "ETH recipient has a character outside the hex set" );
         }
         break;
      }
      case 2: // SOL: base58 alphabet (no 0, O, I, l)
      {
         FC_ASSERT( recipient.size() >= 32 && recipient.size() <= 44,
                    "SOL recipient length out of range" );
         for( const char& c : recipient )
         {
            const bool base58 = ( c >= '1' && c <= '9' ) || ( c >= 'a' && c <= 'z' )
                                || ( c >= 'A' && c <= 'Z' );
            const bool excluded = ( c == 'O' || c == 'I' || c == 'l' );
            FC_ASSERT( base58 && !excluded,
                       "SOL recipient has a character outside the base58 set" );
         }
         break;
      }
      default:
         FC_ASSERT( false, "Recipient format for undeclared chain" );
   }
}

void accs_declare_gateway_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( chain_id <= 2, "Invalid chain id" );
   FC_ASSERT( foreign_asset_id.size() <= 256, "Foreign asset id too long" );
}

share_type accs_declare_gateway_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void accs_deactivate_gateway_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( chain_id < 256, "Invalid chain id" );
}

share_type accs_deactivate_gateway_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void accs_create_offer_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( base_amount > 0, "Base amount must be positive" );
   FC_ASSERT( foreign_amount > 0, "Foreign amount must be positive" );
   FC_ASSERT( !foreign_recipient.empty(), "Foreign recipient must not be empty" );
   FC_ASSERT( foreign_recipient.size() <= 256, "Foreign recipient too long" );
   FC_ASSERT( chain_id <= 2, "Invalid chain id" );
   FC_ASSERT( foreign_asset_id.size() <= 256, "Foreign asset id too long" );
   accs_validate_foreign_recipient( chain_id, foreign_recipient );
}

share_type accs_create_offer_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void accs_cancel_offer_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
}

share_type accs_cancel_offer_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void accs_match_offer_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( griefing_bond > 0, "Griefing bond must be positive" );
}

share_type accs_match_offer_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void accs_fulfill_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( amount > 0, "Fulfillment amount must be positive" );
   // Canonical wire form for the replay guard: exactly 32 bytes as lowercase
   // hex, so the durable consumed-tx set compares decoded bytes as strict
   // equality and no case variant of a consumed hash can be a new lane.
   // Spec: docs/superpowers/specs/2026-10-24-three-track-split-design.md §9
   FC_ASSERT( foreign_tx_hash.size() == 64, "Foreign tx hash must be 64 hex chars" );
   for( const char& c : foreign_tx_hash )
      FC_ASSERT( ( c >= '0' && c <= '9' ) || ( c >= 'a' && c <= 'f' ),
                 "Foreign tx hash must be canonical lowercase hex" );
}

share_type accs_fulfill_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

void accs_claim_griefing_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
}

share_type accs_claim_griefing_operation::calculate_fee( const fee_params_t& schedule )const
{
   return share_type( schedule.fee );
}

} } // graphene::protocol

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_declare_gateway_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_deactivate_gateway_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_create_offer_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_cancel_offer_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_match_offer_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_fulfill_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_claim_griefing_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_declare_gateway_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_deactivate_gateway_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_create_offer_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_cancel_offer_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_match_offer_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_fulfill_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::accs_claim_griefing_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_transfer_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::freeze_blind_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::turnstile_reproof_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::parity_review_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_explicit_spend_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_pool_exchange_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_transfer_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::freeze_blind_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::turnstile_reproof_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::parity_review_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_explicit_spend_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::stealth_pool_exchange_operation )
