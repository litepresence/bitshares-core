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
#include <graphene/chain/accs_evaluator.hpp>
#include <graphene/chain/accs_object.hpp>

#include <algorithm>
#include <graphene/chain/database.hpp>
#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/balance_object.hpp>
#include <graphene/chain/committee_member_object.hpp>

#include <graphene/chain/hardfork.hpp>

namespace graphene { namespace chain {

void_result accs_declare_gateway_evaluator::do_evaluate( const accs_declare_gateway_operation& op )
{ try {
   const database& d = db();

   const auto& member_idx = d.get_index_type<committee_member_index>().indices().get<by_account>();
   const auto member_itr = member_idx.find( op.committee_member );
   FC_ASSERT( member_itr != member_idx.end(),
              "Account ${a} is not a registered committee member", ("a", op.committee_member) );
   const auto& elected = d.get_global_properties().active_committee_members;
   FC_ASSERT( std::find( elected.begin(), elected.end(), member_itr->get_id() ) != elected.end(),
              "Account ${a} is registered but not on the elected committee", ("a", op.committee_member) );

   // Check no existing active gateway for this (chain_id, foreign_asset_id) pair
   const auto& gw_idx = d.get_index_type<accs_gateway_index>().indices();
   for( const auto& gw : gw_idx )
   {
      if( gw.chain_id == op.chain_id && gw.foreign_asset_id == op.foreign_asset_id && gw.active )
         FC_ASSERT( false, "Active gateway already exists for chain ${c} asset ${a}",
                    ("c", op.chain_id)("a", op.foreign_asset_id) );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

object_id_type accs_declare_gateway_evaluator::do_apply( const accs_declare_gateway_operation& op ) const
{ try {
   database& d = db();
   const auto& new_gw = d.create<accs_gateway_object>( [&op, &d]( accs_gateway_object& g ) {
      g.chain_id = op.chain_id;
      g.foreign_asset_id = op.foreign_asset_id;
      g.declared_by = op.committee_member;
      g.declared_at = d.head_block_num();
      g.min_confirmations = 6; // default; per-chain rules set later
      g.active = true;
   } );
   return new_gw.id;
} FC_CAPTURE_AND_RETHROW( (op) ) }

// (implemented below)

void process_accs_maintenance( database& d )
{
   if( !HARDFORK_H2_GATEWAY_PASSED( d.head_block_time() ) )
      return;

   const uint32_t now_block = d.head_block_num();

   const auto& offer_idx = d.get_index_type<accs_offer_index>().indices();
   std::vector<protocol::accs_offer_id_type> to_expire;
   for( const auto& offer : offer_idx )
   {
      if( offer.state == 0 && offer.expiry > 0 && now_block >= offer.expiry )
         to_expire.push_back( offer.id );
   }
   for( protocol::accs_offer_id_type oid : to_expire )
   {
      const accs_offer_object* offer = d.find( oid );
      if( !offer || offer->state != 0 ) continue;
      d.adjust_balance( offer->seller, asset( offer->base_amount, offer->base_asset ) );
      d.modify( *offer, []( accs_offer_object& o ) { o.state = 3; } );
      const accs_orderbook_object* ob = d.find( offer->orderbook );
      if( ob )
      {
         d.modify( *ob, [&offer]( accs_orderbook_object& o ) {
            auto it = std::find( o.open_offers.begin(), o.open_offers.end(), offer->id );
            if( it != o.open_offers.end() ) o.open_offers.erase( it );
         } );
      }
   }
}

void_result accs_create_offer_evaluator::do_evaluate( const accs_create_offer_operation& op )
{ try {
   const database& d = db();

   FC_ASSERT( nullptr != d.find( op.seller ), "Seller account does not exist" );
   const asset_object* base_asset = d.find( op.base_asset );
   FC_ASSERT( nullptr != base_asset, "Base asset does not exist" );

   // Check gateway exists and is active
   bool gateway_found = false;
   const auto& gw_idx = d.get_index_type<accs_gateway_index>().indices();
   for( const auto& gw : gw_idx )
   {
      if( gw.chain_id == op.chain_id && gw.foreign_asset_id == op.foreign_asset_id && gw.active )
      {
         gateway_found = true;
         break;
      }
   }
   FC_ASSERT( gateway_found, "No active gateway for chain ${c} asset ${a}",
              ("c", op.chain_id)("a", op.foreign_asset_id) );

   // Check seller has sufficient balance
   FC_ASSERT( d.get_balance( op.seller, op.base_asset ) >= asset( op.base_amount, op.base_asset ),
              "Seller has insufficient balance for the offer" );

   // Expiry validation
   if( op.expiry > 0 )
   {
      FC_ASSERT( op.expiry > d.head_block_num() + GRAPHENE_ACCS_MIN_OFFER_LIFETIME,
                 "Offer expiry must be at least ${m} blocks in the future",
                 ("m", GRAPHENE_ACCS_MIN_OFFER_LIFETIME) );
   }

   FC_ASSERT( !op.foreign_recipient.empty(), "Foreign recipient must not be empty" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

object_id_type accs_create_offer_evaluator::do_apply( const accs_create_offer_operation& op ) const
{ try {
   database& d = db();

   // Find or create orderbook for (base_asset, chain_id, foreign_asset_id)
   accs_orderbook_object* orderbook = nullptr;
   const auto& ob_idx = d.get_index_type<accs_orderbook_index>().indices();
   for( const auto& ob : ob_idx )
   {
      if( ob.base_asset == op.base_asset && ob.chain_id == op.chain_id
          && ob.foreign_asset_id == op.foreign_asset_id )
      {
         orderbook = const_cast<accs_orderbook_object*>( d.find( ob.id ) );
         break;
      }
   }

   if( !orderbook )
   {
      orderbook = &d.create<accs_orderbook_object>( [&op]( accs_orderbook_object& o ) {
         o.base_asset = op.base_asset;
         o.chain_id = op.chain_id;
         o.foreign_asset_id = op.foreign_asset_id;
         o.next_offer_id = 1;
      } );
   }

   // Deduct base asset from seller (escrow)
   d.adjust_balance( op.seller, asset( -op.base_amount, op.base_asset ) );

   // Create offer
   const auto& new_offer = d.create<accs_offer_object>( [&op, &orderbook, &d]( accs_offer_object& o ) {
      o.offer_id = orderbook->next_offer_id++;
      o.orderbook = orderbook->id;
      o.seller = op.seller;
      o.base_asset = op.base_asset;
      o.chain_id = op.chain_id;
      o.foreign_asset_id = op.foreign_asset_id;
      o.base_amount = op.base_amount;
      o.foreign_amount = op.foreign_amount;
      o.foreign_recipient = op.foreign_recipient;
      o.escrow_balance = op.base_amount;
      o.state = 0; // open
      o.expiry = op.expiry;
      o.created_block = d.head_block_num();
   } );

   // Add to orderbook's open offers
   // (modify orderbook)
   d.modify( *orderbook, [&new_offer]( accs_orderbook_object& o ) {
      o.open_offers.push_back( new_offer.id );
   } );

   return new_offer.id;
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_cancel_offer_evaluator::do_evaluate( const accs_cancel_offer_operation& op )
{ try {
   const database& d = db();
   FC_ASSERT( nullptr != d.find( op.seller ), "Seller account does not exist" );
   const accs_offer_object* offer = d.find( op.offer_id );
   FC_ASSERT( nullptr != offer, "Offer does not exist" );
   FC_ASSERT( offer->seller == op.seller, "Only the seller can cancel" );
   FC_ASSERT( offer->state == 0, "Only open offers can be cancelled" ); // 0 = open
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_cancel_offer_evaluator::do_apply( const accs_cancel_offer_operation& op ) const
{ try {
   database& d = db();
   const accs_offer_object* offer = d.find( op.offer_id );
   FC_ASSERT( nullptr != offer, "Offer does not exist" );

   // Return escrow to seller
   d.adjust_balance( offer->seller, asset( offer->base_amount, offer->base_asset ) );

   // Set state to cancelled (4)
   d.modify( *offer, []( accs_offer_object& o ) {
      o.state = 4; // cancelled
   } );

   // Remove from orderbook's open offers
   const accs_orderbook_object* ob = d.find( offer->orderbook );
   if( ob )
   {
      d.modify( *ob, [&offer]( accs_orderbook_object& o ) {
         auto it = std::find( o.open_offers.begin(), o.open_offers.end(), offer->id );
         if( it != o.open_offers.end() ) o.open_offers.erase( it );
      } );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_match_offer_evaluator::do_evaluate( const accs_match_offer_operation& op )
{ try {
   const database& d = db();
   FC_ASSERT( nullptr != d.find( op.buyer ), "Buyer account does not exist" );
   const accs_offer_object* offer = d.find( op.offer_id );
   FC_ASSERT( nullptr != offer, "Offer does not exist" );
   FC_ASSERT( offer->state == 0, "Only open offers can be matched" ); // 0 = open
   FC_ASSERT( offer->seller != op.buyer, "Cannot match your own offer" );
   FC_ASSERT( op.griefing_bond >= GRAPHENE_ACCS_MIN_GRIEFING_BOND_USD_CENTS,
              "Griefing bond below minimum" );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_match_offer_evaluator::do_apply( const accs_match_offer_operation& op ) const
{ try {
   database& d = db();
   const accs_offer_object* offer = d.find( op.offer_id );
   FC_ASSERT( nullptr != offer, "Offer does not exist" );

   // Deduct griefing bond from buyer
   d.adjust_balance( op.buyer, asset( -op.griefing_bond, offer->base_asset ) );

   // Transition to matched (state = 1)
   d.modify( *offer, [&op, &d]( accs_offer_object& o ) {
      o.state = 1; // matched
      o.matched_buyer = op.buyer;
      o.matched_at = d.head_block_num();
      o.griefing_bond = op.griefing_bond;
      o.sla_deadline = d.head_block_num() + GRAPHENE_ACCS_SLA_BLOCKS;
   } );

   // Move from open to matched in orderbook
   const accs_orderbook_object* ob = d.find( offer->orderbook );
   if( ob )
   {
      d.modify( *ob, [&offer]( accs_orderbook_object& o ) {
         auto it = std::find( o.open_offers.begin(), o.open_offers.end(), offer->id );
         if( it != o.open_offers.end() ) o.open_offers.erase( it );
         o.matched_offers.push_back( offer->id );
      } );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_fulfill_evaluator::do_evaluate( const accs_fulfill_operation& op )
{ try {
   const database& d = db();
   FC_ASSERT( nullptr != d.find( op.publisher ), "Publisher does not exist" );
   const accs_offer_object* offer = d.find( op.offer_id );
   FC_ASSERT( nullptr != offer, "Offer does not exist" );
   FC_ASSERT( offer->state == 1, "Only matched offers can be fulfilled" ); // 1 = matched
   FC_ASSERT( op.amount == offer->foreign_amount, "Amount must equal offer foreign_amount" );
   FC_ASSERT( d.head_block_num() <= offer->sla_deadline, "SLA deadline exceeded" );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_fulfill_evaluator::do_apply( const accs_fulfill_operation& op ) const
{ try {
   database& d = db();
   const accs_offer_object* offer = d.find( op.offer_id );
   FC_ASSERT( nullptr != offer, "Offer does not exist" );

   // Release base asset to buyer
   d.adjust_balance( offer->matched_buyer, asset( offer->base_amount, offer->base_asset ) );

   // Return griefing bond to buyer
   d.adjust_balance( offer->matched_buyer, asset( offer->griefing_bond, offer->base_asset ) );

   // Transition to fulfilled (state = 2)
   d.modify( *offer, [&op]( accs_offer_object& o ) {
      o.state = 2; // fulfilled
      o.expected_tx_hash = op.foreign_tx_hash;
   } );

   // Remove from orderbook's matched offers
   const accs_orderbook_object* ob = d.find( offer->orderbook );
   if( ob )
   {
      d.modify( *ob, [&offer]( accs_orderbook_object& o ) {
         auto it = std::find( o.matched_offers.begin(), o.matched_offers.end(), offer->id );
         if( it != o.matched_offers.end() ) o.matched_offers.erase( it );
      } );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_claim_griefing_evaluator::do_evaluate( const accs_claim_griefing_operation& op )
{ try {
   const database& d = db();
   FC_ASSERT( nullptr != d.find( op.claimer ), "Claimer account does not exist" );
   const accs_offer_object* offer = d.find( op.offer_id );
   FC_ASSERT( nullptr != offer, "Offer does not exist" );
   FC_ASSERT( offer->seller == op.claimer, "Only the seller can claim griefing" );
   FC_ASSERT( offer->state == 1, "Only matched offers can be claimed" ); // 1 = matched
   FC_ASSERT( d.head_block_num() > offer->sla_deadline, "SLA deadline not yet exceeded" );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_claim_griefing_evaluator::do_apply( const accs_claim_griefing_operation& op ) const
{ try {
   database& d = db();
   const accs_offer_object* offer = d.find( op.offer_id );
   FC_ASSERT( nullptr != offer, "Offer does not exist" );

   // Transfer griefing bond to seller
   d.adjust_balance( offer->seller, asset( offer->griefing_bond, offer->base_asset ) );

   // Return escrow to seller
   d.adjust_balance( offer->seller, asset( offer->base_amount, offer->base_asset ) );

   // Transition to expired (state = 3)
   d.modify( *offer, []( accs_offer_object& o ) {
      o.state = 3; // expired
   } );

   // Remove from orderbook's matched offers
   const accs_orderbook_object* ob = d.find( offer->orderbook );
   if( ob )
   {
      d.modify( *ob, [&offer]( accs_orderbook_object& o ) {
         auto it = std::find( o.matched_offers.begin(), o.matched_offers.end(), offer->id );
         if( it != o.matched_offers.end() ) o.matched_offers.erase( it );
      } );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_deactivate_gateway_evaluator::do_evaluate( const accs_deactivate_gateway_operation& op )
{ try {
   const database& d = db();
   const auto& member_idx = d.get_index_type<committee_member_index>().indices().get<by_account>();
   const auto member_itr = member_idx.find( op.committee_member );
   FC_ASSERT( member_itr != member_idx.end(),
              "Account ${a} is not a registered committee member", ("a", op.committee_member) );
   const auto& elected = d.get_global_properties().active_committee_members;
   FC_ASSERT( std::find( elected.begin(), elected.end(), member_itr->get_id() ) != elected.end(),
              "Account ${a} is registered but not on the elected committee", ("a", op.committee_member) );

   // Find active gateway
   bool found = false;
   const auto& gw_idx = d.get_index_type<accs_gateway_index>().indices();
   for( const auto& gw : gw_idx )
   {
      if( gw.chain_id == op.chain_id && gw.foreign_asset_id == op.foreign_asset_id && gw.active )
      {
         found = true;
         break;
      }
   }
   FC_ASSERT( found, "No active gateway to deactivate" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_deactivate_gateway_evaluator::do_apply( const accs_deactivate_gateway_operation& op ) const
{ try {
   database& d = db();
   const auto& gw_idx = d.get_index_type<accs_gateway_index>().indices();
   for( const auto& gw : gw_idx )
   {
      if( gw.chain_id == op.chain_id && gw.foreign_asset_id == op.foreign_asset_id && gw.active )
      {
         d.modify( gw, []( accs_gateway_object& g ) {
            g.active = false;
         } );
         break;
      }
   }
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

} } // graphene::chain
