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
#include <cstring>
#include <graphene/chain/database.hpp>
#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/balance_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/h2_activation.hpp>
#include <graphene/chain/h2_economics_evaluator.hpp>
#include <graphene/protocol/h2_economics.hpp>

#include <fc/crypto/hex.hpp>
#include <fc/crypto/sha256.hpp>

#include <graphene/chain/hardfork.hpp>

namespace graphene { namespace chain {

void_result accs_declare_gateway_evaluator::do_evaluate( const accs_declare_gateway_operation& op )
{ try {
   const database& d = db();
   h2_require_gateway_leg( d.head_block_time() );

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

   // The gateway must bind an F1 foreign-transaction oracle.
   const oracle_object* oracle = d.find( op.oracle_id );
   FC_ASSERT( nullptr != oracle, "Bound oracle does not exist" );
   bool is_foreign_tx = false;
   for( const auto& s : oracle->series )
      if( s.get_kind() == protocol::oracle_series_kind::foreign_tx )
         { is_foreign_tx = true; break; }
   FC_ASSERT( is_foreign_tx, "Bound oracle is not a foreign-transaction oracle" );

   // Governance: the bound oracle must have at least one producer.
   FC_ASSERT( !oracle->options.producers.empty(),
              "Bound oracle has no producers" );

   // Guard-delay must fit inside the SLA window (F1F2-I04).
   const uint32_t guard_delay = d.get_global_properties().parameters.get_oracle_guard_delay_sec();
   FC_ASSERT( guard_delay < GRAPHENE_ACCS_SLA_BLOCKS * 3u,
              "Oracle guard delay exceeds the ACCS SLA window" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

object_id_type accs_declare_gateway_evaluator::do_apply( const accs_declare_gateway_operation& op ) const
{ try {
   database& d = db();

   // Carry forward any consumed-tx hashes from prior (possibly deactivated)
   // gateways for the same (chain, asset) pair, so replay protection survives
   // redeclaration.
   std::vector<protocol::foreign_tx_id> carried;
   const auto& gw_idx = d.get_index_type<accs_gateway_index>().indices();
   for( const auto& g : gw_idx )
   {
      if( g.chain_id == op.chain_id && g.foreign_asset_id == op.foreign_asset_id )
         for( const auto& h : g.consumed_tx_hashes )
            carried.push_back( h );
   }

   const auto& new_gw = d.create<accs_gateway_object>( [&op, &d, &carried]( accs_gateway_object& g ) {
      g.chain_id = op.chain_id;
      g.foreign_asset_id = op.foreign_asset_id;
      g.foreign_asset_code = op.foreign_asset_code;
      g.oracle_id = op.oracle_id;
      g.consumed_tx_hashes = carried;
      g.declared_by = op.committee_member;
      g.declared_at = d.head_block_num();
      switch( op.chain_id )
      {
         case 0: g.min_confirmations = 6; break;   // BTC
         case 1: g.min_confirmations = 12; break;  // ETH
         case 2: g.min_confirmations = 32; break;  // SOL
         default: g.min_confirmations = 6; break;
      }
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
         to_expire.push_back( protocol::accs_offer_id_type( offer.id ) );
   }
   for( protocol::accs_offer_id_type oid : to_expire )
   {
      const accs_offer_object* offer = d.find( oid );
      if( !offer || offer->state != 0 ) continue;
      d.adjust_balance( offer->seller, asset( offer->escrow_balance, offer->base_asset ) );
      d.modify( *offer, []( accs_offer_object& o ) { o.state = 3; o.escrow_balance = 0; } );
      const accs_orderbook_object* ob = d.find( protocol::accs_orderbook_id_type( offer->orderbook ) );
      if( ob )
      {
         d.modify( *ob, [&offer]( accs_orderbook_object& o ) {
            auto it = std::find( o.open_offers.begin(), o.open_offers.end(), protocol::accs_offer_id_type( offer->id ) );
            if( it != o.open_offers.end() ) o.open_offers.erase( it );
         } );
      }
   }

   // Cleanup terminal offers older than the cleanup age.
   std::vector<protocol::accs_offer_id_type> to_clean;
   for( const auto& offer : offer_idx )
   {
      if( ( offer.state == 2 || offer.state == 3 || offer.state == 4 )
          && offer.created_block > 0
          && now_block >= static_cast<uint32_t>( static_cast<uint64_t>( offer.created_block ) + GRAPHENE_ACCS_OFFER_CLEANUP_AGE ) )
         to_clean.push_back( protocol::accs_offer_id_type( offer.id ) );
   }
   for( protocol::accs_offer_id_type oid : to_clean )
   {
      const accs_offer_object* offer = d.find( oid );
      if( !offer ) continue;
      const accs_orderbook_object* ob = d.find( protocol::accs_orderbook_id_type( offer->orderbook ) );
      if( ob )
      {
         d.modify( *ob, [&offer]( accs_orderbook_object& o ) {
            auto it = std::find( o.open_offers.begin(), o.open_offers.end(), protocol::accs_offer_id_type( offer->id ) );
            if( it != o.open_offers.end() ) o.open_offers.erase( it );
            auto it2 = std::find( o.matched_offers.begin(), o.matched_offers.end(), protocol::accs_offer_id_type( offer->id ) );
            if( it2 != o.matched_offers.end() ) o.matched_offers.erase( it2 );
         } );
      }
      d.remove( *offer );
   }
}

void_result accs_create_offer_evaluator::do_evaluate( const accs_create_offer_operation& op )
{
   const database& d = db();
   h2_require_gateway_leg( d.head_block_time() );

   FC_ASSERT( nullptr != d.find( op.seller ), "Seller account does not exist" );

   const asset_object* base_asset = d.find( op.base_asset );
   FC_ASSERT( nullptr != base_asset, "Base asset does not exist" );

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
   FC_ASSERT( gateway_found, "No active gateway" );

   // State bound: cap open offers per orderbook.
   const auto& ob_idx2 = d.get_index_type<accs_orderbook_index>().indices();
   for( const auto& ob : ob_idx2 )
   {
      if( ob.base_asset == op.base_asset && ob.chain_id == op.chain_id
          && ob.foreign_asset_id == op.foreign_asset_id )
      {
         FC_ASSERT( ob.open_offers.size() < GRAPHENE_ACCS_MAX_OPEN_OFFERS_PER_ORDERBOOK,
                    "Orderbook open-offer cap reached" );
      }
   }

   FC_ASSERT( d.get_balance( op.seller, op.base_asset ) >= asset( op.base_amount, op.base_asset ),
              "Seller has insufficient balance for the offer" );

   FC_ASSERT( !op.foreign_recipient.empty(), "Foreign recipient must not be empty" );
   if( op.expiry != 0 )
      FC_ASSERT( op.expiry > d.head_block_num() + GRAPHENE_ACCS_MIN_OFFER_LIFETIME,
                 "Offer expiry below minimum lifetime" );

   return void_result();
}

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
         orderbook = const_cast<accs_orderbook_object*>( d.find( protocol::accs_orderbook_id_type( ob.id ) ) );
         break;
      }
   }

   if( !orderbook )
   {
      orderbook = const_cast<accs_orderbook_object*>( &d.create<accs_orderbook_object>( [&op]( accs_orderbook_object& o ) {
         o.base_asset = op.base_asset;
         o.chain_id = op.chain_id;
         o.foreign_asset_id = op.foreign_asset_id;
         o.next_offer_id = 1;
      } ) );
   }

   // Deduct base asset from seller (escrow)
   d.adjust_balance( op.seller, asset( -op.base_amount, op.base_asset ) );

   // Create offer
   const auto& new_offer = d.create<accs_offer_object>( [&op, &orderbook, &d]( accs_offer_object& o ) {

      o.offer_id = orderbook->next_offer_id;
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

   // Increment the monotonic offer id counter (via modify so it is undo-safe).
   d.modify( *orderbook, []( accs_orderbook_object& o ) {
      ++o.next_offer_id;
   } );

   // Add to orderbook's open offers
   d.modify( *orderbook, [&new_offer]( accs_orderbook_object& o ) {
      o.open_offers.push_back( protocol::accs_offer_id_type( new_offer.id ) );
   } );

   return new_offer.id;
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_cancel_offer_evaluator::do_evaluate( const accs_cancel_offer_operation& op )
{ try {
   const database& d = db();
   h2_require_gateway_leg( d.head_block_time() );

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

   // Return escrow to seller.
   d.adjust_balance( offer->seller, asset( offer->escrow_balance, offer->base_asset ) );

   // Mark cancelled.
   d.modify( *offer, []( accs_offer_object& o ) { o.state = 4; o.escrow_balance = 0; } ); // cancelled

   // Remove from orderbook open list.
   const accs_orderbook_object* ob = d.find( protocol::accs_orderbook_id_type( offer->orderbook ) );
   if( ob )
   {
      d.modify( *ob, [&offer]( accs_orderbook_object& o ) {
         auto it = std::find( o.open_offers.begin(), o.open_offers.end(),
                              protocol::accs_offer_id_type( offer->id ) );
         if( it != o.open_offers.end() ) o.open_offers.erase( it );
      } );
   }
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_match_offer_evaluator::do_evaluate( const accs_match_offer_operation& op )
{ try {
   const database& d = db();
   h2_require_gateway_leg( d.head_block_time() );
   FC_ASSERT( nullptr != d.find( op.buyer ), "Buyer account does not exist" );
   const accs_offer_object* offer = d.find( op.offer_id );
   FC_ASSERT( nullptr != offer, "Offer does not exist" );
   FC_ASSERT( offer->state == 0, "Only open offers can be matched" ); // 0 = open
   FC_ASSERT( offer->seller != op.buyer, "Cannot match your own offer" );
   FC_ASSERT( op.griefing_bond >= GRAPHENE_ACCS_MIN_GRIEFING_BOND_USD_CENTS,
              "Griefing bond below minimum" );
   if( offer->expiry != 0 )
      FC_ASSERT( d.head_block_num() < offer->expiry,
                 "Offer has expired" );
   FC_ASSERT( d.get_balance( op.buyer, asset_id_type() ) >= asset( op.griefing_bond, asset_id_type() ),
              "Buyer has insufficient balance for griefing bond" );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_match_offer_evaluator::do_apply( const accs_match_offer_operation& op ) const
{ try {
   database& d = db();
   const accs_offer_object* offer = d.find( op.offer_id );
   FC_ASSERT( nullptr != offer, "Offer does not exist" );

   // Deduct griefing bond from buyer (in BTS / core asset)
   d.adjust_balance( op.buyer, asset( -op.griefing_bond, asset_id_type() ) );

   // Transition to matched (state = 1)
   d.modify( *offer, [&op, &d]( accs_offer_object& o ) {
      o.state = 1; // matched
      o.matched_buyer = op.buyer;
      o.matched_at = d.head_block_num();
      o.griefing_bond = op.griefing_bond;
      o.sla_deadline = static_cast<uint32_t>( static_cast<uint64_t>( d.head_block_num() ) + GRAPHENE_ACCS_SLA_BLOCKS );
   } );

   // Move from open to matched in orderbook
   const accs_orderbook_object* ob = d.find( protocol::accs_orderbook_id_type( offer->orderbook ) );
   if( ob )
   {
      d.modify( *ob, [&offer]( accs_orderbook_object& o ) {
         auto it = std::find( o.open_offers.begin(), o.open_offers.end(), protocol::accs_offer_id_type( offer->id ) );
         if( it != o.open_offers.end() ) o.open_offers.erase( it );
         o.matched_offers.push_back( protocol::accs_offer_id_type( offer->id ) );
      } );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_fulfill_evaluator::do_evaluate( const accs_fulfill_operation& op )
{ try {
   const database& d = db();
   h2_require_gateway_leg( d.head_block_time() );
   FC_ASSERT( nullptr != d.find( op.publisher ), "Publisher does not exist" );
   const accs_offer_object* offer = d.find( op.offer_id );
   FC_ASSERT( nullptr != offer, "Offer does not exist" );
   FC_ASSERT( offer->state == 1, "Only matched offers can be fulfilled" ); // 1 = matched
   FC_ASSERT( op.amount == offer->foreign_amount, "Amount must equal offer foreign_amount" );
   FC_ASSERT( d.head_block_num() <= offer->sla_deadline, "SLA deadline exceeded" );

   // Bind to the gateway's F1 oracle first (needed for the durable replay guard).
   const accs_gateway_object* gw = nullptr;
   const auto& gw_idx = d.get_index_type<accs_gateway_index>().indices();
   for( const auto& g : gw_idx )
   {
      if( g.chain_id == offer->chain_id && g.foreign_asset_id == offer->foreign_asset_id && g.active )
      { gw = &g; break; }
   }
   FC_ASSERT( nullptr != gw, "No active gateway for this offer" );
   FC_ASSERT( gw->oracle_id != oracle_id_type(), "Gateway has no bound oracle" );

   // Durable replay protection: the foreign tx hash must not have been consumed.
   foreign_tx_id tx_id;
   FC_ASSERT( op.foreign_tx_hash.size() == 64, "Foreign tx hash must be 64 hex chars" );
   size_t decoded = fc::from_hex( op.foreign_tx_hash, reinterpret_cast<char*>( tx_id.hash.data() ), 32 );
   FC_ASSERT( decoded == 32, "Foreign tx hash is not valid hex" );
   for( const auto& h : gw->consumed_tx_hashes )
      FC_ASSERT( h != tx_id,
                 "Foreign transaction ${h} has already fulfilled an offer",
                 ("h", op.foreign_tx_hash) );

   // Publisher must be an attestor with a live bond.
   const oracle_object* oracle = d.find( gw->oracle_id );
   FC_ASSERT( nullptr != oracle, "Bound oracle does not exist" );
   FC_ASSERT( oracle->options.producers.find( op.publisher ) != oracle->options.producers.end(),
              "Publisher ${a} is not an attestor of the bound oracle", ("a", op.publisher) );
   {
      const auto& bond_idx = d.get_index_type<producer_bond_index>().indices().get<by_oracle_producer>();
      const auto bitr = bond_idx.find( boost::make_tuple( gw->oracle_id, op.publisher ) );
      FC_ASSERT( bitr != bond_idx.end() && !bitr->slashed,
                 "Publisher ${a} holds no live producer bond", ("a", op.publisher) );
   }

   // Verify the promoted F1 foreign-transaction record.
   const auto got = h2_read_foreign_tx( d, gw->oracle_id, d.head_block_time(), h2_price_liveness::live );
   FC_ASSERT( got.valid(), "No promoted foreign transaction record for this oracle" );

   // tx_id already decoded in the replay-protection block above.

   FC_ASSERT( got->tx_id == tx_id, "Foreign tx hash does not match the promoted record" );
   FC_ASSERT( got->amount == op.amount, "Foreign amount does not match the promoted record" );
   FC_ASSERT( got->kind == protocol::foreign_tx_kind::lock,
              "Promoted record is not a lock" );
   FC_ASSERT( static_cast<uint8_t>( got->chain ) == offer->chain_id,
              "Promoted record chain does not match the offer" );
   FC_ASSERT( got->foreign_asset_id == gw->foreign_asset_code,
              "Promoted record foreign asset does not match the gateway" );
   FC_ASSERT( got->confirmation_count >= gw->min_confirmations,
              "Promoted record has insufficient confirmations" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_fulfill_evaluator::do_apply( const accs_fulfill_operation& op ) const
{ try {
   database& d = db();
   const accs_offer_object* offer = d.find( op.offer_id );
   FC_ASSERT( nullptr != offer, "Offer does not exist" );

   // Release base asset to buyer
   d.adjust_balance( offer->matched_buyer, asset( offer->base_amount, offer->base_asset ) );

   // Return griefing bond to buyer (in BTS / core asset)
   d.adjust_balance( offer->matched_buyer, asset( offer->griefing_bond, asset_id_type() ) );

   // Transition to fulfilled (state = 2)
   d.modify( *offer, [&op]( accs_offer_object& o ) {
      o.state = 2; // fulfilled
      o.expected_tx_hash = op.foreign_tx_hash;
      o.escrow_balance = 0;
      o.griefing_bond = 0;
   } );

   // Durable replay guard: record the consumed tx hash on the gateway.
   const accs_gateway_object* gw2 = nullptr;
   const auto& gw_idx2 = d.get_index_type<accs_gateway_index>().indices();
   for( const auto& g : gw_idx2 )
   {
      if( g.chain_id == offer->chain_id && g.foreign_asset_id == offer->foreign_asset_id && g.active )
      { gw2 = &g; break; }
   }
   if( gw2 )
   {
      foreign_tx_id consumed_id;
      fc::from_hex( op.foreign_tx_hash, reinterpret_cast<char*>( consumed_id.hash.data() ), 32 );
      d.modify( *gw2, [&consumed_id]( accs_gateway_object& g ) {
         g.consumed_tx_hashes.push_back( consumed_id );
      } );
   }

   // Remove from orderbook's matched offers
   const accs_orderbook_object* ob = d.find( protocol::accs_orderbook_id_type( offer->orderbook ) );
   if( ob )
   {
      d.modify( *ob, [&offer]( accs_orderbook_object& o ) {
         auto it = std::find( o.matched_offers.begin(), o.matched_offers.end(), protocol::accs_offer_id_type( offer->id ) );
         if( it != o.matched_offers.end() ) o.matched_offers.erase( it );
      } );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_claim_griefing_evaluator::do_evaluate( const accs_claim_griefing_operation& op )
{ try {
   const database& d = db();
   h2_require_gateway_leg( d.head_block_time() );
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

   // Transfer griefing bond to seller (in BTS / core asset)
   d.adjust_balance( offer->seller, asset( offer->griefing_bond, asset_id_type() ) );

   // Return escrow to seller
   d.adjust_balance( offer->seller, asset( offer->escrow_balance, offer->base_asset ) );

   // Transition to expired (state = 3)
   d.modify( *offer, []( accs_offer_object& o ) {
      o.state = 3; // expired
      o.escrow_balance = 0;
      o.griefing_bond = 0;
   } );

   // Remove from orderbook's matched offers
   const accs_orderbook_object* ob = d.find( protocol::accs_orderbook_id_type( offer->orderbook ) );
   if( ob )
   {
      d.modify( *ob, [&offer]( accs_orderbook_object& o ) {
         auto it = std::find( o.matched_offers.begin(), o.matched_offers.end(), protocol::accs_offer_id_type( offer->id ) );
         if( it != o.matched_offers.end() ) o.matched_offers.erase( it );
      } );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_deactivate_gateway_evaluator::do_evaluate( const accs_deactivate_gateway_operation& op )
{ try {
   const database& d = db();
   h2_require_gateway_leg( d.head_block_time() );
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
