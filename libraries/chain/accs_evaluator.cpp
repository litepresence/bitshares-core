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

   // At most one gateway record exists per (chain_id, foreign_asset_id) pair;
   // the pair index enforces the invariant, so a new declaration only conflicts
   // with an ACTIVE record of the same pair.
   const auto& gw_idx = d.get_index_type<accs_gateway_index>().indices().get<by_chain_asset>();
   const auto gw_itr = gw_idx.find( boost::make_tuple( op.chain_id, op.foreign_asset_id ) );
   FC_ASSERT( gw_itr == gw_idx.end() || !gw_itr->active,
              "Active gateway already exists for chain ${c} asset ${a}",
              ("c", op.chain_id)("a", op.foreign_asset_id) );

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

   // Replay-set durability (F1F2-C01): replay protection lives on
   // accs_consumed_tx rows keyed (chain_id, foreign_asset_id, tx), never on
   // the gateway instance, so deactivation and redeclaration cannot reset it.
   // The gateway record only carries an acceleration counter, re-synced from
   // the rows on every (re)declaration, so the count can never silently
   // reset even if the pair's record is recreated.
   // Spec: docs/superpowers/specs/2026-10-24-three-track-split-design.md §9
   const auto& gw_idx = d.get_index_type<accs_gateway_index>().indices().get<by_chain_asset>();
   const auto gw_itr = gw_idx.find( boost::make_tuple( op.chain_id, op.foreign_asset_id ) );
   const uint32_t head_block = d.head_block_num();
   uint32_t consumed_count = 0;
   {
      // Committee-frequency resync: count the pair's consumed rows once, on
      // every (re)declaration, so the counter cannot drift from the durable
      // rows. chain_id 3 is the first value past the declared range.
      const auto& cidx = d.get_index_type<accs_consumed_tx_index>()
                            .indices().get<by_chain_asset_tx>();
      auto lower = cidx.lower_bound( boost::make_tuple( op.chain_id, std::string(),
                                                        protocol::foreign_tx_id() ) );
      auto upper = cidx.lower_bound( boost::make_tuple( uint8_t( 3 ), std::string(),
                                                        protocol::foreign_tx_id() ) );
      consumed_count = static_cast<uint32_t>( std::distance( lower, upper ) );
   }

   if( gw_itr != gw_idx.end() )
   {
      // Redeclaration reuses the pair's existing record in place instead of
      // stacking a second object on the same (chain, asset) pair.
      d.modify( *gw_itr, [&op, &head_block, &consumed_count]( accs_gateway_object& g ) {
         g.foreign_asset_code = op.foreign_asset_code;
         g.oracle_id = op.oracle_id;
         g.declared_by = op.committee_member;
         g.declared_at = head_block;
         switch( op.chain_id )
         {
            case 0: g.min_confirmations = 6; break;   // BTC
            case 1: g.min_confirmations = 12; break;  // ETH
            case 2: g.min_confirmations = 32; break;  // SOL
            default: g.min_confirmations = 6; break;
         }
         g.active = true;
         g.consumed_tx_count = consumed_count;
      } );
      return gw_itr->id;
   }

   const auto& new_gw = d.create<accs_gateway_object>( [&op, &head_block,
                                                        &consumed_count]( accs_gateway_object& g ) {
      g.chain_id = op.chain_id;
      g.foreign_asset_id = op.foreign_asset_id;
      g.foreign_asset_code = op.foreign_asset_code;
      g.oracle_id = op.oracle_id;
      g.consumed_tx_count = consumed_count;
      g.declared_by = op.committee_member;
      g.declared_at = head_block;
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
      if( offer.state == static_cast<uint8_t>( accs_offer_state::open )
          && offer.expiry > 0 && now_block >= offer.expiry )
         to_expire.push_back( protocol::accs_offer_id_type( offer.id ) );
   }
   for( protocol::accs_offer_id_type oid : to_expire )
   {
      const accs_offer_object* offer = d.find( oid );
      if( !offer || offer->state != static_cast<uint8_t>( accs_offer_state::open ) ) continue;
      d.adjust_balance( offer->seller, asset( offer->escrow_balance, offer->base_asset ) );
      d.modify( *offer, []( accs_offer_object& o ) {
         o.state = static_cast<uint8_t>( accs_offer_state::expired );
         o.escrow_balance = 0;
      } );
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
      const uint8_t os = offer.state;
      if( ( os == static_cast<uint8_t>( accs_offer_state::fulfilled )
            || os == static_cast<uint8_t>( accs_offer_state::expired )
            || os == static_cast<uint8_t>( accs_offer_state::cancelled ) )
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

   const auto& gw_idx = d.get_index_type<accs_gateway_index>().indices().get<by_chain_asset>();
   const auto gw_itr = gw_idx.find( boost::make_tuple( op.chain_id, op.foreign_asset_id ) );
   FC_ASSERT( gw_itr != gw_idx.end() && gw_itr->active, "No active gateway" );

   // Per-chain recipient format bounds (M06): conservative charset + length
   // only, checked in validate() and again here; no address checksums in
   // consensus. Spec: docs/superpowers/specs/2026-10-20-f2-accs-orderbook-settlement.md §3.1
   protocol::accs_validate_foreign_recipient( op.chain_id, op.foreign_recipient );

   // State bound: cap open offers per orderbook (I06) — the cap refuses a new
   // offer, never evicts an existing one, so open_offer vectors stay bounded.
   const auto& ob_idx = d.get_index_type<accs_orderbook_index>().indices().get<by_pair>();
   const auto ob_itr = ob_idx.find( boost::make_tuple( op.base_asset, op.chain_id,
                                                       op.foreign_asset_id ) );
   if( ob_itr != ob_idx.end() )
      FC_ASSERT( ob_itr->open_offers.size() < GRAPHENE_ACCS_MAX_OPEN_OFFERS_PER_ORDERBOOK,
                 "Orderbook open-offer cap reached" );

   // State bound: cap open offers per seller (I06) so a single account cannot
   // stack an unbounded number of escrowed offers across orderbooks. The walk
   // is bounded by the seller's own open offers, not the whole offer set.
   {
      const auto& of_idx = d.get_index_type<accs_offer_index>()
                              .indices().get<by_seller_state>();
      auto sitr = of_idx.lower_bound( boost::make_tuple( op.seller,
                          static_cast<uint8_t>( accs_offer_state::open ) ) );
      uint32_t open_count = 0;
      while( sitr != of_idx.end()
             && sitr->seller == op.seller
             && sitr->state == static_cast<uint8_t>( accs_offer_state::open ) )
      {
         ++open_count;
         ++sitr;
      }
      FC_ASSERT( open_count < GRAPHENE_ACCS_MAX_OPEN_OFFERS_PER_ACCOUNT,
                 "Seller open-offer cap reached" );
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
   // through the pair index.
   accs_orderbook_object* orderbook = nullptr;
   const auto& ob_idx = d.get_index_type<accs_orderbook_index>().indices().get<by_pair>();
   const auto ob_itr = ob_idx.find( boost::make_tuple( op.base_asset, op.chain_id,
                                                       op.foreign_asset_id ) );
   if( ob_itr != ob_idx.end() )
      orderbook = const_cast<accs_orderbook_object*>( &*ob_itr );

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
      o.state = static_cast<uint8_t>( accs_offer_state::open );
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
   FC_ASSERT( offer->state == static_cast<uint8_t>( accs_offer_state::open ),
              "Only open offers can be cancelled" );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_cancel_offer_evaluator::do_apply( const accs_cancel_offer_operation& op ) const
{ try {
   database& d = db();
   const accs_offer_object* offer = d.find( op.offer_id );
   FC_ASSERT( nullptr != offer, "Offer does not exist" );

   // Release escrow to seller. Supply invariant: balances in circulation +
   // outstanding escrow_balance must keep summing to the base asset's supply,
   // so the locked field reads zero after the terminal transition (M07).
   d.adjust_balance( offer->seller, asset( offer->escrow_balance, offer->base_asset ) );

   // Mark cancelled; escrow_balance is the authoritative locked field and is
   // zeroed on the terminal transition (M07).
   d.modify( *offer, []( accs_offer_object& o ) {
      o.state = static_cast<uint8_t>( accs_offer_state::cancelled );
      o.escrow_balance = 0;
   } );

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
   FC_ASSERT( offer->state == static_cast<uint8_t>( accs_offer_state::open ),
              "Only open offers can be matched" );
   FC_ASSERT( offer->seller != op.buyer, "Cannot match your own offer" );
   FC_ASSERT( op.griefing_bond >= GRAPHENE_ACCS_MIN_GRIEFING_BOND_USD_CENTS,
              "Griefing bond below minimum" );
   if( offer->expiry != 0 )
      FC_ASSERT( d.head_block_num() < offer->expiry,
                 "Offer has expired" );

   // An offer whose gateway is deactivated cannot take a new buyer bond (M09):
   // a match would extend the pair's active settlement surface after the
   // committee shut the gateway down.
   const auto& gw_idx = d.get_index_type<accs_gateway_index>().indices().get<by_chain_asset>();
   const auto gw_itr = gw_idx.find( boost::make_tuple( offer->chain_id, offer->foreign_asset_id ) );
   FC_ASSERT( gw_itr != gw_idx.end() && gw_itr->active,
              "Offer's gateway is not active" );

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

   // Transition to matched
   d.modify( *offer, [&op, &d]( accs_offer_object& o ) {
      o.state = static_cast<uint8_t>( accs_offer_state::matched );
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
   FC_ASSERT( offer->state == static_cast<uint8_t>( accs_offer_state::matched ),
              "Only matched offers can be fulfilled" );
   FC_ASSERT( op.amount == offer->foreign_amount, "Amount must equal offer foreign_amount" );
   FC_ASSERT( d.head_block_num() <= offer->sla_deadline, "SLA deadline exceeded" );

   // Locate the pair's gateway record through the pair index. The record may
   // be inactive; the active check below is what an exchange against this
   // offer requires. A bound oracle without an object is refused by the
   // existence check that follows (the former identity sentinel also rejected
   // the first oracle of a chain, whose id equals the default id value).
   const auto& gw_idx = d.get_index_type<accs_gateway_index>().indices().get<by_chain_asset>();
   const auto gw_itr = gw_idx.find( boost::make_tuple( offer->chain_id, offer->foreign_asset_id ) );
   FC_ASSERT( gw_itr != gw_idx.end(), "No gateway record for this offer" );
   FC_ASSERT( gw_itr->active, "No active gateway for this offer" );
   const accs_gateway_object* gw = &*gw_itr;

   // Governance/validation of the bound oracle must be re-checked here: the
   // gateway record is the attestor binding, not the op's oracle field.
   const oracle_object* gw_oracle = d.find( gw->oracle_id );
   FC_ASSERT( nullptr != gw_oracle, "Gateway has no bound oracle" );

   // Validate and decode the 32-byte foreign tx id. The operation's validate()
   // enforces the canonical lowercase hex wire form, so comparing the decoded
   // bytes is exact equality.
   foreign_tx_id tx_id;
   FC_ASSERT( op.foreign_tx_hash.size() == 64, "Foreign tx hash must be 64 hex chars" );
   size_t decoded = fc::from_hex( op.foreign_tx_hash, reinterpret_cast<char*>( tx_id.hash.data() ), 32 );
   FC_ASSERT( decoded == 32, "Foreign tx hash is not valid hex" );

   // Durable replay protection (F1F2-C01): the consumed set lives on
   // accs_consumed_tx rows keyed (chain_id, foreign_asset_id, tx), independent
   // of any gateway instance; committee deactivation and redeclaration cannot
   // reset or recreate it. Byte equality on the decoded tx id.
   // Spec: docs/superpowers/specs/2026-10-24-three-track-split-design.md §9
   const auto& consumed_idx = d.get_index_type<accs_consumed_tx_index>()
                                 .indices().get<by_chain_asset_tx>();
   FC_ASSERT( consumed_idx.find( boost::make_tuple( offer->chain_id, offer->foreign_asset_id,
                                                    tx_id ) ) == consumed_idx.end(),
              "Foreign transaction has already fulfilled an offer for this pair" );

   // The pair's replay set is capped; the cap is carried on the pair's gateway
   // record and re-synced from the rows at each (re)declaration. At the cap the
   // set fails closed: this fulfill is refused, no older guard is evicted, and
   // the set never silently resets.
   FC_ASSERT( gw->consumed_tx_count < GRAPHENE_ACCS_MAX_CONSUMED_TX_PER_PAIR,
              "Consumed-tx replay set at cap for chain ${c} asset ${a}",
              ("c", offer->chain_id)("a", offer->foreign_asset_id) );

   // Publisher must be an attestor with a live bond.
   FC_ASSERT( gw_oracle->options.producers.find( op.publisher ) != gw_oracle->options.producers.end(),
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

   FC_ASSERT( got->tx_id == tx_id, "Foreign tx hash does not match the promoted record" );
   FC_ASSERT( got->amount == op.amount, "Foreign amount does not match the promoted record" );
   // Kind-mapping invariant (N03): an ACCS offer is a lock-flow settlement, so
   // only foreign_tx_kind::lock records satisfy it — lock/mint records map to
   // the lock flow while withdraw/burn records map to no ACCS offer flow.
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

   // Release base asset to buyer and return the griefing bond to buyer.
   // Supply invariant (F1F2-I03): asset balances in circulation +
   // offer.escrow_balance (base) and outstanding griefing_bond (core) must
   // keep summing to the assets' supplies; releasing the locked values moves
   // them without minting or burning, so both fields read zero on the
   // terminal offer below.
   d.adjust_balance( offer->matched_buyer, asset( offer->base_amount, offer->base_asset ) );

   // Return griefing bond to buyer (in BTS / core asset)
   d.adjust_balance( offer->matched_buyer, asset( offer->griefing_bond, asset_id_type() ) );

   // Transition to fulfilled
   d.modify( *offer, [&op]( accs_offer_object& o ) {
      o.state = static_cast<uint8_t>( accs_offer_state::fulfilled );
      o.expected_tx_hash = op.foreign_tx_hash;
      o.escrow_balance = 0;
      o.griefing_bond = 0;
   } );

   // Durable replay guard (F1F2-C01): create the consumed-tx row keyed
   // (chain_id, foreign_asset_id, tx). Rows survive every gateway lifecycle
   // event, are byte-compared at every fulfill, and only this path (and the
   // committee's count resync at declaration) touch them.
   // Spec: docs/superpowers/specs/2026-10-24-three-track-split-design.md §9
   foreign_tx_id consumed_id;
   FC_ASSERT( op.foreign_tx_hash.size() == 64, "Foreign tx hash must be 64 hex chars" );
   size_t decoded = fc::from_hex( op.foreign_tx_hash, reinterpret_cast<char*>( consumed_id.hash.data() ), 32 );
   FC_ASSERT( decoded == 32, "Foreign tx hash is not valid hex" );
   const auto& gw_idx = d.get_index_type<accs_gateway_index>().indices().get<by_chain_asset>();
   const auto gw_itr = gw_idx.find( boost::make_tuple( offer->chain_id, offer->foreign_asset_id ) );
   FC_ASSERT( gw_itr != gw_idx.end(), "No gateway record for this offer" );
   // Fail-closed cap on the apply side: create the row only under the cap, so
   // the row count never grows past GRAPHENE_ACCS_MAX_CONSUMED_TX_PER_PAIR
   // even if the counter were stale; the evaluate-side pre-check refused at
   // count >= cap, and this guard enforces the same bound at mutation time.
   FC_ASSERT( gw_itr->consumed_tx_count < GRAPHENE_ACCS_MAX_CONSUMED_TX_PER_PAIR,
              "Consumed-tx replay set at cap for this pair" );

   d.create<accs_consumed_tx_object>( [&]( accs_consumed_tx_object& c ) {
      c.chain_id = offer->chain_id;
      c.foreign_asset_id = offer->foreign_asset_id;
      c.tx = consumed_id;
      c.consumed_block = d.head_block_num();
   } );
   d.modify( *gw_itr, []( accs_gateway_object& g ) { ++g.consumed_tx_count; } );

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
   FC_ASSERT( offer->state == static_cast<uint8_t>( accs_offer_state::matched ),
              "Only matched offers can be claimed" );
   FC_ASSERT( d.head_block_num() > offer->sla_deadline, "SLA deadline not yet exceeded" );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_claim_griefing_evaluator::do_apply( const accs_claim_griefing_operation& op ) const
{ try {
   database& d = db();
   const accs_offer_object* offer = d.find( op.offer_id );
   FC_ASSERT( nullptr != offer, "Offer does not exist" );

   // One ordered sequence of balance moves (M10): the griefing bond moves to
   // the seller first, then the escrow, then the offer's row state is
   // written. Supply invariant: balances in circulation + escrow_balance
   // (base) + griefing_bond (core) outstanding must keep summing to the
   // assets' supplies; both locked fields read zero after the move below.
   d.adjust_balance( offer->seller, asset( offer->griefing_bond, asset_id_type() ) );

   // Return escrow to seller
   d.adjust_balance( offer->seller, asset( offer->escrow_balance, offer->base_asset ) );

   // Transition to expired; escrow_balance is the authoritative locked field
   // and griefing_bond the bond field; both zero on the terminal transition.
   d.modify( *offer, []( accs_offer_object& o ) {
      o.state = static_cast<uint8_t>( accs_offer_state::expired );
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

   // Find active gateway through the pair index
   bool found = false;
   const auto& gw_idx = d.get_index_type<accs_gateway_index>().indices().get<by_chain_asset>();
   const auto gw_itr = gw_idx.find( boost::make_tuple( op.chain_id, op.foreign_asset_id ) );
   found = ( gw_itr != gw_idx.end() && gw_itr->active );
   FC_ASSERT( found, "No active gateway to deactivate" );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result accs_deactivate_gateway_evaluator::do_apply( const accs_deactivate_gateway_operation& op ) const
{ try {
   database& d = db();
   const auto& gw_idx = d.get_index_type<accs_gateway_index>().indices().get<by_chain_asset>();
   const auto gw_itr = gw_idx.find( boost::make_tuple( op.chain_id, op.foreign_asset_id ) );
   FC_ASSERT( gw_itr != gw_idx.end() && gw_itr->active, "No active gateway to deactivate" );
   d.modify( *gw_itr, []( accs_gateway_object& g ) {
      g.active = false;
   } );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

} } // graphene::chain
