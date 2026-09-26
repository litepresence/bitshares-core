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
#include <graphene/chain/oracle_evaluator.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/reference_asset_object.hpp>

#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/hardfork.hpp>

namespace graphene { namespace chain {

namespace {

/// Every producer must exist, and the assets an oracle quotes must exist. Checked here rather
/// than left to first use: an oracle referencing a deleted account or a nonexistent asset
/// would look configured while being unable to ever report a value.
void check_producers_exist( const database& d, const oracle_options& options )
{
   for( const auto& p : options.producers )
      FC_ASSERT( nullptr != d.find( p.first ),
                 "Producer account ${a} does not exist", ("a", p.first) );
}

/**
 * Whether @p account may create a reference asset right now. Creation starts committee-only
 * and opens to everyone when the committee sets the chain parameter -- opening it later
 * then needs no hardfork. Committee-only means the committee account itself (acting
 * through a committee proposal) or an account holding a committee membership.
 */
bool may_create_reference_asset( const database& d, account_id_type account )
{
   const auto& params = d.get_global_properties().parameters;
   if( params.extensions.value.allow_public_reference_asset_creation.valid()
       && *params.extensions.value.allow_public_reference_asset_creation )
      return true;
   if( account == GRAPHENE_COMMITTEE_ACCOUNT )
      return true;
   const auto& idx = d.get_index_type<committee_member_index>().indices().get<by_account>();
   return idx.find( account ) != idx.end();
}

/**
 * Pushes a new value out to every market-issued asset fed by this oracle.
 *
 * Walking the oracle's own subscriber set rather than every bitasset on the chain: publishing
 * is designed to happen every few seconds, and work proportional to the chain's total asset
 * count does not belong in it. The set is capped at GRAPHENE_ORACLE_MAX_SUBSCRIBERS.
 */
void refresh_subscribers( database& d, const oracle_object& o )
{
   for( const auto& asset_id : o.subscribers )
   {
      const asset_object* a = d.find( asset_id );
      if( nullptr == a || !a->is_market_issued() )
         continue;   // defensive: an asset cannot stop being an MPA, but never assume it
      d.update_bitasset_current_feed( a->bitasset_data( d ) );
   }
}

} // namespace

void_result reference_asset_create_evaluator::do_evaluate(
      const reference_asset_create_operation& op ) const
{ try {
   const database& d = db();

   FC_ASSERT( HARDFORK_ORACLE_PASSED( d.head_block_time() ),
              "Not allowed until the oracle hardfork" );

   FC_ASSERT( nullptr != d.find( op.creator ),
              "Creator account ${a} does not exist", ("a", op.creator) );

   FC_ASSERT( may_create_reference_asset( d, op.creator ),
              "Reference asset creation is committee-only until the committee opens it" );

   // Symbols live in the reference assets' own namespace, but within it a duplicate is the
   // way to get a consumer to reference the wrong value.
   const auto& idx = d.get_index_type<reference_asset_index>().indices().get<by_reference_symbol>();
   FC_ASSERT( idx.find( op.symbol ) == idx.end(),
              "A reference asset named '${s}' already exists", ("s", op.symbol) );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

object_id_type reference_asset_create_evaluator::do_apply(
      const reference_asset_create_operation& op ) const
{ try {
   const auto& new_ref = db().create<reference_asset_object>( [&op]( reference_asset_object& o ) {
      o.creator     = op.creator;
      o.symbol      = op.symbol;
      o.precision   = op.precision;
      o.description = op.description;
      // No update operation exists, so symbol and precision are immutable by construction:
      // what is stored here is final.
   } );
   return new_ref.id;
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result oracle_create_evaluator::do_evaluate( const oracle_create_operation& op ) const
{ try {
   const database& d = db();

   FC_ASSERT( HARDFORK_ORACLE_PASSED( d.head_block_time() ),
              "Not allowed until the oracle hardfork" );

   op.base(d);    // throws if the reference asset does not exist
   op.quote(d);
   check_producers_exist( d, op.options );

   // Names are how humans address an oracle, so a duplicate is not a harmless collision --
   // it is the way to get a consumer to reference the wrong series.
   const auto& idx = d.get_index_type<oracle_index>().indices().get<by_oracle_name>();
   FC_ASSERT( idx.find( op.name ) == idx.end(),
              "An oracle named '${n}' already exists", ("n", op.name) );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

object_id_type oracle_create_evaluator::do_apply( const oracle_create_operation& op ) const
{ try {
   const auto& new_oracle = db().create<oracle_object>( [&op]( oracle_object& o ) {
      o.owner       = op.owner;
      o.name        = op.name;
      o.description = op.description;
      o.base        = op.base;
      o.quote       = op.quote;
      o.series      = op.series;
      o.options     = op.options;
      // current_value stays absent: a new oracle reports nothing until its producers have
      // published enough values to meet quorum.
   } );
   return new_oracle.id;
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result oracle_update_evaluator::do_evaluate( const oracle_update_operation& op )
{ try {
   const database& d = db();

   FC_ASSERT( HARDFORK_ORACLE_PASSED( d.head_block_time() ),
              "Not allowed until the oracle hardfork" );

   _oracle = &op.oracle_id(d);
   FC_ASSERT( _oracle->owner == op.owner, "Only the oracle's owner may update it" );

   if( op.new_options.valid() )
      check_producers_exist( d, *op.new_options );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result oracle_update_evaluator::do_apply( const oracle_update_operation& op ) const
{ try {
   database& d = db();
   const auto now = d.head_block_time();

   d.modify( *_oracle, [&op]( oracle_object& o ) {
      if( op.new_description.valid() )
         o.description = *op.new_description;
      if( op.new_options.valid() )
         o.options = *op.new_options;
      // base, quote, series and name have no fields in the update operation: what an
      // oracle measures cannot change underneath its consumers.
   } );

   // Policy changes take effect immediately rather than at the next publish. Removing a
   // producer, tightening quorum or shortening the lifetime are the things an owner does in
   // response to a problem, and leaving the old aggregate standing until someone happens to
   // publish would defeat the point.
   if( op.new_options.valid() )
   {
      d.modify( *_oracle, [now]( oracle_object& o ) { o.update_current_value( now ); } );
      // Tightening quorum or dropping a producer can change or remove the value, and any
      // asset fed by this oracle has to see that immediately, not at the next publish.
      refresh_subscribers( d, *_oracle );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result oracle_delete_evaluator::do_evaluate( const oracle_delete_operation& op )
{ try {
   const database& d = db();

   FC_ASSERT( HARDFORK_ORACLE_PASSED( d.head_block_time() ),
              "Not allowed until the oracle hardfork" );

   _oracle = &op.oracle_id(d);
   FC_ASSERT( _oracle->owner == op.owner, "Only the oracle's owner may delete it" );

   // Deleting an oracle a smartcoin depends on would leave that asset with no price source,
   // unable to margin call or force-settle. The issuer must unbind first. (Deleting a
   // reference asset something references is refused the same way; see the
   // asset_update_bitasset evaluator's mapping checks.)
   FC_ASSERT( _oracle->subscribers.empty(),
              "Oracle '${n}' is still the price source for ${c} asset(s); clear their "
              "price_oracle_id first", ("n", _oracle->name)("c", _oracle->subscribers.size()) );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result oracle_delete_evaluator::do_apply( const oracle_delete_operation& op ) const
{ try {
   db().remove( *_oracle );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result oracle_publish_evaluator::do_evaluate( const oracle_publish_operation& op )
{ try {
   const database& d = db();

   FC_ASSERT( HARDFORK_ORACLE_PASSED( d.head_block_time() ),
              "Not allowed until the oracle hardfork" );

   _oracle = &op.oracle_id(d);

   FC_ASSERT( _oracle->options.producers.count( op.producer ) > 0,
              "Account ${a} is not a producer of oracle '${n}'",
              ("a", op.producer)("n", _oracle->name) );

   // One value per declared series, in order. Padding or truncating here would let a
   // producer shift every series' meaning for a round.
   FC_ASSERT( op.values.size() == _oracle->series.size(),
              "Oracle '${n}' declares ${s} series but the submission carries ${v} values",
              ("n", _oracle->name)("s", _oracle->series.size())("v", op.values.size()) );

   // The relations a single submission must satisfy. bid <= ask and down-rounded <=
   // up-rounded hold per producer by enforcement here; aggregation over the same producer
   // set then keeps them true for the aggregate (see ORACLE-DESIGN.md "Series").
   using protocol::oracle_series_kind;
   using protocol::oracle_series_rounding;
   for( size_t i = 0; i < _oracle->series.size(); ++i )
      for( size_t j = 0; j < _oracle->series.size(); ++j )
      {
         if( _oracle->series[i].get_kind() == oracle_series_kind::bid
             && _oracle->series[j].get_kind() == oracle_series_kind::ask )
            FC_ASSERT( !( op.values[j] < op.values[i] ),
                       "Published bid exceeds ask in oracle '${n}'",
                       ("n", _oracle->name) );
         if( _oracle->series[i].get_kind() == _oracle->series[j].get_kind()
             && _oracle->series[i].get_rounding() == oracle_series_rounding::down
             && _oracle->series[j].get_rounding() == oracle_series_rounding::up )
            FC_ASSERT( !( op.values[j] < op.values[i] ),
                       "Published down-rounded value exceeds the up-rounded value of the "
                       "same kind in oracle '${n}'", ("n", _oracle->name) );
      }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result oracle_publish_evaluator::do_apply( const oracle_publish_operation& op ) const
{ try {
   database& d = db();
   const auto now = d.head_block_time();

   d.modify( *_oracle, [&op, now]( oracle_object& o ) {
      o.submissions[op.producer] = std::make_pair( now, op.values );
      o.update_current_value( now );
   } );

   refresh_subscribers( d, *_oracle );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

} } // graphene::chain
