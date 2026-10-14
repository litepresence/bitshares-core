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
#include <graphene/chain/bond_evaluator.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/challenge_object.hpp>
#include <graphene/chain/h2_economics_evaluator.hpp>
#include <graphene/chain/h2_economics_object.hpp>
#include <graphene/chain/vault_object.hpp>

#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_activation.hpp>
#include <graphene/chain/hardfork.hpp>

#include <algorithm>

namespace graphene { namespace chain {

namespace {

/// Every producer must exist, and the reference assets an oracle quotes must exist.
/// Checked here rather than left to first use: an oracle referencing a deleted account
/// or a nonexistent reference asset would look configured while being unable to ever
/// report a value.
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
   const auto itr = idx.find( account );
   if( itr == idx.end() )
      return false;
   // GOV-R9-01: registry rows are permissionless (op-29, LTM only) and never
   // pruned, so registry membership alone is a sybil door. The gate is the
   // stake-elected set; the lookup above still identifies the member object.
   const auto& elected = d.get_global_properties().active_committee_members;
   return std::find( elected.begin(), elected.end(), itr->get_id() ) != elected.end();
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

    // The core asset maps 1:1 to "BTS" by protocol rule at the core asset's own precision
    // (5): a BTS reference at any other precision would silently mis-scale every
    // core-quoted conversion. Refused here in consensus as well as in validate().
    if( op.symbol == GRAPHENE_REFERENCE_ASSET_BTS_SYMBOL )
       FC_ASSERT( op.precision == GRAPHENE_REFERENCE_ASSET_BTS_PRECISION,
                  "The BTS reference asset must have precision ${p}, matching the core asset",
                  ("p", GRAPHENE_REFERENCE_ASSET_BTS_PRECISION) );

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

   // R-02 owner-unfreeze bypass closed: an owner clear of `frozen` (currently
   // frozen, new options set false) is refused while the oracle carries open
   // disputes OR a challenge-set freeze (sustained/expiry terminal dispute
   // for this oracle). Track A owner freezes (no open disputes, no
   // sustained/expired history) still clear here; challenge-set freezes clear
   // only through the committee oracle_unfreeze op. Slash stays flag-only.
   if( _oracle->options.frozen && op.new_options.valid() && !op.new_options->frozen )
   {
      FC_ASSERT( _oracle->open_disputes == 0,
                 "Oracle carries open disputes; owner unfreeze refused until "
                 "resolution (committee oracle_unfreeze after resolution)" );
      const auto& dispute_idx = d.get_index_type<oracle_dispute_index>()
                                   .indices().get<by_dispute_oracle>();
      const auto range = dispute_idx.equal_range( op.oracle_id );
      for( auto itr = range.first; itr != range.second; ++itr )
         FC_ASSERT( itr->state != GRAPHENE_H2_CHALLENGE_SUSTAINED
                    && itr->state != GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN,
                    "Oracle freeze was challenge-set (dispute ${x}); owner "
                    "unfreeze refused, use committee oracle_unfreeze",
                    ("x", itr->id) );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result oracle_update_evaluator::do_apply( const oracle_update_operation& op ) const
{ try {
   database& d = db();
   const auto now = d.head_block_time();
   // Guard inputs come from chain state the object cannot see: the committee-owned
   // delay and the maintenance interval bounding the rate-limit counter.
   const uint32_t delay_sec = d.get_global_properties().parameters.get_oracle_guard_delay_sec();
   const uint32_t maint_sec = d.get_global_properties().parameters.maintenance_interval;

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
      d.modify( *_oracle, [now, delay_sec, maint_sec]( oracle_object& o )
         { o.update_current_value( now, delay_sec, maint_sec ); } );
      // Tightening quorum or dropping a producer can change or remove the value, and any
      // asset fed by this oracle has to see that immediately, not at the next publish.
      // Freezing behaves the same way: the bound feed goes null in this block.
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

   // X-08 lifecycle seam: H2 legs reference the oracle by id, and deletion
   // would strand state no path can repair (a vault's bound_oracle pins with
   // no rebind path; dispute/vault economics read the object itself).
   // Refuse while any of the four legs is live. No extra hardfork gate: every
   // leg below is H2-created state (disputes, bound vaults, producer bonds,
   // forfeit pools cannot predate the H2 legs), so pre-H2 history replays
   // identically. Mirrors the open-dispute refusal on the update (:194) and
   // unfreeze (:456) paths.
   FC_ASSERT( _oracle->open_disputes == 0,
              "Oracle '${n}' carries open disputes; deletion refused until resolution",
              ("n", _oracle->name) );
   for( const vault_object& v : d.get_index_type<vault_index>().indices() )
      FC_ASSERT( !v.bound_oracle.valid() || *v.bound_oracle != _oracle->get_id(),
                 "Vault ${v} is canonically bound to oracle '${n}'; deletion refused",
                 ("v", v.id)("n", _oracle->name) );
   {
      const auto& pb_idx = d.get_index_type<producer_bond_index>()
                              .indices().get<by_oracle_producer>();
      const auto pitr = pb_idx.lower_bound(
            boost::make_tuple( _oracle->get_id(), account_id_type() ) );
      FC_ASSERT( pitr == pb_idx.end() || pitr->oracle != _oracle->get_id(),
                 "Oracle '${n}' still secures producer bonds; deletion refused",
                 ("n", _oracle->name) );
   }
   FC_ASSERT( _oracle->forfeit_pool_balance == share_type( 0 ),
              "Oracle '${n}' holds an undistributed forfeit pool; deletion refused "
              "until the reward sweep settles it",
              ("n", _oracle->name) );

   // Deleting an oracle a smartcoin depends on would leave that asset with no price source,
   // unable to margin call or force-settle. Deletion is refused while any subscriber's
   // binding is still LIVE; STALE subscribers (mapping drift, series out of range -- see
   // the F5 prune rule in do_apply) are pruned instead of blocking. An EXPIRED explicit
   // binding is stale the same way: past its consensus expiry height the pair reads no
   // price, so deleting the oracle strands nothing that was still feeding. (Reference assets need
   // no equivalent guard at all: there is no reference-asset delete operation -- symbol
   // and precision are immutable by construction, so a reference a consumer points at can
   // never disappear.)
   const uint32_t head_num = d.head_block_num();
   for( const auto& asset_id : _oracle->subscribers )
   {
      const asset_object* a = d.find( asset_id );
      if( nullptr == a || !a->is_market_issued() )
         continue;   // defensive: pruned in apply, never blocking
      const auto& exts = a->bitasset_data( d ).options.extensions.value;
      optional<oracle_id_type> bound_id;
      uint16_t bound_series = 0;
      if( exts.price_oracle_binding.valid() )
      {
         bound_id     = exts.price_oracle_binding->oracle_id;
         bound_series = exts.price_oracle_binding->series;
      }
      else if( exts.price_oracle_id.valid() )
         bound_id = *exts.price_oracle_id;
      if( !bound_id.valid() || *bound_id != _oracle->get_id() )
         continue;   // bound elsewhere (or unbound): stale for this oracle
      if( is_price_oracle_binding_expired( exts.price_oracle_binding, head_num ) )
         continue;   // past its consensus expiry: stale for this oracle, pruned not blocking
      const auto debt_mapping = get_effective_reference_mapping( d, asset_id );
      const auto backing_mapping = get_effective_reference_mapping(
            d, a->bitasset_data( d ).options.short_backing_asset );
      if( debt_mapping.valid() && backing_mapping.valid()
          && is_smartcoin_binding_valid( *_oracle, bound_series,
                                         *debt_mapping, *backing_mapping ) )
         FC_ASSERT( false,
                    "Oracle '${n}' still feeds ${a} through a live binding; clear the "
                    "price_oracle_binding first (stale, drifted bindings are pruned, not "
                    "blocking)",
                    ("n", _oracle->name)("a", asset_id) );
   }

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

void_result oracle_delete_evaluator::do_apply( const oracle_delete_operation& op ) const
{ try {
   database& d = db();

   // F5 PRUNE RULE. A subscriber entry is STALE when the asset's stored binding no longer
   // validates (mapping drift since binding, a named series outside the oracle's list, an
   // unbound-or-rebound field, a consensus expiry height the head block has passed, or a non-MPA entry) -- evaluated with the same
   // is_smartcoin_binding_valid predicate the bind and read paths use. Value expiry is
   // NOT staleness: an oracle quiet for a year still has live consumers that resume when
   // publishing resumes, and those keep blocking deletion (see do_evaluate).
   //
   // Mapping drift itself never auto-unbinds: the binding field and the subscriber entry
   // stay put (reads fail closed throughout), so restoring the mapping resumes the feed
   // with no rebind. Pruning happens HERE, at deletion: each stale subscriber's dead
   // binding is cleared on the asset and its feed refreshed (it stays null -- the price
   // was already gone), then the oracle object, subscriber set and all, is removed. A
   // dead entry can therefore never block oracle_delete forever.
   const flat_set<asset_id_type> subscribers = _oracle->subscribers;
   for( const auto& asset_id : subscribers )
   {
      const asset_object* a = d.find( asset_id );
      if( nullptr == a || !a->is_market_issued() )
         continue;
      const asset_bitasset_data_object& bdo = a->bitasset_data( d );
      const auto& exts = bdo.options.extensions.value;
      optional<oracle_id_type> bound_id;
      uint16_t bound_series = 0;
      if( exts.price_oracle_binding.valid() )
      {
         bound_id     = exts.price_oracle_binding->oracle_id;
         bound_series = exts.price_oracle_binding->series;
      }
      else if( exts.price_oracle_id.valid() )
         bound_id = *exts.price_oracle_id;
      bool live = false;
      if( bound_id.valid() && *bound_id == _oracle->get_id()
          && !is_price_oracle_binding_expired( exts.price_oracle_binding, d.head_block_num() ) )
      {
         const auto debt_mapping = get_effective_reference_mapping( d, asset_id );
         const auto backing_mapping = get_effective_reference_mapping(
               d, bdo.options.short_backing_asset );
         live = debt_mapping.valid() && backing_mapping.valid()
                && is_smartcoin_binding_valid( *_oracle, bound_series,
                                               *debt_mapping, *backing_mapping );
      }
      FC_ASSERT( !live,
                 "Oracle '${n}' still feeds ${a} through a live binding",
                 ("n", _oracle->name)("a", asset_id) );
      if( bound_id.valid() && *bound_id == _oracle->get_id() )
      {
         d.modify( bdo, []( asset_bitasset_data_object& o ) {
            o.options.extensions.value.price_oracle_binding = {};
            o.options.extensions.value.price_oracle_id = {};
         } );
         d.update_bitasset_current_feed( bdo );
      }
   }

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
   const uint32_t delay_sec = d.get_global_properties().parameters.get_oracle_guard_delay_sec();
   const uint32_t maint_sec = d.get_global_properties().parameters.maintenance_interval;

   d.modify( *_oracle, [&op, now, delay_sec, maint_sec]( oracle_object& o ) {
      o.submissions[op.producer] = std::make_pair( now, op.values );
      // Reputation counts the attempt here; live/outlier counts accrue inside the
      // aggregation this publish triggers. No economics reads any of it.
      o.reputation[op.producer].publish_count++;
      o.reputation[op.producer].last_publish_time = now;
      o.update_current_value( now, delay_sec, maint_sec );
   } );

   refresh_subscribers( d, *_oracle );

   // H2a advancing-unlock rule: a bonded producer's successful publication pushes
   // its bond unlock out. Unbonded producers (every H1 producer) take no branch
   // inside and see no behavior change.
   advance_producer_bond_on_publish( d, op.oracle_id, op.producer, now );

   // H2d promotion observation: hardened OSM records + rate counting for the
   // oracle's guard shell. Self-gated on the H2 hardfork with shell creation
   // inside, so H1 publishes (pre-fork, or forked oracles no H2 op ever
   // touched... post-fork H1 publishes shell but change nothing H1 reads)
   // keep byte-identical guarded values.
   h2_observe_publication( d, op.oracle_id, now );

   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result oracle_unfreeze_evaluator::do_evaluate( const oracle_unfreeze_operation& op )
{ try {
   database& d = db();

   // Price leg (R-02): the unfreeze clears the H2 debt-tap freeze, so it
   // admits at the price height. Ordering asserted inside.
   h2_require_price_leg( d.head_block_time() );

   _oracle = d.find( op.oracle );
   FC_ASSERT( nullptr != _oracle, "Oracle ${o} does not exist", ("o", op.oracle) );
   const auto& member_idx = d.get_index_type<committee_member_index>().indices().get<by_account>();
   const auto member_itr = member_idx.find( op.unfreezer );
   FC_ASSERT( member_itr != member_idx.end(),
              "Unfreezer ${a} is not a seated committee member", ("a", op.unfreezer) );
   // GOV-R9-01: permissionless registry membership is not a mandate to clear a
   // freeze; only the elected set may. Additive, fail-closed, registry lookup
   // retained (it identifies the member object).
   {
      const auto& elected = d.get_global_properties().active_committee_members;
      FC_ASSERT( std::find( elected.begin(), elected.end(), member_itr->get_id() ) != elected.end(),
                 "Unfreezer ${a} is registered but not on the elected committee",
                 ("a", op.unfreezer) );
   }
    FC_ASSERT( _oracle->options.frozen,
               "Oracle ${o} is not frozen; unfreeze is a no-op refused", ("o", op.oracle) );
    // Clearing after resolution only: an open dispute must resolve (or expire)
    // first, never mid-vote.
    FC_ASSERT( _oracle->open_disputes == 0,
               "Oracle carries open disputes; unfreeze refused until resolution" );
    // GOV-R9-02: even resolved, a challenge-set freeze stands for
    // GRAPHENE_ORACLE_UNFREEZE_DELAY_SEC after the last clear. Imposing it
    // takes a 2/3 supermajority of the deciding set; clearing it here takes
    // one seated member and one op fee, so without the lock a single capture
    // undoes the only durable sanction (GOV-02 slash is flag-only). Both
    // branches fail closed: never cleared = no anchor = no unfreeze, and an
    // anchor newer than the delay = still locked (head-block time only).
    FC_ASSERT( _oracle->dispute_cleared_time != time_point_sec(),
               "Oracle has no cleared dispute to anchor the unfreeze time-lock; "
               "refused (owner oracle_update clears a Track A freeze)" );
    {
       const int64_t held_sec =
             ( d.head_block_time() - _oracle->dispute_cleared_time ).to_seconds();
       FC_ASSERT( held_sec >= int64_t( GRAPHENE_ORACLE_UNFREEZE_DELAY_SEC ),
                  "Unfreeze time-lock: ${h}s since the last dispute cleared, "
                  "${t}s required",
                  ("h", held_sec)("t", GRAPHENE_ORACLE_UNFREEZE_DELAY_SEC) );
    }
    // R3-01 coherence, R4-02 NONE tightening (documented choice: REFUSE while
    // the deviation ladder holds the pair). The frozen flag conflates two
    // causes: guilty freezes (disputes) clear here, deviation halts (any
    // standing tripwire stage) clear only through tripwire reopen (two clean
    // windows). Clearing the flag here mid-halt would split the state (oracle
    // live while the door hold, debt halt, or redemptions latch still stand),
    // so this op refuses until every bound pair's stage reads NONE; the
    // committee then unfreezes in a second step. DOOR needs no carve-out: it
    // is dead as a standing stage (the X-05 jump stores DEBT directly, see
    // h2_economics.cpp), so == NONE also refuses a stored DOOR, should a
    // future rung ever store one. Tripwire reopen, symmetrically, never
    // clears a guilty oracle (see h2_reopen_tripwire): each cause clears
    // through its own path, in either order. Rare-op scan (never a sweep):
    // vaults bound to this oracle, each with at most one tripwire state.
    const auto& vault_idx = d.get_index_type<vault_index>().indices();
    const auto& tw_idx = d.get_index_type<tripwire_index>()
                            .indices().get<by_tripwire_pair>();
    for( auto vitr = vault_idx.begin(); vitr != vault_idx.end(); ++vitr )
    {
       if( !vitr->bound_oracle.valid() || *vitr->bound_oracle != op.oracle )
          continue;
       const auto titr = tw_idx.find( vitr->vault_pair );
       FC_ASSERT( titr == tw_idx.end()
                  || titr->halt_stage == GRAPHENE_H2E_TRIPWIRE_STAGE_NONE,
                  "Pair ${p} sits at tripwire halt stage ${s}; committee unfreeze "
                  "refused until the wire reopens (two clean windows clear the "
                  "stage to NONE, then unfreeze)",
                  ("p", vitr->vault_pair)("s", titr->halt_stage) );
    }

    return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) }

void_result oracle_unfreeze_evaluator::do_apply( const oracle_unfreeze_operation& op ) const
{ try {
   database& d = db();
   const auto now = d.head_block_time();
   const uint32_t delay_sec = d.get_global_properties().parameters.get_oracle_guard_delay_sec();
   const uint32_t maint_sec = d.get_global_properties().parameters.maintenance_interval;
   d.modify( *_oracle, [now, delay_sec, maint_sec]( oracle_object& o ) {
      o.options.frozen = false;
      // Resume promotion math immediately (owner-update precedent): the flag
      // alone does not recompute the aggregate, so refresh the guarded value
      // and bound feeds in this block.
      o.update_current_value( now, delay_sec, maint_sec );
   } );
   refresh_subscribers( d, *_oracle );
   return void_result();
} FC_CAPTURE_AND_RETHROW( (op) ) } // GCOVR_EXCL_LINE

} } // graphene::chain
