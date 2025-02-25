/*
 * Copyright (c) 2015 Cryptonomex, Inc., and contributors.
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

#include <graphene/chain/database.hpp>
#include <graphene/chain/db_with.hpp>
#include <graphene/chain/hardfork.hpp>

#include <graphene/chain/block_summary_object.hpp>
#include <graphene/chain/global_property_object.hpp>
#include <graphene/chain/operation_history_object.hpp>

#include <graphene/chain/proposal_object.hpp>
#include <graphene/chain/samet_fund_object.hpp>
#include <graphene/chain/transaction_history_object.hpp>
#include <graphene/chain/witness_object.hpp>
#include <graphene/chain/exceptions.hpp>
#include <graphene/chain/evaluator.hpp>
#include <graphene/chain/witness_schedule_object.hpp>

#include <graphene/protocol/fee_schedule.hpp>

#include <fc/io/raw.hpp>
#include <fc/thread/parallel.hpp>

namespace graphene { namespace chain {

bool database::is_known_block( const block_id_type& id )const
{
   return _fork_db.is_known_block(id) || _block_id_to_block.contains(id);
}
/**
 * Only return true *if* the transaction has not expired or been invalidated. If this
 * method is called with a VERY old transaction we will return false, they should
 * query things by blocks if they are that old.
 */
bool database::is_known_transaction( const transaction_id_type& id )const
{
   const auto& trx_idx = get_index_type<transaction_index>().indices().get<by_trx_id>();
   return trx_idx.find( id ) != trx_idx.end();
}

block_id_type  database::get_block_id_for_num( uint32_t block_num )const
{ try {
   return _block_id_to_block.fetch_block_id( block_num );
} FC_CAPTURE_AND_RETHROW( (block_num) ) }

optional<signed_block> database::fetch_block_by_id( const block_id_type& id )const
{
   auto b = _fork_db.fetch_block( id );
   if( !b )
      return _block_id_to_block.fetch_optional(id);
   return b->data;
}

optional<signed_block> database::fetch_block_by_number( uint32_t num )const
{
   auto results = _fork_db.fetch_block_by_number(num);
   if( results.size() == 1 )
      return results[0]->data;
   else
      return _block_id_to_block.fetch_by_number(num);
}

const signed_transaction& database::get_recent_transaction(const transaction_id_type& trx_id) const
{
   auto& index = get_index_type<transaction_index>().indices().get<by_trx_id>();
   auto itr = index.find(trx_id);
   FC_ASSERT(itr != index.end());
   return itr->trx;
}

std::vector<block_id_type> database::get_block_ids_on_fork(block_id_type head_of_fork) const
{
  pair<fork_database::branch_type, fork_database::branch_type> branches = _fork_db.fetch_branch_from(head_block_id(), head_of_fork);
  if( !((branches.first.back()->previous_id() == branches.second.back()->previous_id())) )
  {
     edump( (head_of_fork)
            (head_block_id())
            (branches.first.size())
            (branches.second.size()) );
     assert(branches.first.back()->previous_id() == branches.second.back()->previous_id());
  }
  std::vector<block_id_type> result;
  for (const item_ptr& fork_block : branches.second)
    result.emplace_back(fork_block->id);
  result.emplace_back(branches.first.back()->previous_id());
  return result;
}

/**
 * Push block "may fail" in which case every partial change is unwound.  After
 * push block is successful the block is appended to the chain database on disk.
 *
 * @return true if we switched forks as a result of this push.
 */
bool database::push_block(const signed_block& new_block, uint32_t skip)
{
//   idump((new_block.block_num())(new_block.id())(new_block.timestamp)(new_block.previous));
   bool result;
   detail::with_skip_flags( *this, skip, [&]()
   {
      detail::without_pending_transactions( *this, std::move(_pending_tx),
      [&]()
      {
         result = _push_block(new_block);
      });
   });
   return result;
}

bool database::_push_block(const signed_block& new_block)
{ try {
   uint32_t skip = get_node_properties().skip_flags;

   const auto now = fc::time_point::now().sec_since_epoch();
   if( _fork_db.head() && new_block.timestamp.sec_since_epoch() > now - 86400 )
   {
      // verify that the block signer is in the current set of active witnesses.
      shared_ptr<fork_item> prev_block = _fork_db.fetch_block( new_block.previous );
      GRAPHENE_ASSERT( prev_block, unlinkable_block_exception, "block does not link to known chain" );
      if( prev_block->scheduled_witnesses && 0 == (skip&(skip_witness_schedule_check|skip_witness_signature)) )
         verify_signing_witness( new_block, *prev_block );
   }

   const shared_ptr<fork_item> new_head = _fork_db.push_block(new_block);
   //If the head block from the longest chain does not build off of the current head, we need to switch forks.
   if( new_head->data.previous != head_block_id() )
   {
      //If the newly pushed block is the same height as head, we get head back in new_head
      //Only switch forks if new_head is actually higher than head
      if( new_head->data.block_num() > head_block_num() )
      {
         wlog( "Switching to fork: ${id}", ("id",new_head->data.id()) );
         auto branches = _fork_db.fetch_branch_from(new_head->data.id(), head_block_id());

         // pop blocks until we hit the forked block
         while( head_block_id() != branches.second.back()->data.previous )
         {
            ilog( "popping block #${n} ${id}", ("n",head_block_num())("id",head_block_id()) );
            pop_block();
         }

         // push all blocks on the new fork
         for( auto ritr = branches.first.rbegin(); ritr != branches.first.rend(); ++ritr )
         {
               ilog( "pushing block from fork #${n} ${id}", ("n",(*ritr)->data.block_num())("id",(*ritr)->id) );
               optional<fc::exception> except;
               try {
                  undo_database::session session = _undo_db.start_undo_session();
                  apply_block( (*ritr)->data, skip );
                  update_witnesses( **ritr );
                  _block_id_to_block.store( (*ritr)->id, (*ritr)->data );
                  session.commit();
               }
               catch ( const fc::exception& e ) { except = e; }
               if( except )
               {
                  wlog( "exception thrown while switching forks ${e}", ("e",except->to_detail_string() ) );
                  // remove the rest of branches.first from the fork_db, those blocks are invalid
                  while( ritr != branches.first.rend() )
                  {
                     ilog( "removing block from fork_db #${n} ${id}", ("n",(*ritr)->data.block_num())("id",(*ritr)->id) );
                     _fork_db.remove( (*ritr)->id );
                     ++ritr;
                  }
                  _fork_db.set_head( branches.second.front() );

                  // pop all blocks from the bad fork
                  while( head_block_id() != branches.second.back()->data.previous )
                  {
                     ilog( "popping block #${n} ${id}", ("n",head_block_num())("id",head_block_id()) );
                     pop_block();
                  }

                  ilog( "Switching back to fork: ${id}", ("id",branches.second.front()->data.id()) );
                  // restore all blocks from the good fork
                  for( auto ritr2 = branches.second.rbegin(); ritr2 != branches.second.rend(); ++ritr2 )
                  {
                     ilog( "pushing block #${n} ${id}", ("n",(*ritr2)->data.block_num())("id",(*ritr2)->id) );
                     auto session = _undo_db.start_undo_session();
                     apply_block( (*ritr2)->data, skip );
                     _block_id_to_block.store( (*ritr2)->id, (*ritr2)->data );
                     session.commit();
                  }
                  throw *except;
               }
         }
         return true;
      }
      else return false;
   }

   try {
      auto session = _undo_db.start_undo_session();
      apply_block(new_block, skip);
      if( new_block.timestamp.sec_since_epoch() > now - 86400 )
         update_witnesses( *new_head );
      _block_id_to_block.store(new_block.id(), new_block);
      session.commit();
   } catch ( const fc::exception& e ) {
      elog("Failed to push new block:\n${e}", ("e", e.to_detail_string()));
      _fork_db.remove( new_block.id() );
      throw;
   }

   return false;
} FC_CAPTURE_AND_RETHROW( (new_block) ) }

void database::verify_signing_witness( const signed_block& new_block, const fork_item& fork_entry )const
{
   FC_ASSERT( new_block.timestamp >= fork_entry.next_block_time );
   uint32_t slot_num = ( new_block.timestamp - fork_entry.next_block_time ).to_seconds() / block_interval();
   uint64_t index = ( fork_entry.next_block_aslot + slot_num ) % fork_entry.scheduled_witnesses->size();
   const auto& scheduled_witness = (*fork_entry.scheduled_witnesses)[index];
   FC_ASSERT( new_block.witness == scheduled_witness.first, "Witness produced block at wrong time",
              ("block witness",new_block.witness)("scheduled",scheduled_witness)("slot_num",slot_num) );
   FC_ASSERT( new_block.validate_signee( scheduled_witness.second ) );
}

void database::update_witnesses( fork_item& fork_entry )const
{
   if( fork_entry.scheduled_witnesses ) return;

   const dynamic_global_property_object& dpo = get_dynamic_global_properties();
   fork_entry.next_block_aslot = dpo.current_aslot + 1;
   fork_entry.next_block_time = get_slot_time( 1 );

   const witness_schedule_object& wso = get_witness_schedule_object();
   fork_entry.scheduled_witnesses = std::make_shared< vector< pair< witness_id_type, public_key_type > > >();
   fork_entry.scheduled_witnesses->reserve( wso.current_shuffled_witnesses.size() );
   for( size_t i = 0; i < wso.current_shuffled_witnesses.size(); ++i )
   {
       const auto& witness = wso.current_shuffled_witnesses[i](*this);
       fork_entry.scheduled_witnesses->emplace_back( wso.current_shuffled_witnesses[i], witness.signing_key );
   }
}

/**
 * Attempts to push the transaction into the pending queue
 *
 * When called to push a locally generated transaction, set the skip_block_size_check bit on the skip argument. This
 * will allow the transaction to be pushed even if it causes the pending block size to exceed the maximum block size.
 * Although the transaction will probably not propagate further now, as the peers are likely to have their pending
 * queues full as well, it will be kept in the queue to be propagated later when a new block flushes out the pending
 * queues.
 */
processed_transaction database::push_transaction( const precomputable_transaction& trx, uint32_t skip )
{ try {
   // see https://github.com/bitshares/bitshares-core/issues/1573
   FC_ASSERT( fc::raw::pack_size( trx ) < (1024 * 1024), "Transaction exceeds maximum transaction size." );
   processed_transaction result;
   detail::with_skip_flags( *this, skip, [&]()
   {
      result = _push_transaction( trx );
   } );
   return result;
} FC_CAPTURE_AND_RETHROW( (trx) ) }

processed_transaction database::_push_transaction( const precomputable_transaction& trx )
{
   // If this is the first transaction pushed after applying a block, start a new undo session.
   // This allows us to quickly rewind to the clean state of the head block, in case a new block arrives.
   if( !_pending_tx_session.valid() )
      _pending_tx_session = _undo_db.start_undo_session();

   // Create a temporary undo session as a child of _pending_tx_session.
   // The temporary session will be discarded by the destructor if
   // _apply_transaction fails.  If we make it to merge(), we
   // apply the changes.

   auto temp_session = _undo_db.start_undo_session();
   auto processed_trx = _apply_transaction( trx );
   _pending_tx.push_back(processed_trx);

   // notify_changed_objects();
   // The transaction applied successfully. Merge its changes into the pending block session.
   temp_session.merge();

   // notify anyone listening to pending transactions
   notify_on_pending_transaction( trx );
   return processed_trx;
}

processed_transaction database::validate_transaction( const signed_transaction& trx )
{
   auto session = _undo_db.start_undo_session();
   return _apply_transaction( trx );
}

class push_proposal_nesting_guard {
public:
   push_proposal_nesting_guard( uint32_t& nesting_counter, const database& db )
      : orig_value(nesting_counter), counter(nesting_counter)
   {
      FC_ASSERT( counter < db.get_global_properties().active_witnesses.size() * 2, "Max proposal nesting depth exceeded!" );
      counter++;
   }
   ~push_proposal_nesting_guard()
   {
      if( --counter != orig_value )
         elog( "Unexpected proposal nesting count value: ${n} != ${o}", ("n",counter)("o",orig_value) );
   }
private:
    const uint32_t  orig_value;
    uint32_t& counter;
};

processed_transaction database::push_proposal(const proposal_object& proposal)
{ try {
   transaction_evaluation_state eval_state(this);
   eval_state._is_proposed_trx = true;

   eval_state.operation_results.reserve(proposal.proposed_transaction.operations.size());
   processed_transaction ptrx(proposal.proposed_transaction);
   eval_state._trx = &ptrx;
   size_t old_applied_ops_size = _applied_ops.size();

   try {
      push_proposal_nesting_guard guard( _push_proposal_nesting_depth, *this );
      if( _undo_db.size() >= _undo_db.max_size() )
         _undo_db.set_max_size( _undo_db.size() + 1 );
      auto session = _undo_db.start_undo_session(true);
      for( auto& op : proposal.proposed_transaction.operations )
         eval_state.operation_results.emplace_back(apply_operation(eval_state, op)); // This is a virtual operation
      // Make sure there is no unpaid samet fund debt
      const auto& samet_fund_idx = get_index_type<samet_fund_index>().indices().get<by_unpaid>();
      FC_ASSERT( samet_fund_idx.empty() || samet_fund_idx.begin()->unpaid_amount == 0,
                 "Unpaid SameT Fund debt detected" );
      remove(proposal);
      session.merge();
   } catch ( const fc::exception& e ) {
      if( head_block_time() <= HARDFORK_483_TIME )
      {
         for( size_t i=old_applied_ops_size,n=_applied_ops.size(); i<n; i++ )
         {
            ilog( "removing failed operation from applied_ops: ${op}", ("op", *(_applied_ops[i])) );
            _applied_ops[i].reset();
         }
      }
      else
      {
         _applied_ops.resize( old_applied_ops_size );
      }
      wlog( "${e}", ("e",e.to_detail_string() ) );
      throw;
   }

   ptrx.operation_results = std::move(eval_state.operation_results);
   return ptrx;
} FC_CAPTURE_AND_RETHROW( (proposal) ) }

signed_block database::generate_block(
   fc::time_point_sec when,
   witness_id_type witness_id,
   const fc::ecc::private_key& block_signing_private_key,
   uint32_t skip /* = 0 */
   )
{ try {
   signed_block result;
   detail::with_skip_flags( *this, skip, [&]()
   {
      result = _generate_block( when, witness_id, block_signing_private_key );
   } );
   return result;
} FC_CAPTURE_AND_RETHROW() }

signed_block database::_generate_block(
   fc::time_point_sec when,
   witness_id_type witness_id,
   const fc::ecc::private_key& block_signing_private_key
   )
{
   try {
   uint32_t skip = get_node_properties().skip_flags;
   uint32_t slot_num = get_slot_at_time( when );
   FC_ASSERT( slot_num > 0 );
   witness_id_type scheduled_witness = get_scheduled_witness( slot_num );
   FC_ASSERT( scheduled_witness == witness_id );

   //
   // The following code throws away existing pending_tx_session and
   // rebuilds it by re-applying pending transactions.
   //
   // This rebuild is necessary because pending transactions' validity
   // and semantics may have changed since they were received, because
   // time-based semantics are evaluated based on the current block
   // time.  These changes can only be reflected in the database when
   // the value of the "when" variable is known, which means we need to
   // re-apply pending transactions in this method.
   //

   // pop pending state (reset to head block state)
   _pending_tx_session.reset();

   // Check witness signing key
   if( 0 == (skip & skip_witness_signature) )
   {
      // Note: if this check failed (which won't happen in normal situations),
      // we would have temporarily broken the invariant that
      // _pending_tx_session is the result of applying _pending_tx.
      // In this case, when the node received a new block,
      // the push_block() call will re-create the _pending_tx_session.
      FC_ASSERT( witness_id(*this).signing_key == block_signing_private_key.get_public_key() );
   }

   static const size_t max_partial_block_header_size = fc::raw::pack_size( signed_block_header() )
                                                       - fc::raw::pack_size( witness_id_type() ) // witness_id
                                                       + 3; // max space to store size of transactions (out of block header),
                                                            // +3 means 3*7=21 bits so it's practically safe
   const size_t max_block_header_size = max_partial_block_header_size + fc::raw::pack_size( witness_id );
   auto maximum_block_size = get_global_properties().parameters.maximum_block_size;
   size_t total_block_size = max_block_header_size;

   signed_block pending_block;

   _pending_tx_session = _undo_db.start_undo_session();

   uint64_t postponed_tx_count = 0;
   for( const processed_transaction& tx : _pending_tx )
   {
      size_t new_total_size = total_block_size + fc::raw::pack_size( tx );

      // postpone transaction if it would make block too big
      if( new_total_size > maximum_block_size )
      {
         postponed_tx_count++;
         continue;
      }

      try
      {
         auto temp_session = _undo_db.start_undo_session();
         processed_transaction ptx = _apply_transaction( tx );
         // Clear results to save disk space and network bandwidth.
         // This may break client applications which rely on the results.
         ptx.operation_results.clear();

         // We have to recompute pack_size(ptx) because it may be different
         // than pack_size(tx) (i.e. if one or more results increased
         // their size)
         new_total_size = total_block_size + fc::raw::pack_size( ptx );
         // postpone transaction if it would make block too big
         if( new_total_size > maximum_block_size )
         {
            postponed_tx_count++;
            continue;
         }

         temp_session.merge();

         total_block_size = new_total_size;
         pending_block.transactions.push_back( ptx );
      }
      catch ( const fc::exception& e )
      {
         // Do nothing, transaction will not be re-applied
         wlog( "Transaction was not processed while generating block due to ${e}", ("e", e) );
         wlog( "The transaction was ${t}", ("t", tx) );
      }
   }
   if( postponed_tx_count > 0 )
   {
      wlog( "Postponed ${n} transactions due to block size limit", ("n", postponed_tx_count) );
   }

   _pending_tx_session.reset();

   // We have temporarily broken the invariant that
   // _pending_tx_session is the result of applying _pending_tx, as
   // _pending_tx now consists of the set of postponed transactions.
   // However, the push_block() call below will re-create the
   // _pending_tx_session.

   pending_block.previous = head_block_id();
   pending_block.timestamp = when;
   pending_block.transaction_merkle_root = pending_block.calculate_merkle_root();
   pending_block.witness = witness_id;

   if( 0 == (skip & skip_witness_signature) )
      pending_block.sign( block_signing_private_key );

   push_block( pending_block, skip | skip_transaction_signatures ); // skip authority check when pushing self-generated blocks

   return pending_block;
} FC_CAPTURE_AND_RETHROW( (witness_id) ) }

/**
 * Removes the most recent block from the database and
 * undoes any changes it made.
 */
void database::pop_block()
{ try {
   _pending_tx_session.reset();
   auto fork_db_head = _fork_db.head();
   FC_ASSERT( fork_db_head, "Trying to pop() from empty fork database!?" );
   if( fork_db_head->id == head_block_id() )
      _fork_db.pop_block();
   else
   {
      fork_db_head = _fork_db.fetch_block( head_block_id() );
      FC_ASSERT( fork_db_head, "Trying to pop() block that's not in fork database!?" );
   }
   pop_undo();
   _popped_tx.insert( _popped_tx.begin(), fork_db_head->data.transactions.begin(), fork_db_head->data.transactions.end() );
} FC_CAPTURE_AND_RETHROW() }

void database::clear_pending()
{ try {
   assert( (_pending_tx.size() == 0) || _pending_tx_session.valid() );
   _pending_tx.clear();
   _pending_tx_session.reset();
} FC_CAPTURE_AND_RETHROW() }

uint32_t database::push_applied_operation( const operation& op, bool is_virtual /* = true */ )
{
   _applied_ops.emplace_back( operation_history_object( op, _current_block_num, _current_trx_in_block,
                                    _current_op_in_trx, _current_virtual_op, is_virtual, _current_block_time ) );
   ++_current_virtual_op;
   return _applied_ops.size() - 1;
}
void database::set_applied_operation_result( uint32_t op_id, const operation_result& result )
{
   assert( op_id < _applied_ops.size() );
   if( _applied_ops[op_id] )
      _applied_ops[op_id]->result = result;
   else
   {
      elog( "Could not set operation result (head_block_num=${b})", ("b", head_block_num()) );
   }
}

const vector<optional< operation_history_object > >& database::get_applied_operations() const
{
   return _applied_ops;
}

//////////////////// private methods ////////////////////

void database::apply_block( const signed_block& next_block, uint32_t skip )
{
   auto block_num = next_block.block_num();
   if( !_checkpoints.empty() && _checkpoints.rbegin()->second != block_id_type() )
   {
      auto itr = _checkpoints.find( block_num );
      if( itr != _checkpoints.end() )
         FC_ASSERT( next_block.id() == itr->second, "Block did not match checkpoint", ("checkpoint",*itr)("block_id",next_block.id()) );

      if( _checkpoints.rbegin()->first >= block_num )
         skip = ~0;// WE CAN SKIP ALMOST EVERYTHING
   }

   detail::with_skip_flags( *this, skip, [&]()
   {
      _apply_block( next_block );
   } );
   return;
}

void database::_apply_block( const signed_block& next_block )
{ try {
   uint32_t next_block_num = next_block.block_num();
   uint32_t skip = get_node_properties().skip_flags;
   _applied_ops.clear();

   if( 0 == (skip & skip_block_size_check) )
   {
      FC_ASSERT( fc::raw::pack_size(next_block) <= get_global_properties().parameters.maximum_block_size );
   }

   FC_ASSERT( (skip & skip_merkle_check) || next_block.transaction_merkle_root == next_block.calculate_merkle_root(),
              "",
              ("next_block.transaction_merkle_root",next_block.transaction_merkle_root)
              ("calc",next_block.calculate_merkle_root())
              ("next_block",next_block)
              ("id",next_block.id()) );

   const witness_object& signing_witness = validate_block_header(skip, next_block);
   const auto& dynamic_global_props = get_dynamic_global_properties();
   bool maint_needed = (dynamic_global_props.next_maintenance_time <= next_block.timestamp);

   // trx_in_block starts from 0.
   // For real operations which are explicitly included in a transaction, op_in_trx starts from 0, virtual_op is 0.
   // For virtual operations that are derived directly from a real operation,
   //     use the real operation's (block_num,trx_in_block,op_in_trx), virtual_op starts from 1.
   // For virtual operations created after processed all transactions,
   //     trx_in_block = the_block.trsanctions.size(), op_in_trx is 0, virtual_op starts from 0.
   _current_block_num    = next_block_num;
   _current_trx_in_block = 0;

   _current_block_time   = next_block.timestamp;

   _issue_453_affected_assets.clear();

   signed_block processed_block( next_block ); // make a copy
   for( auto& trx : processed_block.transactions )
   {
      /* We do not need to push the undo state for each transaction
       * because they either all apply and are valid or the
       * entire block fails to apply.  We only need an "undo" state
       * for transactions when validating broadcast transactions or
       * when building a block.
       */
      trx.operation_results = apply_transaction( trx, skip ).operation_results;
      ++_current_trx_in_block;
   }

   _current_op_in_trx    = 0;
   _current_virtual_op   = 0;

   const uint32_t missed = update_witness_missed_blocks( next_block );
   update_global_dynamic_data( next_block, missed );
   update_signing_witness(signing_witness, next_block);
   update_last_irreversible_block();

   process_tickets();

   // Are we at the maintenance interval?
   if( maint_needed )
      perform_chain_maintenance( next_block );

   create_block_summary(next_block);
   clear_expired_transactions();
   clear_expired_proposals();
   clear_expired_orders();
   clear_expired_force_settlements();
   clear_expired_htlcs();
   update_expired_feeds();       // this will update expired feeds and some core exchange rates
   update_core_exchange_rates(); // this will update remaining core exchange rates
   update_withdraw_permissions();
   update_credit_offers_and_deals();

   // n.b., update_maintenance_flag() happens this late
   // because get_slot_time() / get_slot_at_time() is needed above
   // TODO:  figure out if we could collapse this function into
   // update_global_dynamic_data() as perhaps these methods only need
   // to be called for header validation?
   update_maintenance_flag( maint_needed );
   update_witness_schedule();
   if( !_node_property_object.debug_updates.empty() )
      apply_debug_updates();

   // notify observers that the block has been applied
   notify_applied_block( processed_block ); //emit
   _applied_ops.clear();

   notify_changed_objects();
} FC_CAPTURE_AND_RETHROW( (next_block.block_num()) )  }

/**
 * @note if a @c processed_transaction is passed in, it is cast into @c signed_transaction here.
 *       It also means that the @c operation_results field is ignored by consensus, although it
 *       is a part of block data.
 */
processed_transaction database::apply_transaction(const signed_transaction& trx, uint32_t skip)
{
   processed_transaction result;
   detail::with_skip_flags( *this, skip, [&]()
   {
      result = _apply_transaction(trx);
   });
   return result;
}

processed_transaction database::_apply_transaction(const signed_transaction& trx)
{ try {
   uint32_t skip = get_node_properties().skip_flags;

   trx.validate();

   auto& trx_idx = get_mutable_index_type<transaction_index>();
   const chain_id_type& chain_id = get_chain_id();
   if( 0 == (skip & skip_transaction_dupe_check) )
   {
      GRAPHENE_ASSERT( trx_idx.indices().get<by_trx_id>().find(trx.id()) == trx_idx.indices().get<by_trx_id>().end(),
                       duplicate_transaction,
                       "Transaction '${txid}' is already in the database",
                       ("txid",trx.id()) );
   }
   transaction_evaluation_state eval_state(this);
   const chain_parameters& chain_parameters = get_global_properties().parameters;
   eval_state._trx = &trx;

   if( 0 == (skip & skip_transaction_signatures) )
   {
      bool allow_non_immediate_owner = ( head_block_time() >= HARDFORK_CORE_584_TIME );
      auto get_active = [this]( account_id_type id ) { return &id(*this).active; };
      auto get_owner  = [this]( account_id_type id ) { return &id(*this).owner;  };
      auto get_custom = [this]( account_id_type id, const operation& op, rejected_predicate_map* rejects ) {
         return get_viable_custom_authorities(id, op, rejects);
      };

      trx.verify_authority(chain_id, get_active, get_owner, get_custom, allow_non_immediate_owner,
                           MUST_IGNORE_CUSTOM_OP_REQD_AUTHS(head_block_time()),
                           get_global_properties().parameters.max_authority_depth);
   }

   //Skip all manner of expiration and TaPoS checking if we're on block 1; It's impossible that the transaction is
   //expired, and TaPoS makes no sense as no blocks exist.
   if( BOOST_LIKELY(head_block_num() > 0) )
   {
      if( 0 == (skip & skip_tapos_check) )
      {
         const auto& tapos_block_summary = block_summary_id_type( trx.ref_block_num )(*this);

         //Verify TaPoS block summary has correct ID prefix, and that this block's time is not past the expiration
         FC_ASSERT( trx.ref_block_prefix == tapos_block_summary.block_id._hash[1].value() );
      }

      fc::time_point_sec now = head_block_time();

      FC_ASSERT( trx.expiration <= now + chain_parameters.maximum_time_until_expiration, "",
                 ("trx.expiration",trx.expiration)("now",now)("max_til_exp",chain_parameters.maximum_time_until_expiration));
      FC_ASSERT( now <= trx.expiration, "", ("now",now)("trx.exp",trx.expiration) );
      if ( 0 == (skip & skip_block_size_check ) ) // don't waste time on replay
         FC_ASSERT( head_block_time() <= HARDFORK_CORE_1573_TIME
               || trx.get_packed_size() <= chain_parameters.maximum_transaction_size,
               "Transaction exceeds maximum transaction size." );
   }

   //Insert transaction into unique transactions database.
   if( 0 == (skip & skip_transaction_dupe_check) )
   {
      create<transaction_history_object>([&trx](transaction_history_object& transaction) {
         transaction.trx_id = trx.id();
         transaction.trx = trx;
      });
   }

   eval_state.operation_results.reserve(trx.operations.size());

   //Finally process the operations
   processed_transaction ptrx(trx);
   _current_op_in_trx = 0;
   for( const auto& op : ptrx.operations )
   {
      _current_virtual_op = 0;
      eval_state.operation_results.emplace_back(apply_operation(eval_state, op, false)); // This is NOT a virtual op
      ++_current_op_in_trx;
   }
   ptrx.operation_results = std::move(eval_state.operation_results);

   // Make sure there is no unpaid samet fund debt
   const auto& samet_fund_idx = get_index_type<samet_fund_index>().indices().get<by_unpaid>();
   FC_ASSERT( samet_fund_idx.empty() || samet_fund_idx.begin()->unpaid_amount == 0,
              "Unpaid SameT Fund debt detected" );

   return ptrx;
} FC_CAPTURE_AND_RETHROW( (trx) ) }

operation_result database::apply_operation( transaction_evaluation_state& eval_state, const operation& op,
                                            bool is_virtual /* = true */ )
{ try {
   int i_which = op.which();
   uint64_t u_which = uint64_t( i_which );
   FC_ASSERT( i_which >= 0, "Negative operation tag in operation ${op}", ("op",op) );
   FC_ASSERT( u_which < _operation_evaluators.size(), "No registered evaluator for operation ${op}", ("op",op) );
   unique_ptr<op_evaluator>& eval = _operation_evaluators[ u_which ];
   FC_ASSERT( eval, "No registered evaluator for operation ${op}", ("op",op) );
   auto op_id = push_applied_operation( op, is_virtual );
   auto result = eval->evaluate( eval_state, op, true );
   set_applied_operation_result( op_id, result );
   return result;
} FC_CAPTURE_AND_RETHROW( (op) ) }

const witness_object& database::validate_block_header( uint32_t skip, const signed_block& next_block )const
{
   FC_ASSERT( head_block_id() == next_block.previous, "", ("head_block_id",head_block_id())("next.prev",next_block.previous) );
   FC_ASSERT( head_block_time() < next_block.timestamp, "", ("head_block_time",head_block_time())("next",next_block.timestamp)("blocknum",next_block.block_num()) );
   const witness_object& witness = next_block.witness(*this);

   if( 0 == (skip&skip_witness_signature) )
      FC_ASSERT( next_block.validate_signee( witness.signing_key ) );

   if( 0 == (skip&skip_witness_schedule_check) )
   {
      uint32_t slot_num = get_slot_at_time( next_block.timestamp );
      FC_ASSERT( slot_num > 0 );

      witness_id_type scheduled_witness = get_scheduled_witness( slot_num );

      FC_ASSERT( next_block.witness == scheduled_witness, "Witness produced block at wrong time",
                 ("block witness",next_block.witness)("scheduled",scheduled_witness)("slot_num",slot_num) );
   }

   return witness;
}

void database::create_block_summary(const signed_block& next_block)
{
   block_summary_id_type sid(next_block.block_num() & 0xffff );
   modify( sid(*this), [&](block_summary_object& p) {
         p.block_id = next_block.id();
   });
}

void database::add_checkpoints( const flat_map<uint32_t,block_id_type>& checkpts )
{
   for( const auto& i : checkpts )
      _checkpoints[i.first] = i.second;
}

bool database::before_last_checkpoint()const
{
   return (_checkpoints.size() > 0) && (_checkpoints.rbegin()->first >= head_block_num());
}


static const uint32_t skip_expensive = database::skip_transaction_signatures | database::skip_witness_signature
                                       | database::skip_merkle_check | database::skip_transaction_dupe_check;

template<typename Trx>
void database::_precompute_parallel( const Trx* trx, const size_t count, const uint32_t skip )const
{
   for( size_t i = 0; i < count; ++i, ++trx )
   {
      trx->validate(); // TODO - parallelize wrt confidential operations
      if( 0 == (skip & skip_block_size_check) )
         trx->get_packed_size();
      if( 0 == (skip&skip_transaction_dupe_check) )
         trx->id();
      if( 0 == (skip&skip_transaction_signatures) )
         trx->get_signature_keys( get_chain_id() );
   }
}

fc::future<void> database::precompute_parallel( const signed_block& block, const uint32_t skip )const
{ try {
   std::vector<fc::future<void>> workers;
   if( !block.transactions.empty() )
   {
      if( (skip & skip_expensive) == skip_expensive )
         _precompute_parallel( &block.transactions[0], block.transactions.size(), skip );
      else
      {
         uint32_t chunks = fc::asio::default_io_service_scope::get_num_threads();
         uint32_t chunk_size = ( block.transactions.size() + chunks - 1 ) / chunks;
         workers.reserve( chunks + 1 );
         for( size_t base = 0; base < block.transactions.size(); base += chunk_size )
            workers.push_back( fc::do_parallel( [this,&block,base,chunk_size,skip] () {
               _precompute_parallel( &block.transactions[base],
                                     base + chunk_size < block.transactions.size() ? chunk_size : block.transactions.size() - base,
                                     skip );
            }) );
      }
   }

   if( 0 == (skip&skip_witness_signature) )
      workers.push_back( fc::do_parallel( [&block] () { block.signee(); } ) );
   if( 0 == (skip&skip_merkle_check) )
      block.calculate_merkle_root();
   block.id();

   if( workers.empty() )
      return fc::future< void >( fc::promise< void >::create( true ) );

   auto first = workers.begin();
   auto worker = first;
   while( ++worker != workers.end() )
      worker->wait();
   return *first;
} FC_LOG_AND_RETHROW() }

fc::future<void> database::precompute_parallel( const precomputable_transaction& trx )const
{
   return fc::do_parallel([this,&trx] () {
      _precompute_parallel( &trx, 1, skip_nothing );
   });
}

} }
