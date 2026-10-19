/*
 * H2d oracle economics: rewards, guard hardening, tripwire, Recovery.
 *
 * USD-terms-at-lock basis inherited from H2a/H2b/H2c ($0.001/BTS pilot basis:
 * 1,000,000 raw units per USD cent). All proposal values from BSIP-1 section
 * 7b unless noted.
 *
 * What this suite covers (plan Task H2d, five required areas + carried items):
 * - Reward-pool pro-rata live-weight payout math exactness (forfeit-funded,
 *   consumer-fee 50% routing share under the joint 70% cap with stealth
 *   parity; rounding DOWN, dust stays in the pool).
 * - Routing-constant validity (sums to 10000 bps, oracle share within cap).
 * - OSM bucket-anchor exactness (absolute-grid anchoring) + promotion
 *   records with liveness counts.
 * - Per-interval promotion rate counters (512/interval proposal; hold past
 *   the limit fails H2 reads closed, clears at the next window).
 * - Fallback-series reference + single-backup switch (primary live, primary
 *   stale serves backup, dual-stale halts), set through the new
 *   oracle_fallback_set op (owner-only, pre-fork refused).
 * - Recovery trigger over the explicit LIVE system-collateral scope (150%
 *   raw scope: unseized live bonds over live outstanding; terminal
 *   wind-down books excluded so one pair's settled failure can never suspend
 *   other pairs' growth -- fault containment): suspends new debt
 *   (vault_register refused), exits stay open, clears on restoration.
 * - Tripwire halt ladder (door -> debt -> redemptions) on crafted
 *   market-vs-feed dislocation with formal math (volume-weighted median
 *   selection, 256-bit deviation predicate, minimum-depth qualifier,
 *   two-window storage, per-sample source pool disclosure), then reopen
 *   after two clean windows.
 * - H1 pairs excluded from H2 medians (vault-less pools never sample;
 *   unbound vaults never evaluate).
 * - Carried H2c-review items (treated as spec): wind-down USD-terms
 *   conversion via the bound-oracle price (closes the H2c-deferred raw-vs-USD
 *   check); vault_rotate full-threshold weight check (membership-only
 *   upgraded); pair<->oracle canonical binding pinned by pair_freeze and
 *   enforced thereafter.
 *
 * Vehicle decisions (reversible minima, logged in the H2d report):
 * - Reward pools + guard states are created lazily per oracle (first
 *   producer-bond lock or first publish observation); no new funding op.
 * - Fallback depth is exactly one (single backup, never a chain).
 * - Tripwire feed leg reads the bound oracle's series-0 value as
 *   (bond_units, pair_units) by binding convention; the market leg reads
 *   direct pair<->core pool legs only.
 * - Bootstrap-weight decay deferred (no consumer reads bootstrap_weight;
 *   decaying write-only state is unobservable consensus churn).
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/challenge_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_economics_evaluator.hpp>
#include <graphene/chain/h2_economics_object.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/htlc_object.hpp>
#include <graphene/chain/liquidity_pool_object.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/seasoning_evaluator.hpp>
#include <graphene/chain/seasoning_object.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/chain/winddown_object.hpp>
#include <graphene/protocol/challenge_ops.hpp>
#include <graphene/protocol/h2_economics.hpp>
#include <graphene/protocol/liquidity_pool.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/protocol/seasoning_ops.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>
#include <graphene/protocol/vault_ops.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;
using graphene::protocol::h2_routing_valid;
using graphene::protocol::h2_osm_bucket_anchor;
using graphene::protocol::h2_deviation_breaches;
using graphene::protocol::h2_pro_rata;
using graphene::protocol::h2_convert_face_to_bond;

namespace {

/// H1-03 vacuity pin: pre-fork refusals must reach the hardfork gate, never
/// stop at the fee check (fee set, funded CORE payer; refusal must name H2).
void h2e_require_gate_refusal( database& db, signed_transaction& tx, const char* what )
{
   try { PUSH_TX( db, tx ); }
   catch ( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_string().find( "H2" ) != std::string::npos
            && ( e.to_string().find( "hardfork" ) != std::string::npos
              || e.to_string().find( "activation" ) != std::string::npos ),
            what << " refused off-gate (vacuous, not gate proof): " << e.to_string() );
      return;
   }
   BOOST_FAIL( what << " was ACCEPTED pre-fork" );
}

// Pilot basis inherited from H2a/H2b/H2c: 1e6 raw BTS units per USD cent.
constexpr int64_t H2E_RAW_PER_USD_CENT = 1000000LL;
constexpr uint64_t H2E_VAULT_USD_CENTS = 1340000;    // $13,400 vault min_bond
constexpr uint64_t H2E_ORACLE_USD_CENTS = 1005000;   // $10,050 oracle min_bond
constexpr uint64_t H2E_FLOOR_USD_CENTS = 83750;      // $837.50 dispute base
const share_type H2E_VAULT_RAW =
      share_type( int64_t( H2E_VAULT_USD_CENTS ) * H2E_RAW_PER_USD_CENT );
const share_type H2E_ORACLE_RAW =
      share_type( int64_t( H2E_ORACLE_USD_CENTS ) * H2E_RAW_PER_USD_CENT );
const share_type H2E_ROUND1_RAW =
      share_type( int64_t( H2E_FLOOR_USD_CENTS ) * H2E_RAW_PER_USD_CENT );

string h2e_evidence( const string& tag )
{ return string( "evidence:" ) + tag; }

void h2e_make_committee_member( database_fixture& f, const account_object& account )
{
   f.upgrade_to_lifetime_member( account );
   f.create_and_seat_committee_member( account );
}

reference_asset_id_type h2e_create_reference(
      database_fixture& f, account_id_type creator, const fc::ecc::private_key& key,
      const string& symbol, uint8_t precision )
{
   reference_asset_create_operation op;
   op.creator     = creator;
   op.symbol      = symbol;
   op.precision   = precision;
   op.description = symbol + " reference asset";
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return reference_asset_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

oracle_id_type h2e_make_oracle(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      const string& name, reference_asset_id_type base, reference_asset_id_type quote,
      const oracle_options& opts )
{
   oracle_create_operation op;
   op.owner   = owner;
   op.name    = name;
   op.base    = base;
   op.quote   = quote;
   op.series  = { oracle_series( oracle_series_kind::mid,
                                 oracle_series_rounding::unspecified ) };
   op.options = opts;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return oracle_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

asset_id_type h2e_create_uia(
      database_fixture& f, account_id_type issuer, const fc::ecc::private_key& key,
      const string& symbol, uint8_t precision = 5 );

/// Pilot-scale default pair (AC-02): vault scaffolding binds a fresh
/// zero-supply UIA, never CORE (whose 1e15 genesis supply is now correctly
/// refused at the pilot gate in vault_register::do_evaluate). Find-or-create
/// keeps the suite's fixed-pair semantics: repeat registrations in one test
/// still hit the duplicate-pair gate, exactly as with the old CORE default.
asset_id_type h2e_default_pair(
      database_fixture& f, account_id_type issuer, const fc::ecc::private_key& key )
{
   const auto& sym_idx =
         f.db.get_index_type<asset_index>().indices().get<by_symbol>();
   const auto itr = sym_idx.find( "H2EPAIR" );
   if( itr != sym_idx.end() )
      return itr->get_id();
   return h2e_create_uia( f, issuer, key, "H2EPAIR" );
}

vault_id_type h2e_register_vault(
      database_fixture& f, account_id_type registrar, const fc::ecc::private_key& key,
      const authority& vault_auth, share_type min_bond, uint64_t min_bond_usd,
      asset_id_type pair = asset_id_type() )
{
   vault_register_operation op;
   op.registrar            = registrar;
   op.pair                 = ( pair == asset_id_type() )
         ? h2e_default_pair( f, registrar, key ) : pair;
   op.vault_authority      = vault_auth;
   op.min_bond             = min_bond;
   op.min_bond_usd_cents   = min_bond_usd;
   op.bond_asset           = asset_id_type();
   op.secure_ratio_bps     = 20000;
   op.challenge_window_sec = GRAPHENE_H2_BOND_UNBOND_DELAY_SEC;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vault_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

vault_id_type h2e_register_vault_default(
      database_fixture& f, account_id_type registrar, const fc::ecc::private_key& key,
      const authority& vault_auth )
{
   return h2e_register_vault( f, registrar, key, vault_auth, H2E_VAULT_RAW, H2E_VAULT_USD_CENTS );
}

vesting_balance_id_type h2e_make_cdd_vesting(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      share_type amount )
{
   vesting_balance_create_operation op;
   op.creator = owner;
   op.owner   = owner;
   op.amount  = asset( amount, asset_id_type() );
   op.policy  = cdd_vesting_policy_initializer(
         GRAPHENE_H2_BOND_UNBOND_DELAY_SEC, f.db.head_block_time() + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vesting_balance_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

vault_bond_id_type h2e_lock_vault_bond(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      vault_id_type vault, vesting_balance_id_type vesting,
      share_type amount, uint64_t usd_cents )
{
   vault_bond_lock_operation op;
   op.owner           = owner;
   op.vault           = vault;
   op.vesting_balance = vesting;
   op.bond_amount     = amount;
   op.bond_usd_cents  = usd_cents;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vault_bond_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

producer_bond_id_type h2e_lock_producer_bond(
      database_fixture& f, account_id_type producer, const fc::ecc::private_key& key,
      oracle_id_type oracle, vesting_balance_id_type vesting,
      share_type amount, uint64_t usd_cents, uint16_t bootstrap = 0 )
{
   oracle_bond_lock_operation op;
   op.producer          = producer;
   op.oracle            = oracle;
   op.vesting_balance   = vesting;
   op.bond_amount       = amount;
   op.bond_usd_cents    = usd_cents;
   op.bootstrap_weight  = bootstrap;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return producer_bond_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

void h2e_publish(
      database_fixture& f, oracle_id_type oid,
      account_id_type who, const fc::ecc::private_key& key,
      int64_t base_amount, int64_t quote_amount )
{
   oracle_publish_operation op;
   op.producer  = who;
   op.oracle_id = oid;
   op.values    = { oracle_value( base_amount, quote_amount ) };
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2e_set_outstanding( database_fixture& f, vault_id_type vid, share_type amount )
{
   const vault_object& v = vid( f.db );
   f.db.modify( v, [&amount]( vault_object& m ) { m.outstanding = amount; } );
}

oracle_dispute_id_type h2e_post_dispute(
      database_fixture& f, account_id_type challenger, const fc::ecc::private_key& key,
      oracle_id_type oracle, account_id_type defender,
      const fc::time_point_sec& accused_time, uint16_t series, const string& memo )
{
   oracle_dispute_operation op;
   op.challenger      = challenger;
   op.oracle          = oracle;
   op.defender        = defender;
   op.accused_time    = accused_time;
   op.accused_series  = series;
   op.dispute_bond    = H2E_ROUND1_RAW;
   op.dispute_bond_usd_cents = H2E_FLOOR_USD_CENTS;
   op.evidence_memo   = memo;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return oracle_dispute_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

vault_challenge_id_type h2e_post_challenge(
      database_fixture& f, account_id_type challenger, const fc::ecc::private_key& key,
      vault_id_type vault, const string& memo )
{
   vault_challenge_operation op;
   op.challenger               = challenger;
   op.vault                    = vault;
   op.challenge_bond           = H2E_ROUND1_RAW;
   op.challenge_bond_usd_cents = H2E_FLOOR_USD_CENTS;
   op.evidence_memo            = memo;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return vault_challenge_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

void h2e_vote(
      database_fixture& f, account_id_type voter, const fc::ecc::private_key& key,
      object_id_type target, uint8_t decision )
{
   challenge_vote_operation op;
   op.voter    = voter;
   op.target   = target;
   op.decision = decision;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

/// Votes a fast-reject supermajority from the genesis seated set. GOV-R17-02:
/// the deciding set is the ELECTED set (active_committee_members), not the
/// permissionless registry, and the threshold mirrors the evaluator's
/// supermajority helper -- a registry-sized vote loop overruns the
/// resolution and the last vote is refused as non-OPEN.
void h2e_fast_reject_from_genesis( database_fixture& f, object_id_type target )
{
   const uint64_t n = f.db.get_global_properties().active_committee_members.size();
   BOOST_REQUIRE( n > 0 );
   const uint64_t need = ( n * GRAPHENE_H2_SUPERMAJORITY_BPS + 9999 ) / 10000;
   for( uint64_t i = 0; i < need; ++i )
   {
      const auto& acct = f.get_account( string( "init" ) + fc::to_string( i ) );
      if( f.db.get_balance( acct.get_id(), asset_id_type() ).amount < share_type( 1000000 ) )
         f.fund( acct, asset( 1000000 ) );
      h2e_vote( f, acct.get_id(), f.init_account_priv_key, target,
                GRAPHENE_H2_DISPUTE_FAST_REJECT );
   }
}

/// Votes a sustain supermajority from the genesis seated set (BPS-constant
/// threshold mirroring the evaluator's supermajority helper; GOV-R17-02:
/// counted over the ELECTED set, active_committee_members).
void h2e_sustain_from_genesis( database_fixture& f, object_id_type target )
{
   const uint64_t n = f.db.get_global_properties().active_committee_members.size();
   BOOST_REQUIRE( n > 0 );
   const uint64_t need = ( n * GRAPHENE_H2_SUPERMAJORITY_BPS + 9999 ) / 10000;
   for( uint64_t i = 0; i < need; ++i )
   {
      const auto& acct = f.get_account( string( "init" ) + fc::to_string( i ) );
      if( f.db.get_balance( acct.get_id(), asset_id_type() ).amount < share_type( 1000000 ) )
         f.fund( acct, asset( 1000000 ) );
      h2e_vote( f, acct.get_id(), f.init_account_priv_key, target,
                GRAPHENE_H2_DISPUTE_SUSTAIN );
   }
}

/// Votes an exonerate supermajority from the genesis seated set (GOV-R17-02:
/// counted over the ELECTED set, active_committee_members).
void h2e_exonerate_from_genesis( database_fixture& f, object_id_type target )
{
   const uint64_t n = f.db.get_global_properties().active_committee_members.size();
   BOOST_REQUIRE( n > 0 );
   const uint64_t need = ( n * GRAPHENE_H2_SUPERMAJORITY_BPS + 9999 ) / 10000;
   for( uint64_t i = 0; i < need; ++i )
   {
      const auto& acct = f.get_account( string( "init" ) + fc::to_string( i ) );
      if( f.db.get_balance( acct.get_id(), asset_id_type() ).amount < share_type( 1000000 ) )
         f.fund( acct, asset( 1000000 ) );
      h2e_vote( f, acct.get_id(), f.init_account_priv_key, target,
                GRAPHENE_H2_DISPUTE_EXONERATE );
   }
}

/// ISS-R14-16 test adaptation: grant a season record the production shape by
/// backdating its window and stamping the verifier bit (hand-set precedent in
/// h2_seasoning_tests). Records exist only for vaulted pairs; the early
/// return keeps never-vaulted sites exact -- no flush, no block-cadence
/// change, the issuer-direct gate is already inert there. The flush precedes
/// the locate: a backdate written into an open pending session would be
/// discarded at the next clear, so the record is re-located in committed
/// state before the modify (file-local twin of h2x_grant_seasoning).
void h2e_grant_seasoning( database_fixture& f, asset_id_type pair )
{
   const auto& by_pair = f.db.get_index_type<seasoning_record_index>()
                            .indices().get<by_seasoning_pair>();
   if( by_pair.find( pair ) == by_pair.end() )
      return; // never-vaulted pair: no record exists and the gate is inert
   f.generate_block(); // seal setup: a backdate issued back-to-back would be discarded
   const auto itr = by_pair.find( pair );
   if( itr == by_pair.end() )
      return; // structural surprise: leave the record untouched
   const fc::time_point_sec backdate = f.db.head_block_time()
         - GRAPHENE_H2_SEASONING_WINDOW_SEC - 3600;
   f.db.modify( *itr, [&backdate]( seasoning_record_object& m ) {
      m.window_start  = backdate;
      m.min_vault_bps  = 50000;  // > the 2.0 (20000bps) and 1.0 (10000bps) floors
      m.min_oracle_bps = 50000;
      m.verifier_set   = true;
      m.complete       = true;
   } );
}

/// Committee oracle_unfreeze through the price-leg op (throws on refusal).
void h2e_committee_unfreeze(
      database_fixture& f, account_id_type unfreezer, const fc::ecc::private_key& key,
      oracle_id_type oid )
{
   oracle_unfreeze_operation uop;
   uop.unfreezer = unfreezer;
   uop.oracle    = oid;
   signed_transaction tx;
   tx.operations.push_back( uop );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

/// Owner frozen-flag update through oracle_update (throws on refusal).
void h2e_owner_set_frozen(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      oracle_id_type oid, bool frozen )
{
   oracle_update_operation uop;
   uop.owner     = owner;
   uop.oracle_id = oid;
   oracle_options opts = oid( f.db ).options;
   opts.frozen = frozen;
   uop.new_options = opts;
   signed_transaction tx;
   tx.operations.push_back( uop );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2e_freeze(
      database_fixture& f, account_id_type freezer, const fc::ecc::private_key& key,
      vault_id_type vault, oracle_id_type oracle )
{
   pair_freeze_operation op;
   op.freezer = freezer;
   op.vault   = vault;
   op.oracle  = oracle;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2e_set_fallback(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      oracle_id_type oracle, const optional<price_oracle>& fallback )
{
   oracle_fallback_set_operation op;
   op.owner    = owner;
   op.oracle   = oracle;
   op.fallback = fallback;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

/// Far-future consensus expiry for fallback bindings that do not exercise
/// expiry (rev2 far-future bind precedent in oracle_tests.cpp): strictly
/// positive so the op validate() gate passes and every refusal below
/// isolates its named gate (owner / self / series / hardfork leg), never the
/// expiry default. Far enough out that no test's block advance crosses it.
price_oracle h2e_fallback_to( database_fixture& f, oracle_id_type backup, uint16_t series )
{
   price_oracle fb;
   fb.oracle_id = backup;
   fb.series = series;
   fb.expiry_height = f.db.head_block_num() + 1000000000;
   return fb;
}

/// Creates a plain UIA to serve as a vault pair or pool leg.
asset_id_type h2e_create_uia(
      database_fixture& f, account_id_type issuer, const fc::ecc::private_key& key,
      const string& symbol, uint8_t precision )
{
   asset_create_operation op;
   op.issuer      = issuer;
   op.symbol      = symbol;
   op.precision   = precision;
   op.common_options.max_supply = GRAPHENE_MAX_SHARE_SUPPLY;
   op.common_options.core_exchange_rate = price( asset( 2 ), asset( 1, asset_id_type( 1 ) ) );
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   return asset_id_type {
      PUSH_TX( f.db, tx ).operation_results.front().get<object_id_type>() };
}

void h2e_delete_oracle(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      oracle_id_type oid )
{
   oracle_delete_operation op;
   op.owner     = owner;
   op.oracle_id = oid;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

void h2e_delete_oracle_throws(
      database_fixture& f, account_id_type owner, const fc::ecc::private_key& key,
      oracle_id_type oid )
{
   oracle_delete_operation op;
   op.owner     = owner;
   op.oracle_id = oid;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( f.db, tx ), fc::exception );
}

const tripwire_state_object* h2e_find_tripwire( database_fixture& f, asset_id_type pair )
{
   const auto& idx = f.db.get_index_type<tripwire_index>().indices().get<by_tripwire_pair>();
   const auto itr = idx.find( pair );
   return itr == idx.end() ? nullptr : &*itr;
}

const reward_pool_object* h2e_find_pool( database_fixture& f, oracle_id_type oid )
{
   const auto& idx = f.db.get_index_type<reward_pool_index>().indices().get<by_pool_oracle>();
   const auto itr = idx.find( oid );
   return itr == idx.end() ? nullptr : &*itr;
}

const guard_state_object* h2e_find_guard( database_fixture& f, oracle_id_type oid )
{
   const auto& idx = f.db.get_index_type<guard_state_index>().indices().get<by_guard_oracle>();
   const auto itr = idx.find( oid );
   return itr == idx.end() ? nullptr : &*itr;
}

const recovery_state_object* h2e_find_recovery( database_fixture& f )
{
   const auto& idx = f.db.get_index_type<recovery_state_index>().indices();
   return idx.empty() ? nullptr : &*idx.begin();
}

/// R11-R1 entitlement funding (public path): issues pair-token face from
/// the pair issuer to a senior claimant. Faces must fit the $20k
/// issuer-direct pilot cap; full-book settlements use surgery instead.
void h2e_issue_pair_face( database_fixture& f,
      account_id_type issuer, const fc::ecc::private_key& key,
      account_id_type recipient, asset_id_type pair, share_type amount )
{
   h2e_grant_seasoning( f, pair ); // ISS-R14-16: season the bound pair before the print
   asset_issue_operation op;
   op.issuer           = issuer;
   op.asset_to_issue   = asset( amount, pair );
   op.issue_to_account = recipient;
   signed_transaction tx;
   tx.operations.push_back( op );
   f.db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( f.db, tx );
   tx.sign( key, f.db.get_chain_id() );
   PUSH_TX( f.db, tx );
}

} // namespace

BOOST_FIXTURE_TEST_SUITE( h2_oracle_tests, database_fixture )

/// The new fallback op must be refused before the H2 bonds hardfork.
BOOST_AUTO_TEST_CASE( h2d_fallback_op_refused_before_the_hardfork )
{ try {
   ACTORS( (alice) );
   fund( alice );

   oracle_fallback_set_operation op;
   op.owner    = alice_id;
   op.oracle   = oracle_id_type( 0 );
   price_oracle fb = h2e_fallback_to( *this, oracle_id_type( 1 ), 0 );
   op.fallback  = fb;
   signed_transaction tx;
   tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   tx.sign( alice_private_key, db.get_chain_id() );
   h2e_require_gate_refusal( db, tx, "oracle_fallback_set pre-fork" );
} FC_LOG_AND_RETHROW() }

/// Routing shares are validated in consensus: they must sum to 10000 bps and
/// the oracle share must respect the joint 70% diversion cap (stealth parity).
BOOST_AUTO_TEST_CASE( routing_shares_sum_to_100pc_under_joint_cap )
{ try {
   BOOST_CHECK( h2_routing_valid( GRAPHENE_H2E_REWARD_ORACLE_BPS,
                                  GRAPHENE_H2E_REWARD_VAULT_BPS,
                                  GRAPHENE_H2E_REWARD_RESERVE_BPS,
                                  GRAPHENE_H2E_FEE_DIVERSION_CAP_BPS ) );
   BOOST_CHECK_EQUAL( GRAPHENE_H2E_REWARD_ORACLE_BPS
                      + GRAPHENE_H2E_REWARD_VAULT_BPS
                      + GRAPHENE_H2E_REWARD_RESERVE_BPS, 10000 );
   BOOST_CHECK( GRAPHENE_H2E_REWARD_ORACLE_BPS <= GRAPHENE_H2E_FEE_DIVERSION_CAP_BPS );
   // Over-100% routing is invalid ...
   BOOST_CHECK( !h2_routing_valid( 5000, 3000, 3000, GRAPHENE_H2E_FEE_DIVERSION_CAP_BPS ) );
   // ... as is an oracle share above the joint cap.
   BOOST_CHECK( !h2_routing_valid( 8000, 1000, 1000, GRAPHENE_H2E_FEE_DIVERSION_CAP_BPS ) );
} FC_LOG_AND_RETHROW() }

/// OSM bucket anchors sit on an absolute time grid derived from the delay
/// alone: interval changes can never shift them.
BOOST_AUTO_TEST_CASE( osm_bucket_anchor_is_absolute_grid )
{ try {
   // delay 3600 -> bucket 225; t=100000 anchors to 99900.
   BOOST_CHECK_EQUAL( h2_osm_bucket_anchor( 100000, 3600 ), 99900u );
   BOOST_CHECK_EQUAL( h2_osm_bucket_anchor( 99900, 3600 ), 99900u );
   BOOST_CHECK_EQUAL( h2_osm_bucket_anchor( 100124, 3600 ), 99900u );
   // Zero delay -> bucket 1 -> identity.
   BOOST_CHECK_EQUAL( h2_osm_bucket_anchor( 12345, 0 ), 12345u );
   // Sub-bucket delays collapse to bucket 1.
   BOOST_CHECK_EQUAL( h2_osm_bucket_anchor( 99999, 16 ), 99999u );
   // Deviation predicate exactness (256-bit, no rounding): 6% breaches 5%,
   // 4% does not, and equality with the bound is not a breach.
   BOOST_CHECK( h2_deviation_breaches( oracle_value( 106, 1 ), oracle_value( 100, 1 ),
                                       GRAPHENE_H2E_TRIPWIRE_DEVIATION_PPM ) );
   BOOST_CHECK( !h2_deviation_breaches( oracle_value( 104, 1 ), oracle_value( 100, 1 ),
                                        GRAPHENE_H2E_TRIPWIRE_DEVIATION_PPM ) );
   BOOST_CHECK( !h2_deviation_breaches( oracle_value( 105, 1 ), oracle_value( 100, 1 ),
                                        GRAPHENE_H2E_TRIPWIRE_DEVIATION_PPM ) );
   // Ratio-form values compare by cross-multiplication, not by truncation.
   BOOST_CHECK( h2_deviation_breaches( oracle_value( 212, 2 ), oracle_value( 100, 1 ),
                                       GRAPHENE_H2E_TRIPWIRE_DEVIATION_PPM ) );
   BOOST_CHECK( !h2_deviation_breaches( oracle_value( 208, 2 ), oracle_value( 100, 1 ),
                                        GRAPHENE_H2E_TRIPWIRE_DEVIATION_PPM ) );
   // Pro-rata floors (rounding DOWN against payees); zero total pays nothing.
   BOOST_CHECK( h2_pro_rata( share_type( 100 ), 1, 3 ) == share_type( 33 ) );
   BOOST_CHECK( h2_pro_rata( share_type( 100 ), 0, 3 ) == share_type( 0 ) );
   BOOST_CHECK( h2_pro_rata( share_type( 100 ), 1, 0 ) == share_type( 0 ) );
   // Face-to-bond conversion truncates.
   BOOST_CHECK( h2_convert_face_to_bond( share_type( 3 ), oracle_value( 100, 1 ) )
                == share_type( 300 ) );
   BOOST_CHECK( h2_convert_face_to_bond( share_type( 1 ), oracle_value( 1, 3 ) )
                == share_type( 0 ) );
} FC_LOG_AND_RETHROW() }

/// Reward pool: swept 15% forfeits pay bonded live producers pro-rata at
/// maintenance with exact remainder; the unbonded and the stale get nothing.
BOOST_AUTO_TEST_CASE( reward_pool_pays_pro_rata_live_weight_with_exact_remainder )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave)(erin)(fred)(ginger) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( dave, asset( 30000000000000LL ) );
   fund( erin, asset( 30000000000000LL ) );
   fund( fred, asset( 30000000000000LL ) );
   fund( ginger, asset( 30000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   // Weights 1/2/4/1: total 7 does not divide the pool -> dust stays pooled.
   oracle_options opts;
   opts.producers[bob_id]   = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 2 );
   opts.producers[dave_id]  = oracle_producer_entry( 4 );
   opts.producers[erin_id]  = oracle_producer_entry( 1 ); // publishes, never bonds
   opts.producers[fred_id]  = oracle_producer_entry( 1 ); // bonds, then goes stale
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "REWARD.USD", bts_ref, usd_ref, opts );

   // Bond lock creates the reward pool + guard state shells for the oracle.
   const auto vb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, oid, vb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   const auto vc = h2e_make_cdd_vesting( *this, carol_id, carol_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, carol_id, carol_private_key, oid, vc, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   const auto vd = h2e_make_cdd_vesting( *this, dave_id, dave_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, dave_id, dave_private_key, oid, vd, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   const auto vf = h2e_make_cdd_vesting( *this, fred_id, fred_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, fred_id, fred_private_key, oid, vf, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   BOOST_REQUIRE( h2e_find_pool( *this, oid ) != nullptr );
   BOOST_REQUIRE( h2e_find_guard( *this, oid ) != nullptr );
   const reward_pool_object* pool0 = h2e_find_pool( *this, oid );
   BOOST_CHECK( pool0->balance == share_type( 0 ) );
   BOOST_CHECK( h2_routing_valid( pool0->routing_oracle_bps, pool0->routing_vault_bps,
                                  pool0->routing_reserve_bps,
                                  GRAPHENE_H2E_FEE_DIVERSION_CAP_BPS ) );

   // Fred publishes early, then the chain moves past the value lifetime so his
   // submission is stale for the payout: bonded but not live -> unpaid.
   h2e_publish( *this, oid, fred_id, fred_private_key, 100, 1 );
   generate_blocks( db.head_block_time() + 90000 );
   generate_block();
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   h2e_publish( *this, oid, carol_id, carol_private_key, 100, 1 );
   h2e_publish( *this, oid, dave_id, dave_private_key, 100, 1 );
   h2e_publish( *this, oid, erin_id, erin_private_key, 100, 1 );

    // Promotion records carry the liveness count observed at promotion time.
    // All four publishes land in the same block (same head time), so only the
    // first one advances the consumed value and records: at bob's publish the
    // live set is bob alone (fred's submission is 90000s old against the 86400s
    // lifetime, hence stale; carol/dave/erin have not published yet). Same-block
    // republishes with unchanged time and value record nothing further.
    const guard_state_object* guard = h2e_find_guard( *this, oid );
    BOOST_REQUIRE( guard != nullptr );
    BOOST_REQUIRE( !guard->promotion_log.empty() );
    BOOST_CHECK_EQUAL( guard->promotion_log.back().producer_count, 1u );
   BOOST_CHECK( guard->promotion_log.back().promote_time == oid( db ).consumed_value_time );

   // A spam dispute fast-rejects: 15% of the base accrues to the pool shell.
   const fc::time_point_sec accused = oid( db ).history.back().first;
   const oracle_dispute_id_type did = h2e_post_dispute(
         *this, ginger_id, ginger_private_key, oid, bob_id, accused, 0,
         h2e_evidence( "spam-reward" ) );
   h2e_fast_reject_from_genesis( *this, object_id_type( did ) );
   BOOST_REQUIRE_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_FAST_REJECTED );
   const int64_t pool_expect = H2E_ROUND1_RAW.value * 1500 / 10000;
   BOOST_CHECK( oid( db ).forfeit_pool_balance == share_type( pool_expect ) );

   // Balances after every fee is paid, before the sweep: deltas are payouts.
   const share_type bob_before = db.get_balance( bob_id, asset_id_type() ).amount;
   const share_type carol_before = db.get_balance( carol_id, asset_id_type() ).amount;
   const share_type dave_before = db.get_balance( dave_id, asset_id_type() ).amount;
   const share_type erin_before = db.get_balance( erin_id, asset_id_type() ).amount;
   const share_type fred_before = db.get_balance( fred_id, asset_id_type() ).amount;

   // The next maintenance sweeps the forfeit into the pool and pays it out.
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();

   const int64_t bob_expect = pool_expect * 1 / 7;
   const int64_t carol_expect = pool_expect * 2 / 7;
   const int64_t dave_expect = pool_expect * 4 / 7;
   BOOST_CHECK( db.get_balance( bob_id, asset_id_type() ).amount == bob_before + bob_expect );
   BOOST_CHECK( db.get_balance( carol_id, asset_id_type() ).amount == carol_before + carol_expect );
   BOOST_CHECK( db.get_balance( dave_id, asset_id_type() ).amount == dave_before + dave_expect );
   // Unbonded publisher and stale bonder earn nothing (liveness-only rule).
   BOOST_CHECK( db.get_balance( erin_id, asset_id_type() ).amount == erin_before );
   BOOST_CHECK( db.get_balance( fred_id, asset_id_type() ).amount == fred_before );
   // Accrual shell is drained; dust remainder stays pooled, never minted.
   BOOST_CHECK( oid( db ).forfeit_pool_balance == share_type( 0 ) );
   const reward_pool_object* pool1 = h2e_find_pool( *this, oid );
   BOOST_CHECK( pool1->balance
                == share_type( pool_expect - bob_expect - carol_expect - dave_expect ) );
   BOOST_CHECK( pool1->paid_lifetime == share_type( bob_expect + carol_expect + dave_expect ) );
} FC_LOG_AND_RETHROW() }

/// Per-interval promotion rate counters: past 512 promotions in one window
/// the H2 read path holds fail-closed; the next window clears it.
BOOST_AUTO_TEST_CASE( promotion_rate_limit_holds_h2_reads_past_512 )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "RATE.USD", bts_ref, usd_ref, opts );
   const auto vb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, oid, vb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );

   // Same-block publishes with distinct values: every one promotes (the value
   // changes), so all count in the current interval window without crossing
   // maintenance. One less than the flood: no hold.
   for( uint32_t i = 0; i < GRAPHENE_H2E_PROMOTION_LIMIT_PER_INTERVAL - 1; ++i )
      h2e_publish( *this, oid, bob_id, bob_private_key, 100 + i, 1 );
   const guard_state_object* guard0 = h2e_find_guard( *this, oid );
   BOOST_REQUIRE( guard0 != nullptr );
   BOOST_CHECK_EQUAL( guard0->promotion_count, GRAPHENE_H2E_PROMOTION_LIMIT_PER_INTERVAL - 1 );
   BOOST_CHECK_EQUAL( guard0->consumption_hold, false );

   // The anchor stored on the record is the absolute-grid anchor of the
   // promotion time under the committee delay: hardening, not decoration.
   const uint32_t delay = db.get_global_properties().parameters.get_oracle_guard_delay_sec();
   BOOST_CHECK( guard0->promotion_log.back().anchor
                == h2_osm_bucket_anchor( uint32_t( guard0->promotion_log.back()
                                                  .promote_time.sec_since_epoch() ), delay ) );

   // Two more promotions cross the limit: the hold engages and H2 reads fail
   // closed while the raw aggregate stays transparent.
   h2e_publish( *this, oid, bob_id, bob_private_key, 100000, 1 );
   h2e_publish( *this, oid, bob_id, bob_private_key, 100001, 1 );
   const guard_state_object* guard1 = h2e_find_guard( *this, oid );
   BOOST_CHECK_EQUAL( guard1->consumption_hold, true );
   BOOST_CHECK( oid( db ).current_value.valid() );
   BOOST_CHECK( !h2_read_consumed_price( db, oid, 0, db.head_block_time() ).valid() );

   // The next interval window clears the hold: reads resume.
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   h2e_publish( *this, oid, bob_id, bob_private_key, 100002, 1 );
   const guard_state_object* guard2 = h2e_find_guard( *this, oid );
   BOOST_CHECK_EQUAL( guard2->consumption_hold, false );
   BOOST_CHECK_EQUAL( guard2->promotion_count, 1u );
   BOOST_CHECK( h2_read_consumed_price( db, oid, 0, db.head_block_time() ).valid() );
} FC_LOG_AND_RETHROW() }

/// Fallback op auth + switch semantics: owner sets, strangers cannot;
/// self-reference and out-of-range series are refused; clearing works.
BOOST_AUTO_TEST_CASE( fallback_set_op_auth_and_bounds )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice );
   fund( bob );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   oracle_options opts;
   const oracle_id_type o1 =
         h2e_make_oracle( *this, alice_id, alice_private_key, "FB1.USD", bts_ref, usd_ref, opts );
   const oracle_id_type o2 =
         h2e_make_oracle( *this, alice_id, alice_private_key, "FB2.USD", bts_ref, usd_ref, opts );

   // Strangers cannot set another oracle's fallback.
   {
      oracle_fallback_set_operation op;
      op.owner   = bob_id;
      op.oracle  = o1;
      price_oracle fb = h2e_fallback_to( *this, o2, 0 );
      op.fallback = fb;
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( bob_private_key, db.get_chain_id() );
      BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   // Self-reference is refused (single backup, never a chain to oneself).
   {
      oracle_fallback_set_operation op;
      op.owner   = alice_id;
      op.oracle  = o1;
      price_oracle fb = h2e_fallback_to( *this, o1, 0 );
      op.fallback = fb;
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   // Out-of-range series is refused (single-series oracles here).
   {
      oracle_fallback_set_operation op;
      op.owner   = alice_id;
      op.oracle  = o1;
      price_oracle fb = h2e_fallback_to( *this, o2, 7 );
      op.fallback = fb;
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   // Owner sets, then clears.
   price_oracle fb = h2e_fallback_to( *this, o2, 0 );
   h2e_set_fallback( *this, alice_id, alice_private_key, o1, optional<price_oracle>( fb ) );
   BOOST_REQUIRE( h2e_find_guard( *this, o1 ) != nullptr );
   BOOST_CHECK( h2e_find_guard( *this, o1 )->fallback.valid() );
   BOOST_CHECK( h2e_find_guard( *this, o1 )->fallback->oracle_id == o2 );
   h2e_set_fallback( *this, alice_id, alice_private_key, o1, optional<price_oracle>() );
   BOOST_CHECK( !h2e_find_guard( *this, o1 )->fallback.valid() );
} FC_LOG_AND_RETHROW() }

/// Fallback switch on dual-stale, read through a bound vault's wind-down
/// conversion: primary serves while live, backup serves when primary is
/// stale, dual-stale halts the conversion-dependent claim.
BOOST_AUTO_TEST_CASE( fallback_switch_serves_backup_then_halts_on_dual_stale )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( dave, asset( 30000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type primary =
         h2e_make_oracle( *this, alice_id, alice_private_key, "PRI.USD", bts_ref, usd_ref, opts );
   const oracle_id_type backup =
         h2e_make_oracle( *this, alice_id, alice_private_key, "BAK.USD", bts_ref, usd_ref, opts );
   const auto vb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, primary, vb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   // Separate block: an identical same-owner same-amount vesting create in the
   // same block is the identical transaction (same expiration, same signature)
   // and is refused as a duplicate, not as economics.
   generate_block();
   const auto vb2 = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, backup, vb2, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   price_oracle fb = h2e_fallback_to( *this, backup, 0 );
   h2e_set_fallback( *this, alice_id, alice_private_key, primary,
                     optional<price_oracle>( fb ) );

   // Vault with full-size books: full bond against full-size outstanding
   // breaches 150% only past the edge (see the recovery case for the edge).
   // Here outstanding equals the bond (100%) to force top-up -> wind-down.
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2e_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2E_VAULT_RAW, H2E_VAULT_USD_CENTS );
   const auto vest = h2e_make_cdd_vesting( *this, alice_id, alice_private_key, H2E_VAULT_RAW );
   h2e_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2E_VAULT_RAW,
                        H2E_VAULT_USD_CENTS );
   // Pin the canonical pair<->oracle binding through the first freeze ...
   h2e_freeze( *this, alice_id, alice_private_key, vid, primary );
   BOOST_REQUIRE( vid( db ).bound_oracle.valid() );
   BOOST_CHECK( *vid( db ).bound_oracle == primary );
   // ... then unfreeze for the test (binding persists; the freeze was the pin).
   generate_block();
   db.modify( vid( db ), []( vault_object& v ) { v.frozen = false; } );
   db.modify( primary( db ), []( oracle_object& o ) { o.options.frozen = false; } );

   // Breach -> top-up -> wind-down: segregated full bond against equal
   // face (100% < 150%), so the share leg pays face verbatim.
   generate_block();
   h2e_set_outstanding( *this, vid, H2E_VAULT_RAW );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_REQUIRE_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_TOPUP );
   generate_blocks( vid( db ).top_up_deadline + 2 * 86400 );
   generate_block();
   BOOST_REQUIRE_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_WINDDOWN );
   const winddown_vault_id_type wdid {
      db.get_index_type<winddown_vault_index>().indices().begin()->id };

   // Primary live at 100 BTS per face unit: pro-rata binds at face/100.
   h2e_publish( *this, primary, bob_id, bob_private_key, 100, 1 );
   h2e_publish( *this, backup, bob_id, bob_private_key, 200, 1 );
    const share_type face( 1000000 );
    // R11-R1 entitlement: carol's senior face must exist before she claims.
    h2e_issue_pair_face( *this, alice_id, alice_private_key, carol_id,
                         wdid( db ).pair, face );
    const share_type carol_before = db.get_balance( carol_id, asset_id_type() ).amount;
   winddown_claim_operation cop;
   cop.claimant     = carol_id;
   cop.winddown     = wdid;
   cop.claim_amount = face;
   cop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction ctx; ctx.operations.push_back( cop );
   db.current_fee_schedule().set_fee( ctx.operations.back() );
   set_expiration( db, ctx );
   ctx.sign( carol_private_key, db.get_chain_id() );
   PUSH_TX( db, ctx );
   // Price-invariant converted payout: the pro-rata share leg is face x
   // segregated / total verbatim (price cancels), so carol at 100 BTS/face
   // equals dave at 200 BTS/face: min(haircut-in-bond, 1000000) = 1000000.
   BOOST_CHECK( db.get_balance( carol_id, asset_id_type() ).amount
                == carol_before + share_type( 1000000 ) );

   // Primary goes stale; backup stays live: the switch serves backup math.
   generate_blocks( db.head_block_time() + 90000 );
   generate_block();
    h2e_publish( *this, backup, bob_id, bob_private_key, 200, 1 );
    // R11-R1 entitlement: dave's senior face must exist before he claims.
    h2e_issue_pair_face( *this, alice_id, alice_private_key, dave_id,
                         wdid( db ).pair, face );
    const share_type dave_before = db.get_balance( dave_id, asset_id_type() ).amount;
   winddown_claim_operation dop;
   dop.claimant     = dave_id;
   dop.winddown     = wdid;
   dop.claim_amount = face;
   dop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction dtx; dtx.operations.push_back( dop );
   db.current_fee_schedule().set_fee( dtx.operations.back() );
   set_expiration( db, dtx );
   dtx.sign( dave_private_key, db.get_chain_id() );
   PUSH_TX( db, dtx );
   // Price-invariance check: dave at backup price 200 BTS/face must equal
   // carol at 100 BTS/face (share leg verbatim, only the haircut cap converts).
   BOOST_CHECK( db.get_balance( dave_id, asset_id_type() ).amount
                == dave_before + share_type( 1000000 ) );

   // Dual-stale halts: no live leg, no conversion-dependent claim.
   generate_blocks( db.head_block_time() + 90000 );
   generate_block();
   BOOST_CHECK( !h2_read_pair_price( db, vid( db ), 0, db.head_block_time() ).valid() );
   winddown_claim_operation sop;
   sop.claimant     = alice_id;
   sop.winddown     = wdid;
   sop.claim_amount = face;
   sop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction stx; stx.operations.push_back( sop );
   db.current_fee_schedule().set_fee( stx.operations.back() );
   set_expiration( db, stx );
   stx.sign( alice_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, stx ), fc::exception );
} FC_LOG_AND_RETHROW() }

/// ATR-R17-01 (CONFIRMED_IMPORTANT): an administrative freeze of
/// the bound oracle must hold at the pair read. The owner-controlled backup
/// covers staleness/liveness loss of the bound series only -- never a freeze
/// (committee tripwire, challenge, pair_freeze). RED pre-fix: the frozen
/// primary still hopped to the live backup, because the hop predated the
/// frozen-flag refusal h2_read_consumed_price applies to the primary, so
/// freezing an already-stale self-owned primary never halted the vault's
/// consumed price.
BOOST_AUTO_TEST_CASE( atr_r17_01_frozen_bound_oracle_refuses_the_backup_hop )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type primary =
         h2e_make_oracle( *this, alice_id, alice_private_key, "A17P.USD", bts_ref, usd_ref, opts );
   const oracle_id_type backup =
         h2e_make_oracle( *this, alice_id, alice_private_key, "A17B.USD", bts_ref, usd_ref, opts );
   const auto vb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, primary, vb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   generate_block(); // identical same-block vesting create would be a duplicate tx
   const auto vb2 = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, backup, vb2, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   price_oracle fb = h2e_fallback_to( *this, backup, 0 );
   h2e_set_fallback( *this, alice_id, alice_private_key, primary,
                     optional<price_oracle>( fb ) );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2e_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2E_VAULT_RAW, H2E_VAULT_USD_CENTS );
   const auto vest = h2e_make_cdd_vesting( *this, alice_id, alice_private_key, H2E_VAULT_RAW );
   h2e_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2E_VAULT_RAW,
                        H2E_VAULT_USD_CENTS );
   h2e_freeze( *this, alice_id, alice_private_key, vid, primary );
   BOOST_REQUIRE( vid( db ).bound_oracle.valid() );
   generate_block();
   db.modify( vid( db ), []( vault_object& v ) { v.frozen = false; } );
   db.modify( primary( db ), []( oracle_object& o ) { o.options.frozen = false; } );

   // Both legs live: the primary serves.
   h2e_publish( *this, primary, bob_id, bob_private_key, 100, 1 );
   h2e_publish( *this, backup, bob_id, bob_private_key, 200, 1 );
   {
      const auto p = h2_read_pair_price( db, vid( db ), 0, db.head_block_time() );
      BOOST_REQUIRE( p.valid() );
      BOOST_CHECK( p->base_amount == share_type( 100 ) );
   }

   // Primary stale, backup live: the hop serves (the control leg -- the fix
   // must not kill the backup's designed staleness purpose).
   generate_blocks( db.head_block_time() + 90000 );
   generate_block();
   h2e_publish( *this, backup, bob_id, bob_private_key, 200, 1 );
   {
      const auto p = h2_read_pair_price( db, vid( db ), 0, db.head_block_time() );
      BOOST_REQUIRE( p.valid() );
      BOOST_CHECK( p->base_amount == share_type( 200 ) );
   }

   // Now freeze the BOUND oracle (the flag every admin path sets): the
   // backup must NOT be read, even though it is live. Flush first: the
   // backup publish above leaves the pending session open and a direct
   // surgery into it would be rolled back by the next block (the
   // pending-session rule; same flush discipline as the h2_09 recovery
   // tests).
   generate_block();
   db.modify( primary( db ), []( oracle_object& o ) { o.options.frozen = true; } );
   generate_block();
   BOOST_CHECK( !h2_read_pair_price( db, vid( db ), 0, db.head_block_time() ).valid() );
} FC_LOG_AND_RETHROW() }

/// Recovery trigger over the explicit system scope: below 150% new debt
/// (vault_register) is refused while exits stay possible; restoration clears.
BOOST_AUTO_TEST_CASE( recovery_suspends_new_debt_at_150_scope_then_clears )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );

   authority vault_auth( 1, alice_id, 1 );
   const share_type bonds = H2E_VAULT_RAW;
   const vault_id_type vid = h2e_register_vault(
         *this, alice_id, alice_private_key, vault_auth, bonds, H2E_VAULT_USD_CENTS );
   const auto vest = h2e_make_cdd_vesting( *this, alice_id, alice_private_key, bonds );
   h2e_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, bonds,
                        H2E_VAULT_USD_CENTS );

   // Exactly 150% is healthy (cross-multiplied equality meets):
   // floor(1.34e12 x 10000/15000) = 893333333333.
   generate_block();
   h2e_set_outstanding( *this, vid, share_type( 893333333333LL ) );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   const recovery_state_object* healthy = h2e_find_recovery( *this );
   BOOST_REQUIRE( healthy != nullptr );
   BOOST_CHECK_EQUAL( healthy->new_debt_suspended, false );

   // One unit past the edge: 1340000000000/893333333334 < 150% -> Recovery enters.
   h2e_set_outstanding( *this, vid, share_type( 893333333334LL ) );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   const recovery_state_object* tripped = h2e_find_recovery( *this );
   BOOST_REQUIRE( tripped != nullptr );
   BOOST_CHECK_EQUAL( tripped->new_debt_suspended, true );
   BOOST_CHECK( tripped->last_collateral == bonds );
   BOOST_CHECK( tripped->last_debt == share_type( 893333333334LL ) );

    // New debt is suspended (full-size terms, so the refusal isolates the
    // suspension gate, never the bond floors) ...
    // NOTE (vacuous pre-existing): this duplicate-pair leg refuses at the
    // duplicate-pair gate (vault_evaluator.cpp:104-105, earlier in
    // do_evaluate), not the Recovery gate — preserved as-is.
    BOOST_CHECK_THROW( h2e_register_vault( *this, bob_id, bob_private_key,
                                           authority( 1, bob_id, 1 ),
                                           H2E_VAULT_RAW, H2E_VAULT_USD_CENTS ),
                       fc::exception );

    // Fresh-pair Recovery proof (defense vault_evaluator.cpp:111-113 ->
    // test recovery_fresh_pair_refused_during_suspension): a never-used
    // zero-supply UIA skips the duplicate-pair gate (new pair) and the
    // pilot gate (zero supply), so refusal isolates the Recovery gate.
    BOOST_CHECK_THROW( h2e_register_vault(
          *this, bob_id, bob_private_key, authority( 1, bob_id, 1 ),
          H2E_VAULT_RAW, H2E_VAULT_USD_CENTS, h2e_create_uia(
                *this, bob_id, bob_private_key, "RECOV1" ) ),
                       fc::exception );

     // ... restoration clears it (before the 36h top-up expires: no wind-down).
    // New block first: the refused registration above leaves the pending undo
    // session open, and a direct modify into that session would be rolled back
    // by the next block (pending state rebuilds from pushed transactions only).
     generate_block();
     h2e_set_outstanding( *this, vid, share_type( 893333333333LL ) );
     generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
     generate_block();
     BOOST_CHECK_EQUAL( h2e_find_recovery( *this )->new_debt_suspended, false );
   const vault_id_type vid2 = h2e_register_vault(
         *this, bob_id, bob_private_key, authority( 1, bob_id, 1 ),
         H2E_VAULT_RAW, H2E_VAULT_USD_CENTS, h2e_create_uia(
               *this, bob_id, bob_private_key, "RECOV2" ) );
   BOOST_CHECK( db.find( vid2 ) != nullptr );
} FC_LOG_AND_RETHROW() }

/// Rotate now proves the FULL old threshold in signing weight: a lone
/// 1-of-3 member cannot rotate; two members co-signing can.
BOOST_AUTO_TEST_CASE( rotate_requires_full_old_threshold_weight )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );

   authority old_auth( 2, alice_id, 1, bob_id, 1, carol_id, 1 );
   const vault_id_type vid = h2e_register_vault_default(
         *this, alice_id, alice_private_key, old_auth );
   const auto vest = h2e_make_cdd_vesting( *this, alice_id, alice_private_key, H2E_VAULT_RAW );
   h2e_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2E_VAULT_RAW,
                        H2E_VAULT_USD_CENTS );

   authority new_auth( 1, carol_id, 1 );

   // Lone member: weight 1 of 2 -> refused despite membership.
   {
      vault_rotate_operation rop;
      rop.rotator       = alice_id;
      rop.vault         = vid;
      rop.new_authority = new_auth;
      signed_transaction rtx; rtx.operations.push_back( rop );
      db.current_fee_schedule().set_fee( rtx.operations.back() );
      set_expiration( db, rtx );
      rtx.sign( alice_private_key, db.get_chain_id() );
      BOOST_CHECK_THROW( PUSH_TX( db, rtx ), fc::exception );
      BOOST_CHECK( !( vid( db ).vault_authority == new_auth ) );
   }
   // Non-member co-signer adds no weight -> still refused.
   {
      vault_rotate_operation rop;
      rop.rotator       = alice_id;
      rop.vault         = vid;
      rop.new_authority = new_auth;
      // dave is not a member of the old set (validate passes: unknown ids
      // are structurally fine); the weight check refuses.
      rop.co_signers.insert( account_id_type( 999999 ) );
      signed_transaction rtx; rtx.operations.push_back( rop );
      db.current_fee_schedule().set_fee( rtx.operations.back() );
      set_expiration( db, rtx );
      rtx.sign( alice_private_key, db.get_chain_id() );
      BOOST_CHECK_THROW( PUSH_TX( db, rtx ), fc::exception );
   }
   // Rotator plus one member co-signer: weight 2 of 2, both signatures
   // required by the operation's authority gathering -> rotates.
   {
      vault_rotate_operation rop;
      rop.rotator       = alice_id;
      rop.vault         = vid;
      rop.new_authority = new_auth;
      rop.co_signers.insert( bob_id );
      signed_transaction rtx; rtx.operations.push_back( rop );
      db.current_fee_schedule().set_fee( rtx.operations.back() );
      set_expiration( db, rtx );
      rtx.sign( alice_private_key, db.get_chain_id() );
      rtx.sign( bob_private_key, db.get_chain_id() );
      PUSH_TX( db, rtx );
      BOOST_CHECK( vid( db ).vault_authority == new_auth );
   }
} FC_LOG_AND_RETHROW() }

/// Canonical pair<->oracle binding: the first pair_freeze pins it; any later
/// freeze naming a different oracle is refused; re-freezing the bound pair
/// stays atomic. R11R2: the bind no longer closes the door at zero debt --
/// the pin lands with the door and the debt tap open (close-race freeze only
/// over live debt).
BOOST_AUTO_TEST_CASE( pair_freeze_pins_canonical_binding_and_enforces_it )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   oracle_options opts;
   const oracle_id_type o1 =
         h2e_make_oracle( *this, alice_id, alice_private_key, "BIND.USD", bts_ref, usd_ref, opts );
   const oracle_id_type o2 =
         h2e_make_oracle( *this, alice_id, alice_private_key, "OTHER.USD", bts_ref, usd_ref, opts );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2e_register_vault_default(
         *this, alice_id, alice_private_key, vault_auth );

   BOOST_CHECK( !vid( db ).bound_oracle.valid() );
   // First freeze pins the binding; at zero debt the door and the debt tap
   // stay open (R11R2 bind/freeze decoupling, still one atomic apply).
   h2e_freeze( *this, alice_id, alice_private_key, vid, o1 );
   BOOST_REQUIRE( vid( db ).bound_oracle.valid() );
   BOOST_CHECK( *vid( db ).bound_oracle == o1 );
   BOOST_CHECK_EQUAL( vid( db ).frozen, false );
   BOOST_CHECK_EQUAL( o1( db ).options.frozen, false );

   // A later freeze naming a different oracle is refused: scope can never
   // silently swing to an unrelated debt tap.
   pair_freeze_operation bad;
   bad.freezer = alice_id;
   bad.vault   = vid;
   bad.oracle  = o2;
   signed_transaction btx; btx.operations.push_back( bad );
   db.current_fee_schedule().set_fee( btx.operations.back() );
   set_expiration( db, btx );
   btx.sign( alice_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, btx ), fc::exception );
   BOOST_CHECK_EQUAL( o2( db ).options.frozen, false );

    // Re-freezing the bound pair is still accepted (idempotent, atomic);
    // at zero debt it still binds-without-closing.
    // New block first: the identical freeze in the same block is the identical
    // transaction and is refused as a duplicate, not as economics.
    generate_block();
    h2e_freeze( *this, alice_id, alice_private_key, vid, o1 );
   BOOST_CHECK_EQUAL( vid( db ).frozen, false );
   BOOST_CHECK_EQUAL( o1( db ).options.frozen, false );
} FC_LOG_AND_RETHROW() }

/// H1 pairs excluded from H2 medians: pools on vault-less pairs never sample,
/// and an unbound vault's windows never evaluate (no feed, no halt).
BOOST_AUTO_TEST_CASE( h1_pairs_excluded_from_h2_medians )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(sam) );
   fund( alice, asset( 30000000000000LL ) );
   fund( sam, asset( 6000000000000LL ) );
   h2e_make_committee_member( *this, alice );

    // Vault-less pair NOPAIR: heavy pool flow must create no H2 state at all.
    const asset_id_type nopair = h2e_create_uia( *this, alice_id, alice_private_key, "NOPAIR" );
    const asset_id_type noshare = h2e_create_uia( *this, sam_id, sam_private_key, "NOSHARE" );
    // Pool IDs, never references: references dangle across block production.
    const liquidity_pool_id_type npool_id = create_liquidity_pool(
          sam_id, asset_id_type(), nopair, noshare, 0, 0 ).get_id();
    issue_uia( sam, asset( 20000000000LL, nopair ) );
    deposit_to_liquidity_pool( sam_id, npool_id,
                               asset( 1000000000000LL ), asset( 10000000000LL, nopair ) );
    for( int i = 0; i < 4; ++i )
       exchange_with_liquidity_pool( sam_id, npool_id,
                                     asset( 500000000LL, nopair ), asset( 1, asset_id_type() ) );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_CHECK( h2e_find_tripwire( *this, nopair ) == nullptr );

   // Bound-less vault on pair LONE: samples record (H2 membership by vault),
   // but with no bound oracle there is no feed leg, so windows fill and the
   // stage never moves across three maintenances.
   const asset_id_type lone = h2e_create_uia( *this, alice_id, alice_private_key, "LONE" );
   // ISS-R14-16: the issuer-direct print must sit before the vault exists --
   // the issuer-direct gate is inert on a vault-less pair, and the sampling
   // subject (a bound-less vault over three maintenances) is unaffected.
   // The shared trx was stamped at test start; re-stamp at the current head
   // (post-maintenance-jump) or the push fails the expiration check.
   set_expiration( db, trx );
   issue_uia( sam, asset( 2000000000LL, lone ) ); // pilot-scale (AC-02): ÷10, cap-inclusive
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type lvid = h2e_register_vault(
         *this, alice_id, alice_private_key, vault_auth,
         H2E_VAULT_RAW, H2E_VAULT_USD_CENTS, lone );
     const asset_id_type lshare = h2e_create_uia( *this, sam_id, sam_private_key, "LSHARE" );
     const liquidity_pool_id_type lpool_id = create_liquidity_pool(
           sam_id, asset_id_type(), lone, lshare, 0, 0 ).get_id();
    deposit_to_liquidity_pool( sam_id, lpool_id,
                               asset( 10000000000LL ), asset( 100000000LL, lone ) ); // ÷10 pilot-scale
    for( int w = 0; w < 3; ++w )
    {
       for( int i = 0; i < 2; ++i )
          exchange_with_liquidity_pool( sam_id, lpool_id,
                                        asset( 50000000LL, lone ), asset( 1, asset_id_type() ) ); // ÷10 pilot-scale
      generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
      generate_block();
   }
   const tripwire_state_object* lone_tw = h2e_find_tripwire( *this, lone );
   BOOST_REQUIRE( lone_tw != nullptr );
   BOOST_CHECK( lone_tw->win_new.total_volume > 0 || lone_tw->win_old.total_volume > 0 );
   BOOST_CHECK_EQUAL( lone_tw->halt_stage, 0u );
   BOOST_CHECK_EQUAL( lvid( db ).frozen, false );
} FC_LOG_AND_RETHROW() }

/// Tripwire halt ladder on crafted dislocation: aligned windows stay clean;
/// a 100% market-vs-feed dislocation trips door, then debt, then redemptions
/// across consecutive breached windows; two clean windows reopen everything.
BOOST_AUTO_TEST_CASE( tripwire_halt_ladder_on_crafted_dislocation_then_reopens )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(sam) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( sam, asset( 4000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   // Pair P with a bonded vault and a bonded producer on its oracle.
   const asset_id_type pairp = h2e_create_uia( *this, alice_id, alice_private_key, "TRIP" );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2e_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2E_VAULT_RAW, H2E_VAULT_USD_CENTS,
         pairp );
   const auto vest = h2e_make_cdd_vesting( *this, alice_id, alice_private_key, H2E_VAULT_RAW );
   h2e_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2E_VAULT_RAW,
                        H2E_VAULT_USD_CENTS );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "TRIP.USD", bts_ref, usd_ref, opts );
   const auto vb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, oid, vb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   // Canonical binding pinned, then unfrozen for the test (binding persists).
   h2e_freeze( *this, alice_id, alice_private_key, vid, oid );
   generate_block();
   db.modify( vid( db ), []( vault_object& v ) { v.frozen = false; } );
   db.modify( oid( db ), []( oracle_object& o ) { o.options.frozen = false; } );

    // Two pools on the pair at exactly 100 CORE per P, zero fees everywhere.
    // Object references dangle across block production (the pending session is
    // rebuilt from pushed transactions, destroying and recreating objects), so
    // only the pool IDs are held: IDs are stable, references are not.
    const asset_id_type s1 = h2e_create_uia( *this, sam_id, sam_private_key, "TRS1" );
    const asset_id_type s2 = h2e_create_uia( *this, sam_id, sam_private_key, "TRS2" );
    const liquidity_pool_id_type pool1_id = create_liquidity_pool(
          sam_id, asset_id_type(), pairp, s1, 0, 0 ).get_id();
    const liquidity_pool_id_type pool2_id = create_liquidity_pool(
          sam_id, asset_id_type(), pairp, s2, 0, 0 ).get_id();
    h2e_grant_seasoning( *this, pairp ); // ISS-R14-16: season the bound pair before the print
   issue_uia( sam, asset( 1200000000LL, pairp ) ); // pilot-scale (AC-02): ÷20 pools, drift <2%
    deposit_to_liquidity_pool( sam_id, pool1_id,
                               asset( 50000000000LL ), asset( 500000000LL, pairp ) );
    deposit_to_liquidity_pool( sam_id, pool2_id,
                               asset( 50000000000LL ), asset( 500000000LL, pairp ) );

    auto trade_both = [&]( int64_t sell_p, int64_t tweak )
    {
       exchange_with_liquidity_pool( sam_id, pool1_id,
                                     asset( sell_p + tweak, pairp ),
                                     asset( 1, asset_id_type() ) );
       exchange_with_liquidity_pool( sam_id, pool2_id,
                                     asset( sell_p - tweak, pairp ),
                                     asset( 1, asset_id_type() ) );
    };
   auto pass_window = [&]()
   {
      generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
      generate_block();
   };

   // Window 1: feed 100, market ~100. First sweep only fills the older slot.
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   trade_both( 1000000, 1 );
   pass_window();
   const tripwire_state_object* tw1 = h2e_find_tripwire( *this, pairp );
   BOOST_REQUIRE( tw1 != nullptr );
   BOOST_CHECK_EQUAL( tw1->halt_stage, 0u );
   // Source disclosure: both pools contributed samples.
   {
      flat_set<liquidity_pool_id_type> sources;
      for( const auto& s : tw1->win_old.samples ) sources.insert( s.source_pool );
      for( const auto& s : tw1->win_new.samples ) sources.insert( s.source_pool );
      BOOST_CHECK_EQUAL( sources.size(), 2u );
   }

   // Window 2: still aligned -> first evaluation is clean (streak 1, no halt).
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   trade_both( 1000000, 3 );
   pass_window();
   BOOST_CHECK_EQUAL( h2e_find_tripwire( *this, pairp )->halt_stage, 0u );
   BOOST_CHECK_EQUAL( h2e_find_tripwire( *this, pairp )->clean_streak, 1u );

    // Window 3: both pools shift to 200 (withdraw + redeposit at the new ratio);
    // heavy flow at ~199 vs feed 100 -> breach -> DOOR+DEBT halt ATOMICALLY
    // (X-05: first breach jumps past DEBT, so no block observes
    // door-closed/debt-open). Pool objects are re-fetched by ID: no reference
    // survives block production.
    for( const liquidity_pool_id_type pid : { pool1_id, pool2_id } )
    {
       const liquidity_pool_object& pool = pid( db );
       const share_type shares = db.get_balance( sam_id, pool.share_asset ).amount;
       withdraw_from_liquidity_pool( sam_id, pid, asset( shares, pool.share_asset ) );
       deposit_to_liquidity_pool( sam_id, pid,
                                  asset( 100000000000LL ), asset( 500000000LL, pairp ) );
    }
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   trade_both( 1000000, 5 );
   pass_window();
   const tripwire_state_object* tw3 = h2e_find_tripwire( *this, pairp );
   BOOST_REQUIRE( tw3 != nullptr );
   // X-05 atomicity: first breach lands at DEBT (door AND debt together),
   // never DOOR alone.
   BOOST_CHECK_EQUAL( tw3->halt_stage, GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   BOOST_CHECK_EQUAL( vid( db ).tripwire_door_hold, true );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );
   BOOST_CHECK_EQUAL( tw3->clean_streak, 0u );
    // The median sits inside the dislocated window's sample range (selection,
    // never an average): every window-3 sample prices far above the feed.
    // (Post-sweep the evaluated newer window has rotated into win_old.)
    for( const auto& s : tw3->win_old.samples )
       BOOST_CHECK( s.price.base_amount.value > s.price.quote_amount.value * 150 );

   // Window 4: dislocation persists -> REDEMPTIONS halt last (only lagging rung).
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   trade_both( 1000000, 7 );
   pass_window();
   const tripwire_state_object* tw4 = h2e_find_tripwire( *this, pairp );
   BOOST_CHECK_EQUAL( tw4->halt_stage,
                      GRAPHENE_H2E_TRIPWIRE_STAGE_REDEMPTIONS );
   BOOST_CHECK_EQUAL( tw4->redemptions_halted, true );
   BOOST_CHECK( h2_redemptions_halted( db, pairp ) );

   // Windows 5-6: the feed tells the truth again (tracks pool marginals, so
    // restoration is exact by construction) -> two clean windows reopen.
    // Binding convention is bond-per-pair: (balance_a, balance_b) with the
    // core leg first, matching the market samples' (bond, pair) orientation.
    for( int w = 0; w < 2; ++w )
    {
        const liquidity_pool_object& p1 = pool1_id( db );
       h2e_publish( *this, oid, bob_id, bob_private_key,
                    p1.balance_a.value, p1.balance_b.value );
      trade_both( 1000000, 11 + w );
      pass_window();
   }
   const tripwire_state_object* tw7 = h2e_find_tripwire( *this, pairp );
   BOOST_CHECK_EQUAL( tw7->halt_stage, 0u );
   BOOST_CHECK_EQUAL( tw7->redemptions_halted, false );
   BOOST_CHECK_EQUAL( vid( db ).tripwire_door_hold, false );
   BOOST_CHECK_EQUAL( vid( db ).frozen, false );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, false );
   // Window storage stays bounded across the whole run.
   BOOST_CHECK( tw7->win_old.samples.size() <= GRAPHENE_H2E_TRIPWIRE_MAX_SAMPLES );
   BOOST_CHECK( tw7->win_new.samples.size() <= GRAPHENE_H2E_TRIPWIRE_MAX_SAMPLES );
} FC_LOG_AND_RETHROW() }

/// Redemptions gate: while a pair's tripwire holds redemptions shut,
/// wind-down claims for that pair are refused; clearing reopens them.
BOOST_AUTO_TEST_CASE( tripwire_redemptions_hold_freezes_claims_until_cleared )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(sam) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( sam, asset( 4000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   const asset_id_type pairq = h2e_create_uia( *this, alice_id, alice_private_key, "HOLD" );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2e_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2E_VAULT_RAW, H2E_VAULT_USD_CENTS,
         pairq );
   const auto vest = h2e_make_cdd_vesting( *this, alice_id, alice_private_key, H2E_VAULT_RAW );
   h2e_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2E_VAULT_RAW,
                        H2E_VAULT_USD_CENTS );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "HOLD.USD", bts_ref, usd_ref, opts );
   const auto vb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, oid, vb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   h2e_freeze( *this, alice_id, alice_private_key, vid, oid );
   generate_block();
   db.modify( vid( db ), []( vault_object& v ) { v.frozen = false; } );
   db.modify( oid( db ), []( oracle_object& o ) { o.options.frozen = false; } );

    // One pool trade creates the tripwire state for the pair (real path).
    const asset_id_type sq = h2e_create_uia( *this, sam_id, sam_private_key, "HSHARE" );
    const liquidity_pool_id_type pool_id = create_liquidity_pool(
          sam_id, asset_id_type(), pairq, sq, 0, 0 ).get_id();
    h2e_grant_seasoning( *this, pairq ); // ISS-R14-16: season the bound pair before the print
    issue_uia( sam, asset( 2000000000LL, pairq ) ); // pilot-scale (AC-02): ÷10, cap-inclusive
    deposit_to_liquidity_pool( sam_id, pool_id,
                               asset( 10000000000LL ), asset( 100000000LL, pairq ) ); // ÷10 pilot-scale
    h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
    exchange_with_liquidity_pool( sam_id, pool_id,
                                   asset( 50000000LL, pairq ), asset( 1, asset_id_type() ) ); // ÷10 pilot-scale
   BOOST_REQUIRE( h2e_find_tripwire( *this, pairq ) != nullptr );

    // The hold itself is set through the object's own latch (the ladder case
    // proves stage 3 sets it behaviorally; here the gate is under test).
    // New block first: pending pushes leave the undo session open and a direct
    // modify into it would be rolled back by the next block.
    generate_block();
    db.modify( *h2e_find_tripwire( *this, pairq ),
               []( tripwire_state_object& t ) { t.redemptions_halted = true; } );
   BOOST_CHECK( h2_redemptions_halted( db, pairq ) );

   // Wind the vault down (100% coverage breach -> top-up -> expiry).
   generate_block();
   h2e_set_outstanding( *this, vid, H2E_VAULT_RAW );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_REQUIRE_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_TOPUP );
   generate_blocks( vid( db ).top_up_deadline + 2 * 86400 );
   generate_block();
   BOOST_REQUIRE_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_WINDDOWN );
   const winddown_vault_id_type wdid {
      db.get_index_type<winddown_vault_index>().indices().begin()->id };

   // Held shut: the claim is refused even with a live price leg ...
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   winddown_claim_operation hop;
   hop.claimant     = carol_id;
   hop.winddown     = wdid;
   hop.claim_amount = share_type( 1000000 );
   hop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction htx; htx.operations.push_back( hop );
   db.current_fee_schedule().set_fee( htx.operations.back() );
   set_expiration( db, htx );
   htx.sign( carol_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, htx ), fc::exception );

    // ... clearing the hold reopens the same claim at converted math.
    // New block first: the refused claim above leaves the pending undo session
    // open (same rollback hazard as the latch above).
    generate_block();
     db.modify( *h2e_find_tripwire( *this, pairq ),
                []( tripwire_state_object& t ) { t.redemptions_halted = false; } );
    // R11-R1 entitlement: carol's senior face comes from sam's pool-side
    // holdings (pairq supply already sits AT the pilot cap, so no new
    // issuance could fund her; a transfer moves existing face instead).
    transfer_operation xfer;
    xfer.from   = sam_id;
    xfer.to     = carol_id;
    xfer.amount = asset( share_type( 1000000 ), pairq );
    signed_transaction xtx; xtx.operations.push_back( xfer );
    db.current_fee_schedule().set_fee( xtx.operations.back() );
    set_expiration( db, xtx );
    xtx.sign( sam_private_key, db.get_chain_id() );
    PUSH_TX( db, xtx );
    const share_type carol_before = db.get_balance( carol_id, asset_id_type() ).amount;
   signed_transaction htx2; htx2.operations.push_back( hop );
   db.current_fee_schedule().set_fee( htx2.operations.back() );
   set_expiration( db, htx2 );
   htx2.sign( carol_private_key, db.get_chain_id() );
   PUSH_TX( db, htx2 );
   // Price-invariant converted payout (share leg verbatim: face x
   // segregated / total); the hold clear reopens the same 1000000 claim.
   BOOST_CHECK( db.get_balance( carol_id, asset_id_type() ).amount
                == carol_before + share_type( 1000000 ) );
} FC_LOG_AND_RETHROW() }

/// X-01 adversarial: a live H1-style oracle (quorum-live consumed value, no
/// producer bonds) yields NO H2 price. Reads fail closed, the tripwire feed
/// leg pauses, and conversion-dependent debt (wind-down claims) is blocked.
/// If existing tests read without bonds, THOSE TESTS post bonds (matching
/// production reality) — the gate is never weakened for green suites.
BOOST_AUTO_TEST_CASE( unbonded_oracle_reads_fail_closed_and_block_debt )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   // Live but never bonded: single producer, no bond locks anywhere.
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "NOBOND.USD", bts_ref, usd_ref, opts );
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   // H1 liveness holds (consumed tracks raw, quorum met)...
   BOOST_REQUIRE( oid( db ).consumed_value.valid() );
   // ...but H2 reads fail closed without a bonded live set.
   BOOST_CHECK( !h2_read_consumed_price( db, oid, 0, db.head_block_time() ).valid() );

   // Bound vault on a plain UIA: pin the canonical binding, then unfreeze for
   // the test (binding persists; the freeze was the pin).
   const asset_id_type pairu = h2e_create_uia( *this, alice_id, alice_private_key, "NOBOND" );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2e_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2E_VAULT_RAW, H2E_VAULT_USD_CENTS,
         pairu );
   const auto vest = h2e_make_cdd_vesting( *this, alice_id, alice_private_key, H2E_VAULT_RAW );
   h2e_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2E_VAULT_RAW,
                        H2E_VAULT_USD_CENTS );
   h2e_freeze( *this, alice_id, alice_private_key, vid, oid );
   BOOST_REQUIRE( vid( db ).bound_oracle.valid() );
   generate_block();
   db.modify( vid( db ), []( vault_object& v ) { v.frozen = false; } );
   db.modify( oid( db ), []( oracle_object& o ) { o.options.frozen = false; } );

   // Pair read also fails closed (primary unbonded, no fallback).
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   BOOST_CHECK( !h2_read_pair_price( db, vid( db ), 0, db.head_block_time() ).valid() );

   // Breach -> top-up -> wind-down, then a fresh live publish (still unbonded).
   generate_block();
   h2e_set_outstanding( *this, vid, H2E_VAULT_RAW );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   BOOST_REQUIRE_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_TOPUP );
   generate_blocks( vid( db ).top_up_deadline + 2 * 86400 );
   generate_block();
   BOOST_REQUIRE_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_WINDDOWN );
   const winddown_vault_id_type wdid {
      db.get_index_type<winddown_vault_index>().indices().begin()->id };
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   BOOST_REQUIRE( oid( db ).consumed_value.valid() );
   BOOST_CHECK( !h2_read_pair_price( db, vid( db ), 0, db.head_block_time() ).valid() );

   // Debt blocked: conversion-dependent claims halt on dual-stale/unbonded.
   winddown_claim_operation cop;
   cop.claimant     = carol_id;
   cop.winddown     = wdid;
   cop.claim_amount = share_type( 1000000 );
   cop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction ctx; ctx.operations.push_back( cop );
   db.current_fee_schedule().set_fee( ctx.operations.back() );
   set_expiration( db, ctx );
   ctx.sign( carol_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, ctx ), fc::exception );
} FC_LOG_AND_RETHROW() }

/// X-03 H2-side merge-contract half: every sweep records h2_diversion_bps
/// (the oracle-leg share) on the shared 10000-bps denominator inside the
/// 7000bps joint ceiling. G1 reads this field at merge time; no cross-branch
/// writes here.
BOOST_AUTO_TEST_CASE( h2_diversion_bps_recorded_within_joint_cap )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "DIV.USD", bts_ref, usd_ref, opts );
   const auto vb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, oid, vb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   // Shell advertises a valid half at creation...
   BOOST_REQUIRE( h2e_find_pool( *this, oid ) != nullptr );
   BOOST_CHECK_EQUAL( h2e_find_pool( *this, oid )->h2_diversion_bps,
                      GRAPHENE_H2E_REWARD_ORACLE_BPS );
   BOOST_CHECK( h2e_find_pool( *this, oid )->h2_diversion_bps
                <= GRAPHENE_H2E_FEE_DIVERSION_CAP_BPS );
   // ...and every sweep re-records it inside the cap with a valid triple.
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();
   const reward_pool_object* pool = h2e_find_pool( *this, oid );
   BOOST_REQUIRE( pool != nullptr );
   BOOST_CHECK_EQUAL( pool->h2_diversion_bps, pool->routing_oracle_bps );
   BOOST_CHECK( pool->h2_diversion_bps <= GRAPHENE_H2E_FEE_DIVERSION_CAP_BPS );
   BOOST_CHECK( h2_routing_valid( pool->routing_oracle_bps, pool->routing_vault_bps,
                                  pool->routing_reserve_bps,
                                  GRAPHENE_H2E_FEE_DIVERSION_CAP_BPS ) );
} FC_LOG_AND_RETHROW() }

/// X-05 + V-07 coincident both-legs breach (BSIP acceptance vector): vault
/// coverage <150% AND tripwire deviation breach in ONE maintenance window.
/// Asserts: no block observes door-closed/debt-open (atomic DEBT on first
/// breach), redemptions_hold freezes claims, seniors-first wind-down follows.
BOOST_AUTO_TEST_CASE( coincident_vault_and_tripwire_breach_halts_atomically )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(sam) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( sam, asset( 4000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   // Pair COIN with a bonded vault and a bonded producer on its oracle.
   const asset_id_type pairc = h2e_create_uia( *this, alice_id, alice_private_key, "COIN" );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2e_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2E_VAULT_RAW, H2E_VAULT_USD_CENTS,
         pairc );
   const auto vest = h2e_make_cdd_vesting( *this, alice_id, alice_private_key, H2E_VAULT_RAW );
   h2e_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2E_VAULT_RAW,
                        H2E_VAULT_USD_CENTS );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "COIN.USD", bts_ref, usd_ref, opts );
   const auto vb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, oid, vb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   h2e_freeze( *this, alice_id, alice_private_key, vid, oid );
   generate_block();
   db.modify( vid( db ), []( vault_object& v ) { v.frozen = false; } );
   db.modify( oid( db ), []( oracle_object& o ) { o.options.frozen = false; } );

   // Two pools at 100 CORE per COIN, zero fees (ladder pattern).
   const asset_id_type s1 = h2e_create_uia( *this, sam_id, sam_private_key, "COS1" );
   const asset_id_type s2 = h2e_create_uia( *this, sam_id, sam_private_key, "COS2" );
   const liquidity_pool_id_type pool1_id = create_liquidity_pool(
         sam_id, asset_id_type(), pairc, s1, 0, 0 ).get_id();
   const liquidity_pool_id_type pool2_id = create_liquidity_pool(
         sam_id, asset_id_type(), pairc, s2, 0, 0 ).get_id();
   h2e_grant_seasoning( *this, pairc ); // ISS-R14-16: season the bound pair before the print
   issue_uia( sam, asset( 1200000000LL, pairc ) ); // pilot-scale (AC-02): ÷20 pools, drift <2%
   deposit_to_liquidity_pool( sam_id, pool1_id,
                              asset( 50000000000LL ), asset( 500000000LL, pairc ) );
   deposit_to_liquidity_pool( sam_id, pool2_id,
                              asset( 50000000000LL ), asset( 500000000LL, pairc ) );
   auto trade_both = [&]( int64_t sell_p, int64_t tweak )
   {
      exchange_with_liquidity_pool( sam_id, pool1_id,
                                    asset( sell_p + tweak, pairc ),
                                    asset( 1, asset_id_type() ) );
      exchange_with_liquidity_pool( sam_id, pool2_id,
                                    asset( sell_p - tweak, pairc ),
                                    asset( 1, asset_id_type() ) );
   };
   auto pass_window = [&]()
   {
      generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
      generate_block();
   };

   // Windows 1-2: aligned (feed 100, market ~100) to fill both windows clean.
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   trade_both( 1000000, 1 );
   pass_window();
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   trade_both( 1000000, 3 );
   pass_window();
   BOOST_REQUIRE_EQUAL( h2e_find_tripwire( *this, pairc )->halt_stage, 0u );

   // COINCIDENT window 3: vault coverage breach (100% < 150%) AND tripwire
   // dislocation (pools to 200, feed stays 100) in the SAME window.
   generate_block();
   h2e_set_outstanding( *this, vid, H2E_VAULT_RAW );
   for( const liquidity_pool_id_type pid : { pool1_id, pool2_id } )
   {
      const liquidity_pool_object& pool = pid( db );
      const share_type shares = db.get_balance( sam_id, pool.share_asset ).amount;
      withdraw_from_liquidity_pool( sam_id, pid, asset( shares, pool.share_asset ) );
      deposit_to_liquidity_pool( sam_id, pid,
                                 asset( 100000000000LL ), asset( 500000000LL, pairc ) );
   }
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   trade_both( 1000000, 5 );
   pass_window();

   // Atomicity: ONE sweep applied door AND debt together. No block observed
   // door-closed/debt-open: after the single sweep both flags are set and the
   // stage is past DEBT (never DOOR alone).
   const tripwire_state_object* tw3 = h2e_find_tripwire( *this, pairc );
   BOOST_REQUIRE( tw3 != nullptr );
   BOOST_CHECK_EQUAL( tw3->halt_stage, GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   BOOST_CHECK_EQUAL( vid( db ).tripwire_door_hold, true );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );
   // Vault leg breached in the same window: TOPUP with mint halt.
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_TOPUP );

   // Window 4: dislocation persists -> REDEMPTIONS (only lagging rung).
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   trade_both( 1000000, 7 );
   pass_window();
   const tripwire_state_object* tw4 = h2e_find_tripwire( *this, pairc );
   BOOST_REQUIRE( tw4 != nullptr );
   BOOST_CHECK_EQUAL( tw4->halt_stage, GRAPHENE_H2E_TRIPWIRE_STAGE_REDEMPTIONS );
   BOOST_CHECK_EQUAL( tw4->redemptions_halted, true );
   BOOST_CHECK( h2_redemptions_halted( db, pairc ) );

   // Wind-down follows the coverage breach: past the 36h top-up deadline.
   generate_blocks( vid( db ).top_up_deadline + 2 * 86400 );
   generate_block();
   BOOST_REQUIRE_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_WINDDOWN );
   const winddown_vault_id_type wdid {
      db.get_index_type<winddown_vault_index>().indices().begin()->id };

   // Redemptions hold freezes claims: live bonded price, but the latch holds.
   // White-box isolation: the tripwire froze the debt tap (oracle frozen)
   // along with the latch; unfreeze the tap so the price leg is live again
   // while redemptions_halted persists, proving the hold ALONE freezes
   // claims. The fresh publish needs the guard delay to promote to consumed
   // (H1 rule), so advance past it: the refusal below must be the hold
   // latch, never a stale price.
   generate_block();
   db.modify( oid( db ), []( oracle_object& o ) { o.options.frozen = false; } );
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   generate_blocks( db.head_block_time() + 2
                    * db.get_global_properties().parameters.get_oracle_guard_delay_sec() );
   generate_block();
   BOOST_REQUIRE( h2_read_pair_price( db, vid( db ), 0, db.head_block_time() ).valid() );
   winddown_claim_operation hop;
   hop.claimant     = carol_id;
   hop.winddown     = wdid;
   hop.claim_amount = share_type( 1000000 );
   hop.tranche      = GRAPHENE_H2_WINDDOWN_SENIOR;
   signed_transaction htx; htx.operations.push_back( hop );
   db.current_fee_schedule().set_fee( htx.operations.back() );
   set_expiration( db, htx );
   htx.sign( carol_private_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, htx ), fc::exception );

   // Clear the hold through clean windows (feed tracks pool marginals),
   // then seniors-first wind-down proceeds at converted math. The wind-down
   // gap's paused sweeps rotated the ring to empty, so three truthful
   // windows are needed: the first refills (pause), the next two build the
   // reopen streak.
   for( int w = 0; w < 3; ++w )
   {
      const liquidity_pool_object& p1 = pool1_id( db );
      h2e_publish( *this, oid, bob_id, bob_private_key,
                   p1.balance_a.value, p1.balance_b.value );
      trade_both( 1000000, 11 + w );
      pass_window();
   }
   BOOST_REQUIRE_EQUAL( h2e_find_tripwire( *this, pairc )->halt_stage, 0u );
   // Fresh price leg for the claim itself: the loop's last publish is a full
   // window old (dual-stale at claim time), so republish like the
   // redemptions-hold precedent does before claiming.
    h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
    generate_block();
    // R11-R1 entitlement: carol's senior face must exist before she claims.
    h2e_issue_pair_face( *this, alice_id, alice_private_key, carol_id,
                         pairc, share_type( 1000000 ) );
    const share_type carol_before = db.get_balance( carol_id, asset_id_type() ).amount;
   signed_transaction htx2; htx2.operations.push_back( hop );
   db.current_fee_schedule().set_fee( htx2.operations.back() );
   set_expiration( db, htx2 );
   htx2.sign( carol_private_key, db.get_chain_id() );
   PUSH_TX( db, htx2 );
   BOOST_CHECK( db.get_balance( carol_id, asset_id_type() ).amount
                == carol_before + share_type( 1000000 ) );
} FC_LOG_AND_RETHROW() }

/// R3-01: tripwire reopen never clears a guilty oracle; committee unfreeze
/// refuses while the deviation ladder holds the pair (documented coherence
/// choice: refuse, never split oracle-live/door-shut), then clears after the
/// wire reopens. Two producers — bob accused and sustained, carol bonded and
/// live — so the feed leg survives the sustain slash and clean windows can
/// actually evaluate.
BOOST_AUTO_TEST_CASE( tripwire_reopen_keeps_sustained_oracle_frozen_then_committee_clears )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(sam) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( sam, asset( 4000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   const asset_id_type pairp = h2e_create_uia( *this, alice_id, alice_private_key, "R301" );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2e_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2E_VAULT_RAW, H2E_VAULT_USD_CENTS,
         pairp );
   const auto vest = h2e_make_cdd_vesting( *this, alice_id, alice_private_key, H2E_VAULT_RAW );
   h2e_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2E_VAULT_RAW,
                        H2E_VAULT_USD_CENTS );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "R301.USD", bts_ref, usd_ref, opts );
   const auto vbb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, oid, vbb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   const auto vbc = h2e_make_cdd_vesting( *this, carol_id, carol_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, carol_id, carol_private_key, oid, vbc, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   // Canonical binding pinned, then unfrozen for the test (binding persists).
   h2e_freeze( *this, alice_id, alice_private_key, vid, oid );
   generate_block();
   db.modify( vid( db ), []( vault_object& v ) { v.frozen = false; } );
   db.modify( oid( db ), []( oracle_object& o ) { o.options.frozen = false; } );

   const asset_id_type s1 = h2e_create_uia( *this, sam_id, sam_private_key, "R3S1" );
   const asset_id_type s2 = h2e_create_uia( *this, sam_id, sam_private_key, "R3S2" );
   const liquidity_pool_id_type pool1_id = create_liquidity_pool(
         sam_id, asset_id_type(), pairp, s1, 0, 0 ).get_id();
   const liquidity_pool_id_type pool2_id = create_liquidity_pool(
         sam_id, asset_id_type(), pairp, s2, 0, 0 ).get_id();
   h2e_grant_seasoning( *this, pairp ); // ISS-R14-16: season the bound pair before the print
   issue_uia( sam, asset( 1200000000LL, pairp ) ); // pilot-scale (AC-02): ÷20 pools, drift <2%
   deposit_to_liquidity_pool( sam_id, pool1_id,
                              asset( 50000000000LL ), asset( 500000000LL, pairp ) );
   deposit_to_liquidity_pool( sam_id, pool2_id,
                              asset( 50000000000LL ), asset( 500000000LL, pairp ) );
   auto trade_both = [&]( int64_t sell_p, int64_t tweak )
   {
      exchange_with_liquidity_pool( sam_id, pool1_id,
                                    asset( sell_p + tweak, pairp ),
                                    asset( 1, asset_id_type() ) );
      exchange_with_liquidity_pool( sam_id, pool2_id,
                                    asset( sell_p - tweak, pairp ),
                                    asset( 1, asset_id_type() ) );
   };
   auto pass_window = [&]()
   {
      generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
      generate_block();
   };

   // Accused print, then sustain: guilty freeze with zero open disputes.
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   h2e_publish( *this, oid, carol_id, carol_private_key, 100, 1 );
   const fc::time_point_sec accused = oid( db ).history.back().first;
   const oracle_dispute_id_type did = h2e_post_dispute(
         *this, sam_id, sam_private_key, oid, bob_id, accused, 0,
         h2e_evidence( "r301-sustain" ) );
   h2e_sustain_from_genesis( *this, object_id_type( did ) );
   BOOST_REQUIRE_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_SUSTAINED );
   BOOST_REQUIRE_EQUAL( oid( db ).options.frozen, true );
   BOOST_REQUIRE_EQUAL( oid( db ).open_disputes, 0u );
   // Fresh block before the window phase: identical republish txs in one
   // block would trip duplicate_transaction, never the gate under test.
   generate_block();

   // GOV-R9-02: the committee unfreeze now waits 14 days from this clear.
   // Chain time only -- carol keeps a daily publish so her producer bond
   // stays ahead of its 7-day unlock (publish-advanced; a lapsed bond drops
   // the pair out of the bonded live set and the wire pauses forever).
   // No trades though: the wire has no samples, so every sweep pauses and
   // the stage holds at NONE. The refusal pinned below must therefore still
   // trip the deviation ladder (windows 1-2 run after this wait), never the
   // clock.
   const fc::time_point_sec cleared = db.head_block_time();
   const fc::time_point_sec wait_end = cleared + GRAPHENE_ORACLE_UNFREEZE_DELAY_SEC + 60;
   while( db.head_block_time() < wait_end )
   {
      h2e_publish( *this, oid, carol_id, carol_private_key, 100, 1 );
      generate_blocks( db.head_block_time() + 86400 );
   }
   generate_block();
   set_expiration( db, trx );

   // Window 1: aligned market on the surviving carol feed — clean, no halt,
   // and the guilty freeze is untouched by the clean wire.
   h2e_publish( *this, oid, carol_id, carol_private_key, 100, 1 );
   trade_both( 1000000, 1 );
   pass_window();
   BOOST_CHECK_EQUAL( h2e_find_tripwire( *this, pairp )->halt_stage, 0u );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );

   // Window 2: dislocate to 200 vs feed 100 -> breach -> DEBT halt.
   for( const liquidity_pool_id_type pid : { pool1_id, pool2_id } )
   {
      const liquidity_pool_object& pool = pid( db );
      const share_type shares = db.get_balance( sam_id, pool.share_asset ).amount;
      withdraw_from_liquidity_pool( sam_id, pid, asset( shares, pool.share_asset ) );
      deposit_to_liquidity_pool( sam_id, pid,
                                 asset( 100000000000LL ), asset( 500000000LL, pairp ) );
   }
   h2e_publish( *this, oid, carol_id, carol_private_key, 100, 1 );
   trade_both( 1000000, 5 );
   pass_window();
   BOOST_REQUIRE_EQUAL( h2e_find_tripwire( *this, pairp )->halt_stage,
                        GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT );
   BOOST_REQUIRE_EQUAL( vid( db ).tripwire_door_hold, true );

   // Committee unfreeze REFUSED while the ladder holds the pair (coherence:
   // refuse, never split oracle-live/door-shut).
   try {
      h2e_committee_unfreeze( *this, alice_id, alice_private_key, oid );
      BOOST_FAIL( "committee unfreeze cleared a tripwire-held oracle" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK( e.to_detail_string().find( "tripwire" ) != std::string::npos );
   }
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );
   // Owner path stays refused on the guilty history (R-02 pin, unchanged).
   BOOST_CHECK_THROW( h2e_owner_set_frozen( *this, alice_id, alice_private_key, oid, false ),
                      fc::exception );

   // Windows 3-4: the feed tells the truth again (tracks pool marginals, so
   // restoration is exact by construction — the ladder-test pattern) -> two
   // clean windows reopen the STAGE while the GUILTY oracle stays frozen:
   // the pre-R3-01 bypass (open_disputes == 0 alone) would have cleared it
   // here.
   for( int w = 0; w < 2; ++w )
   {
      const liquidity_pool_object& p1 = pool1_id( db );
      h2e_publish( *this, oid, carol_id, carol_private_key,
                   p1.balance_a.value, p1.balance_b.value );
      trade_both( 1000000, 21 + w );
      pass_window();
   }
   const tripwire_state_object* tw = h2e_find_tripwire( *this, pairp );
   BOOST_REQUIRE( tw != nullptr );
   BOOST_CHECK_EQUAL( tw->halt_stage, 0u );
   BOOST_CHECK_EQUAL( tw->redemptions_halted, false );
   BOOST_CHECK_EQUAL( vid( db ).tripwire_door_hold, false );
   BOOST_CHECK_EQUAL( vid( db ).frozen, false ); // healthy, no open challenges
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, true ); // R3-01: guilty stays

   // Window 5: a third clean window with no committee action changes nothing.
   {
      const liquidity_pool_object& p1 = pool1_id( db );
      h2e_publish( *this, oid, carol_id, carol_private_key,
                   p1.balance_a.value, p1.balance_b.value );
      trade_both( 1000000, 25 );
      pass_window();
   }
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );

   // Committee unfreeze clears now that the stage has cleared.
   h2e_committee_unfreeze( *this, alice_id, alice_private_key, oid );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, false );
} FC_LOG_AND_RETHROW() }

/// R3-01 owner-lockout pin: an EXONERATED past is not guilty history, so a
/// Track A owner freeze still clears through oracle_update (resolution-
/// scoped check, never whole-history; dispute objects persist but do not
/// permanently lock owners out).
BOOST_AUTO_TEST_CASE( exonerated_oracle_remains_owner_updatable )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 3000000000000LL ) );
   fund( carol, asset( 3000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "R301X.USD", bts_ref, usd_ref, opts );
   h2e_publish( *this, oid, carol_id, carol_private_key, 100, 1 );
   const fc::time_point_sec accused = oid( db ).history.back().first;

   const oracle_dispute_id_type did = h2e_post_dispute(
         *this, bob_id, bob_private_key, oid, carol_id, accused, 0,
         h2e_evidence( "r301-exonerate" ) );
   h2e_exonerate_from_genesis( *this, object_id_type( did ) );
   BOOST_REQUIRE_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_EXONERATED );
   BOOST_REQUIRE_EQUAL( oid( db ).open_disputes, 0u );
   BOOST_REQUIRE_EQUAL( oid( db ).options.frozen, false );

   // Track A owner freeze, then owner clear: allowed despite the terminal
   // EXONERATED history standing in the (never-erased) dispute index.
   h2e_owner_set_frozen( *this, alice_id, alice_private_key, oid, true );
   BOOST_REQUIRE_EQUAL( oid( db ).options.frozen, true );
   h2e_owner_set_frozen( *this, alice_id, alice_private_key, oid, false );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, false );

   // Owner policy control is intact too (producer-set update succeeds).
   {
      oracle_update_operation uop;
      uop.owner     = alice_id;
      uop.oracle_id = oid;
      oracle_options live = oid( db ).options;
      live.producers[bob_id] = oracle_producer_entry( 1 );
      uop.new_options = live;
      signed_transaction tx; tx.operations.push_back( uop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
      BOOST_CHECK( oid( db ).options.producers.find( bob_id )
                   != oid( db ).options.producers.end() );
   }
} FC_LOG_AND_RETHROW() }

/// R3-02 adversarial: a bonded live producer with weight 0 backs nothing —
/// the H2 gate fails closed on it. Production reality: oracle_options
/// validate refuses weight 0 at create AND update (oracle.cpp:146 — "remove
/// the producer instead"), so no consensus op can place such an entry; the
/// gate's weight>0 check is the second layer, pinned here by forcing the
/// state white-box (V-08 headroom precedent), never by weakening a gate.
BOOST_AUTO_TEST_CASE( weight_zero_bonded_producer_does_not_satisfy_gate )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   // First layer pins: weight 0 is refused at create (and update, same
   // validate), so the forced state below is unreachable by consensus ops.
   {
      oracle_options zero_opts;
      zero_opts.producers[bob_id] = oracle_producer_entry( 0 );
      oracle_create_operation cop;
      cop.owner   = alice_id;
      cop.name    = "R302Z.USD";
      cop.base    = bts_ref;
      cop.quote   = usd_ref;
      cop.series  = { oracle_series( oracle_series_kind::mid,
                                     oracle_series_rounding::unspecified ) };
      cop.options = zero_opts;
      signed_transaction tx;
      tx.operations.push_back( cop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( alice_private_key, db.get_chain_id() );
      BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
   }

   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "R302.USD", bts_ref, usd_ref, opts );
   const auto vb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, oid, vb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   // Control: bonded weight-1 live producer satisfies the H2 read.
   BOOST_REQUIRE( oid( db ).consumed_value.valid() );
   BOOST_REQUIRE( h2_read_consumed_price( db, oid, 0, db.head_block_time() ).valid() );

   // Adversarial state, forced white-box: the bonded live producer's weight
   // drops to 0 (same bond, same live submission, same producer entry).
   db.modify( oid( db ), [&]( oracle_object& o ) {
      o.options.producers[bob_id].weight = 0;
   } );
   // H1 liveness is untouched (aggregation already ran; weight is not
   // re-read until the next publish)...
   BOOST_REQUIRE( oid( db ).consumed_value.valid() );
   // ...but the H2 gate refuses: weight 0 backs nothing.
   BOOST_CHECK( !h2_read_consumed_price( db, oid, 0, db.head_block_time() ).valid() );

   // Restoring the weight restores the read (the refusal is the weight,
   // not the bond or the submission).
   db.modify( oid( db ), [&]( oracle_object& o ) {
      o.options.producers[bob_id].weight = 1;
   } );
   BOOST_CHECK( h2_read_consumed_price( db, oid, 0, db.head_block_time() ).valid() );
} FC_LOG_AND_RETHROW() }

/// X-06 H2-side joint-outcome pin (R4-05: honestly NOT a step-through
/// order proof): expiry -> vault top-up -> tripwire reopen, pinned through
/// joint outcomes (db_maint.cpp hook order: expiry, then vault, then
/// oracle/tripwire). Phase A: the vault sweep respects a tripwire door hold
/// it does not own (paused wire, healthy coverage: vault stays frozen); only
/// tripwire reopen clears it. Phase B: an expiry freeze lands before the
/// reopen read, so clean windows keep an expiry-frozen oracle frozen until
/// committee unfreeze. The same-sweep expiry-before-reopen race itself is
/// pinned by expiry_coincides_with_reopen_sweep_frozen_persists (deadlines
/// engineered inside the reopen sweep): the race is benign by double-gating
/// (open counters pre-expiry, guilty history post-expiry refuse the same
/// clears), so any hook order yields this identical joint outcome.
BOOST_AUTO_TEST_CASE( h2_maintenance_order_expiry_vault_tripwire_pinned )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(sam) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( sam, asset( 4000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   const asset_id_type pairp = h2e_create_uia( *this, alice_id, alice_private_key, "X06" );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2e_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2E_VAULT_RAW, H2E_VAULT_USD_CENTS,
         pairp );
   const auto vest = h2e_make_cdd_vesting( *this, alice_id, alice_private_key, H2E_VAULT_RAW );
   h2e_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2E_VAULT_RAW,
                        H2E_VAULT_USD_CENTS );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "X06.USD", bts_ref, usd_ref, opts );
   const auto vb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, oid, vb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   h2e_freeze( *this, alice_id, alice_private_key, vid, oid );
   generate_block();
   db.modify( vid( db ), []( vault_object& v ) { v.frozen = false; } );
   db.modify( oid( db ), []( oracle_object& o ) { o.options.frozen = false; } );

   const asset_id_type s1 = h2e_create_uia( *this, sam_id, sam_private_key, "X6S1" );
   const asset_id_type s2 = h2e_create_uia( *this, sam_id, sam_private_key, "X6S2" );
   const liquidity_pool_id_type pool1_id = create_liquidity_pool(
         sam_id, asset_id_type(), pairp, s1, 0, 0 ).get_id();
   const liquidity_pool_id_type pool2_id = create_liquidity_pool(
         sam_id, asset_id_type(), pairp, s2, 0, 0 ).get_id();
   h2e_grant_seasoning( *this, pairp ); // ISS-R14-16: season the bound pair before the print
   issue_uia( sam, asset( 1200000000LL, pairp ) ); // pilot-scale (AC-02): ÷20 pools, drift <2%
   deposit_to_liquidity_pool( sam_id, pool1_id,
                              asset( 50000000000LL ), asset( 500000000LL, pairp ) );
   deposit_to_liquidity_pool( sam_id, pool2_id,
                              asset( 50000000000LL ), asset( 500000000LL, pairp ) );
   auto trade_both = [&]( int64_t sell_p, int64_t tweak )
   {
      exchange_with_liquidity_pool( sam_id, pool1_id,
                                    asset( sell_p + tweak, pairp ),
                                    asset( 1, asset_id_type() ) );
      exchange_with_liquidity_pool( sam_id, pool2_id,
                                    asset( sell_p - tweak, pairp ),
                                    asset( 1, asset_id_type() ) );
   };
   auto pass_window = [&]()
   {
      generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
      generate_block();
   };

   // Phase A: halt at DEBT through dislocation (two windows: fill, then
   // breach on the combined median, mirroring the ladder test).
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   trade_both( 1000000, 1 );
   pass_window();
   for( const liquidity_pool_id_type pid : { pool1_id, pool2_id } )
   {
      const liquidity_pool_object& pool = pid( db );
      const share_type shares = db.get_balance( sam_id, pool.share_asset ).amount;
      withdraw_from_liquidity_pool( sam_id, pid, asset( shares, pool.share_asset ) );
      deposit_to_liquidity_pool( sam_id, pid,
                                 asset( 100000000000LL ), asset( 500000000LL, pairp ) );
   }
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   trade_both( 1000000, 5 );
   pass_window();
   BOOST_REQUIRE_EQUAL( h2e_find_tripwire( *this, pairp )->halt_stage,
                        GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT );
   BOOST_REQUIRE_EQUAL( vid( db ).tripwire_door_hold, true );

   // A paused sweep (no new samples, no feed advance): the vault sweep runs
   // over healthy coverage but must NOT clear the door-held freeze — the
   // tripwire owns that door, and only its reopen clears it.
   pass_window();
   BOOST_REQUIRE_EQUAL( h2e_find_tripwire( *this, pairp )->halt_stage,
                        GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT );
   BOOST_CHECK_EQUAL( vid( db ).tripwire_door_hold, true );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );

   // Two clean windows reopen everything (no guilty history anywhere).
   // The paused sweep above rotated the ring to empty, so three truthful
   // windows are needed: the first refills (pause), the next two build the
   // reopen streak (coincident-test precedent).
   for( const liquidity_pool_id_type pid : { pool1_id, pool2_id } )
   {
      const liquidity_pool_object& pool = pid( db );
      const share_type shares = db.get_balance( sam_id, pool.share_asset ).amount;
      withdraw_from_liquidity_pool( sam_id, pid, asset( shares, pool.share_asset ) );
      deposit_to_liquidity_pool( sam_id, pid,
                                 asset( 50000000000LL ), asset( 500000000LL, pairp ) );
   }
   for( int w = 0; w < 3; ++w )
   {
      h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
      trade_both( 1000000, 31 + w );
      pass_window();
   }
   BOOST_CHECK_EQUAL( h2e_find_tripwire( *this, pairp )->halt_stage, 0u );
   BOOST_CHECK_EQUAL( vid( db ).tripwire_door_hold, false );
   BOOST_CHECK_EQUAL( vid( db ).frozen, false );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, false );

   // Phase B: an open dispute expires in-sweep ahead of the tripwire read.
   // Keep the wire clean and the feed live throughout.
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   const fc::time_point_sec accused = oid( db ).history.back().first;
   const oracle_dispute_id_type did = h2e_post_dispute(
         *this, sam_id, sam_private_key, oid, bob_id, accused, 0,
         h2e_evidence( "x06-expiry" ) );
   trade_both( 1000000, 41 );
   generate_blocks( did( db ).round_deadline + 2 * 86400 );
   generate_block();
   BOOST_REQUIRE_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN );
   BOOST_REQUIRE_EQUAL( oid( db ).options.frozen, true );
   // GOV-R9-02: expiry is a clear -- this head-block time anchors the
   // committee unfreeze time-lock.
   const fc::time_point_sec cleared = db.head_block_time();

   // Two clean windows after expiry: the stage logic runs (nothing held —
   // Phase A cleared it) but the expiry freeze persists past the reopen
   // read, pinning expiry-before-reopen.
   for( int w = 0; w < 2; ++w )
   {
      h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
      trade_both( 1000000, 51 + w );
      pass_window();
   }
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );

   // GOV-R9-02: idle chain time until the 14-day lock from the expiry clear
   // elapses -- no publishes, no trades, so every sweep pauses and the stage
   // holds; the eventual committee unfreeze must clear a real lock.
   generate_blocks( cleared + GRAPHENE_ORACLE_UNFREEZE_DELAY_SEC + 60 );
   generate_block();
   set_expiration( db, trx );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );
   h2e_committee_unfreeze( *this, alice_id, alice_private_key, oid );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, false );
} FC_LOG_AND_RETHROW() }

/// R4-02a vault-half mirror of the R3-01 oracle pin: an EXPIRED vault
/// challenge keeps its vault frozen across clean tripwire windows even with
/// zero open challenges and healthy coverage. Without the guilty-history pin
/// in h2_reopen_tripwire's vault half, the counter + health read alone would
/// silently unfreeze a theft finding two windows after expiry. The oracle on
/// the same pair carries no guilty history, so the reopen still clears the
/// oracle half — the halves are independent. A further clean window with no
/// committee action changes nothing (the vault half has no unfreeze op:
/// sustained executes via vault_resolve; expired pins fail-closed).
BOOST_AUTO_TEST_CASE( tripwire_reopen_keeps_expired_vault_frozen )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(sam) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( sam, asset( 4000000000000LL ) );
   fund( sam, asset( 5000000000000LL ) ); // challenge bond + pool cycles need headroom
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   const asset_id_type pairp = h2e_create_uia( *this, alice_id, alice_private_key, "R402V" );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2e_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2E_VAULT_RAW, H2E_VAULT_USD_CENTS,
         pairp );
   const auto vest = h2e_make_cdd_vesting( *this, alice_id, alice_private_key, H2E_VAULT_RAW );
   h2e_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2E_VAULT_RAW,
                        H2E_VAULT_USD_CENTS );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "R402V.USD", bts_ref, usd_ref, opts );
   const auto vbb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, oid, vbb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   const auto vbc = h2e_make_cdd_vesting( *this, carol_id, carol_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, carol_id, carol_private_key, oid, vbc, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   h2e_freeze( *this, alice_id, alice_private_key, vid, oid );
   generate_block();
   db.modify( vid( db ), []( vault_object& v ) { v.frozen = false; } );
   db.modify( oid( db ), []( oracle_object& o ) { o.options.frozen = false; } );

   const asset_id_type s1 = h2e_create_uia( *this, sam_id, sam_private_key, "R4VS1" );
   const asset_id_type s2 = h2e_create_uia( *this, sam_id, sam_private_key, "R4VS2" );
   const liquidity_pool_id_type pool1_id = create_liquidity_pool(
         sam_id, asset_id_type(), pairp, s1, 0, 0 ).get_id();
   const liquidity_pool_id_type pool2_id = create_liquidity_pool(
         sam_id, asset_id_type(), pairp, s2, 0, 0 ).get_id();
   h2e_grant_seasoning( *this, pairp ); // ISS-R14-16: season the bound pair before the print
   issue_uia( sam, asset( 1200000000LL, pairp ) ); // pilot-scale (AC-02): ÷20 pools, drift <2%
   deposit_to_liquidity_pool( sam_id, pool1_id,
                              asset( 50000000000LL ), asset( 500000000LL, pairp ) );
   deposit_to_liquidity_pool( sam_id, pool2_id,
                              asset( 50000000000LL ), asset( 500000000LL, pairp ) );
   auto trade_both = [&]( int64_t sell_p, int64_t tweak )
   {
      exchange_with_liquidity_pool( sam_id, pool1_id,
                                    asset( sell_p + tweak, pairp ),
                                    asset( 1, asset_id_type() ) );
      exchange_with_liquidity_pool( sam_id, pool2_id,
                                    asset( sell_p - tweak, pairp ),
                                    asset( 1, asset_id_type() ) );
   };
   auto pass_window = [&]()
   {
      generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
      generate_block();
   };
   auto publish_both = [&]()
   {
      h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
      h2e_publish( *this, oid, carol_id, carol_private_key, 100, 1 );
   };

   // Halt to DEBT through dislocation (X-06 ladder pattern).
   publish_both();
   trade_both( 1000000, 1 );
   pass_window();
   for( const liquidity_pool_id_type pid : { pool1_id, pool2_id } )
   {
      const liquidity_pool_object& pool = pid( db );
      const share_type shares = db.get_balance( sam_id, pool.share_asset ).amount;
      withdraw_from_liquidity_pool( sam_id, pid, asset( shares, pool.share_asset ) );
      deposit_to_liquidity_pool( sam_id, pid,
                                 asset( 100000000000LL ), asset( 500000000LL, pairp ) );
   }
   publish_both();
   trade_both( 1000000, 5 );
   pass_window();
   BOOST_REQUIRE_EQUAL( h2e_find_tripwire( *this, pairp )->halt_stage,
                        GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT );
   BOOST_REQUIRE_EQUAL( vid( db ).tripwire_door_hold, true );

   // A vault challenge opens on the frozen vault (halting mints never blocks
   // new challenges) and expires untouched: guilty freeze, zero open.
   const vault_challenge_id_type cid = h2e_post_challenge(
         *this, sam_id, sam_private_key, vid, h2e_evidence( "r402v-expiry" ) );
   generate_blocks( cid( db ).deadline + 86400 );
   generate_block();
   BOOST_REQUIRE_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN );
   BOOST_REQUIRE_EQUAL( vid( db ).open_challenges, 0u );
   BOOST_REQUIRE_EQUAL( vid( db ).frozen, true );

   // Three truthful windows (refill after the jump's pause + two clean):
   // the wire reopens its STAGE while the GUILTY vault stays frozen — the
   // pre-R4-02 bypass (open_challenges == 0 + HEALTHY alone) would have
   // cleared it here. The guilt-free oracle half clears normally.
   for( const liquidity_pool_id_type pid : { pool1_id, pool2_id } )
   {
      const liquidity_pool_object& pool = pid( db );
      const share_type shares = db.get_balance( sam_id, pool.share_asset ).amount;
      withdraw_from_liquidity_pool( sam_id, pid, asset( shares, pool.share_asset ) );
      deposit_to_liquidity_pool( sam_id, pid,
                                 asset( 50000000000LL ), asset( 500000000LL, pairp ) );
   }
   for( int w = 0; w < 3; ++w )
   {
      publish_both();
      trade_both( 1000000, 61 + w );
      pass_window();
   }
   const tripwire_state_object* tw = h2e_find_tripwire( *this, pairp );
   BOOST_REQUIRE( tw != nullptr );
   BOOST_CHECK_EQUAL( tw->halt_stage, 0u );
   BOOST_CHECK_EQUAL( tw->redemptions_halted, false );
   BOOST_CHECK_EQUAL( vid( db ).tripwire_door_hold, false );
   BOOST_CHECK_EQUAL( vid( db ).maintenance_state, GRAPHENE_H2_VAULT_HEALTHY );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, false ); // oracle half: no guilty, reopened
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );           // R4-02a: guilty vault stays

   // One more clean window with no committee action: still frozen (the vault
   // half has no unfreeze op; expired pins fail-closed by design).
   publish_both();
   trade_both( 1000000, 64 );
   pass_window();
   BOOST_CHECK_EQUAL( h2e_find_tripwire( *this, pairp )->halt_stage, 0u );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, false );
} FC_LOG_AND_RETHROW() }

/// R4-02a control: an EXONERATED vault past is not guilty history, so a
/// door-held vault restores normally through tripwire reopen (mirrors the
/// exonerated-oracle owner-update pin for the vault half).
BOOST_AUTO_TEST_CASE( exonerated_vault_restores_through_reopen )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(sam) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( sam, asset( 4000000000000LL ) );
   fund( sam, asset( 5000000000000LL ) ); // challenge forfeit + pool cycles need headroom
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   const asset_id_type pairp = h2e_create_uia( *this, alice_id, alice_private_key, "R402X" );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2e_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2E_VAULT_RAW, H2E_VAULT_USD_CENTS,
         pairp );
   const auto vest = h2e_make_cdd_vesting( *this, alice_id, alice_private_key, H2E_VAULT_RAW );
   h2e_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2E_VAULT_RAW,
                        H2E_VAULT_USD_CENTS );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "R402X.USD", bts_ref, usd_ref, opts );
   const auto vbb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, oid, vbb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   const auto vbc = h2e_make_cdd_vesting( *this, carol_id, carol_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, carol_id, carol_private_key, oid, vbc, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   h2e_freeze( *this, alice_id, alice_private_key, vid, oid );
   generate_block();
   db.modify( vid( db ), []( vault_object& v ) { v.frozen = false; } );
   db.modify( oid( db ), []( oracle_object& o ) { o.options.frozen = false; } );

   // A vault challenge opens and exonerates: terminal EXONERATED history
   // stands in the (never-erased) challenge index, the vault never froze.
   const vault_challenge_id_type cid = h2e_post_challenge(
         *this, sam_id, sam_private_key, vid, h2e_evidence( "r402x-exonerate" ) );
   h2e_exonerate_from_genesis( *this, object_id_type( cid ) );
   BOOST_REQUIRE_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_EXONERATED );
   BOOST_REQUIRE_EQUAL( vid( db ).open_challenges, 0u );
   generate_block(); // fresh block: identical republish txs would trip duplicate_transaction

   const asset_id_type s1 = h2e_create_uia( *this, sam_id, sam_private_key, "R4XS1" );
   const asset_id_type s2 = h2e_create_uia( *this, sam_id, sam_private_key, "R4XS2" );
   const liquidity_pool_id_type pool1_id = create_liquidity_pool(
         sam_id, asset_id_type(), pairp, s1, 0, 0 ).get_id();
   const liquidity_pool_id_type pool2_id = create_liquidity_pool(
         sam_id, asset_id_type(), pairp, s2, 0, 0 ).get_id();
   h2e_grant_seasoning( *this, pairp ); // ISS-R14-16: season the bound pair before the print
   issue_uia( sam, asset( 1200000000LL, pairp ) ); // pilot-scale (AC-02): ÷20 pools, drift <2%
   deposit_to_liquidity_pool( sam_id, pool1_id,
                              asset( 50000000000LL ), asset( 500000000LL, pairp ) );
   deposit_to_liquidity_pool( sam_id, pool2_id,
                              asset( 50000000000LL ), asset( 500000000LL, pairp ) );
   auto trade_both = [&]( int64_t sell_p, int64_t tweak )
   {
      exchange_with_liquidity_pool( sam_id, pool1_id,
                                    asset( sell_p + tweak, pairp ),
                                    asset( 1, asset_id_type() ) );
      exchange_with_liquidity_pool( sam_id, pool2_id,
                                    asset( sell_p - tweak, pairp ),
                                    asset( 1, asset_id_type() ) );
   };
   auto pass_window = [&]()
   {
      generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
      generate_block();
   };
   auto publish_both = [&]()
   {
      h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
      h2e_publish( *this, oid, carol_id, carol_private_key, 100, 1 );
   };

   // Halt to DEBT (door hold freezes the vault), then three truthful
   // windows: reopen clears the vault despite the standing EXONERATED past.
   publish_both();
   trade_both( 1000000, 1 );
   pass_window();
   for( const liquidity_pool_id_type pid : { pool1_id, pool2_id } )
   {
      const liquidity_pool_object& pool = pid( db );
      const share_type shares = db.get_balance( sam_id, pool.share_asset ).amount;
      withdraw_from_liquidity_pool( sam_id, pid, asset( shares, pool.share_asset ) );
      deposit_to_liquidity_pool( sam_id, pid,
                                 asset( 100000000000LL ), asset( 500000000LL, pairp ) );
   }
   publish_both();
   trade_both( 1000000, 5 );
   pass_window();
   BOOST_REQUIRE_EQUAL( h2e_find_tripwire( *this, pairp )->halt_stage,
                        GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT );
   BOOST_REQUIRE_EQUAL( vid( db ).frozen, true );

   for( const liquidity_pool_id_type pid : { pool1_id, pool2_id } )
   {
      const liquidity_pool_object& pool = pid( db );
      const share_type shares = db.get_balance( sam_id, pool.share_asset ).amount;
      withdraw_from_liquidity_pool( sam_id, pid, asset( shares, pool.share_asset ) );
      deposit_to_liquidity_pool( sam_id, pid,
                                 asset( 50000000000LL ), asset( 500000000LL, pairp ) );
   }
   for( int w = 0; w < 3; ++w )
   {
      publish_both();
      trade_both( 1000000, 71 + w );
      pass_window();
   }
   BOOST_REQUIRE_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_EXONERATED );
   BOOST_CHECK_EQUAL( h2e_find_tripwire( *this, pairp )->halt_stage, 0u );
   BOOST_CHECK_EQUAL( vid( db ).tripwire_door_hold, false );
   BOOST_CHECK_EQUAL( vid( db ).frozen, false );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, false );
} FC_LOG_AND_RETHROW() }

/// R4-03 parity: the reward live-set applies the IDENTICAL bonded-live
/// definition as the read gate, so unbacked entries earn zero (fail-closed).
/// Bob is the bonded-live control; carol (weight forced to 0 white-box,
/// R3-02 precedent), dave (unlock forced past), and erin (vesting drained
/// below the bond — vesting withdrawals bypass the bond object) each fail
/// exactly one gate filter while staying unslashed, in-set, and live.
/// Pre-R4-03 code paid dave and erin (submission-live + unslashed was
/// enough); carol earns zero either way (pro-rata of weight 0), pinning
/// denominator parity instead.
BOOST_AUTO_TEST_CASE( reward_pool_pays_only_backed_live_producers )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(dave)(erin)(ginger) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( dave, asset( 30000000000000LL ) );
   fund( erin, asset( 30000000000000LL ) );
   fund( ginger, asset( 30000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   oracle_options opts;
   opts.producers[bob_id]   = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   opts.producers[dave_id]  = oracle_producer_entry( 1 );
   opts.producers[erin_id]  = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "R403.USD", bts_ref, usd_ref, opts );

   const auto vb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, oid, vb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   const auto vc = h2e_make_cdd_vesting( *this, carol_id, carol_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, carol_id, carol_private_key, oid, vc, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   const auto vd = h2e_make_cdd_vesting( *this, dave_id, dave_private_key, H2E_ORACLE_RAW );
   const producer_bond_id_type bdd =
         h2e_lock_producer_bond( *this, dave_id, dave_private_key, oid, vd, H2E_ORACLE_RAW,
                                 H2E_ORACLE_USD_CENTS );
   const auto ve = h2e_make_cdd_vesting( *this, erin_id, erin_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, erin_id, erin_private_key, oid, ve, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );

   // Eight days pass with no publishes: every bond unlock lapses, and erin's
   // vesting fully matures (CDD start_claim and vesting window are both 7d),
   // so a REAL withdrawal can break vesting coverage below the locked amount
   // — the production path the gate guards against. (White-box balance
   // forgery is not an option: the fixture checks total supply every block.)
   generate_blocks( db.head_block_time() + 8 * 86400 );
   generate_block();
   {
      vesting_balance_withdraw_operation wop;
      wop.vesting_balance = ve;
      wop.owner           = erin_id;
      wop.amount          = asset( H2E_ORACLE_RAW.value / 2, asset_id_type() );
      signed_transaction tx;
      tx.operations.push_back( wop );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      tx.sign( erin_private_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
   BOOST_REQUIRE( ve( db ).balance.amount < H2E_ORACLE_RAW );

   // Cross one more (empty) sweep so the publishes below land just after a
   // maintenance: the publish→sweep gap is then ~24h minus setup blocks,
   // keeping submissions live at the payout sweep whatever the grid phase
   // (a publish phase placed a full grid before the sweep would go stale —
   // value_lifetime_sec is 24h — and pay nobody).
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();

   // Fresh live submissions for all four. Bob and erin publish four times,
   // so their unlocks advance ~4d past the ~9d lapse back into the future
   // (both stay unlock-valid: erin is excluded by vesting coverage alone);
   // dave publishes once (his unlock stays lapsed despite the live
   // submission → unlock filter); carol publishes once (her weight is
   // forced to 0 below → weight filter).
   h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
   h2e_publish( *this, oid, bob_id, bob_private_key, 101, 1 );
   h2e_publish( *this, oid, bob_id, bob_private_key, 102, 1 );
   h2e_publish( *this, oid, bob_id, bob_private_key, 103, 1 );
   h2e_publish( *this, oid, carol_id, carol_private_key, 100, 1 );
   h2e_publish( *this, oid, dave_id, dave_private_key, 100, 1 );
   h2e_publish( *this, oid, erin_id, erin_private_key, 100, 1 );
   h2e_publish( *this, oid, erin_id, erin_private_key, 101, 1 );
   h2e_publish( *this, oid, erin_id, erin_private_key, 102, 1 );
   h2e_publish( *this, oid, erin_id, erin_private_key, 103, 1 );

   // Adversarial states, forced white-box AFTER the final publishes (a
   // publish would advance dave's unlock; votes below publish nothing).
   // Production reality: weight 0 is refused at create/update validate, so
   // carol's state is consensus-unreachable (gate second layer); dave's
   // lapsed unlock and erin's drained vesting are reachable (idle producers;
   // vesting withdrawals bypass the bond object).
   db.modify( oid( db ), [&]( oracle_object& o ) {
      o.options.producers[carol_id].weight = 0;
   } );
   db.modify( bdd( db ), [&]( producer_bond_object& b ) {
      b.unlock_time = db.head_block_time(); // sweep now >= unlock: releasable, unbacked
   } );

   // A spam dispute fast-rejects: 15% of the base accrues to the pool shell.
   const fc::time_point_sec accused = oid( db ).history.back().first;
   const oracle_dispute_id_type did = h2e_post_dispute(
         *this, ginger_id, ginger_private_key, oid, bob_id, accused, 0,
         h2e_evidence( "r403-spam" ) );
   h2e_fast_reject_from_genesis( *this, object_id_type( did ) );
   BOOST_REQUIRE_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_FAST_REJECTED );
   const int64_t pool_expect = H2E_ROUND1_RAW.value * 1500 / 10000;
   BOOST_CHECK( oid( db ).forfeit_pool_balance == share_type( pool_expect ) );

   const share_type bob_before = db.get_balance( bob_id, asset_id_type() ).amount;
   const share_type carol_before = db.get_balance( carol_id, asset_id_type() ).amount;
   const share_type dave_before = db.get_balance( dave_id, asset_id_type() ).amount;
   const share_type erin_before = db.get_balance( erin_id, asset_id_type() ).amount;

   // The next maintenance sweeps the forfeit into the pool and pays it out.

   // The next maintenance sweeps the forfeit into the pool and pays it out.
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
   generate_block();

   // Only the backed-live control earns: sole live weight 1 of 1 takes the
   // whole pool exactly (no dust); the three unbacked entries earn nothing.
   BOOST_CHECK_EQUAL( db.get_balance( bob_id, asset_id_type() ).amount.value,
                      ( bob_before + pool_expect ).value );
   BOOST_CHECK_EQUAL( db.get_balance( carol_id, asset_id_type() ).amount.value,
                      carol_before.value );
   BOOST_CHECK_EQUAL( db.get_balance( dave_id, asset_id_type() ).amount.value,
                      dave_before.value );
   BOOST_CHECK_EQUAL( db.get_balance( erin_id, asset_id_type() ).amount.value,
                      erin_before.value );
   BOOST_CHECK( oid( db ).forfeit_pool_balance == share_type( 0 ) );
   const reward_pool_object* pool1 = h2e_find_pool( *this, oid );
   BOOST_CHECK_EQUAL( pool1->balance.value, 0 );
   BOOST_CHECK_EQUAL( pool1->paid_lifetime.value, pool_expect );
} FC_LOG_AND_RETHROW() }

/// R4-05 coincidence: a vault-challenge deadline AND an oracle-dispute
/// round_deadline both fall strictly inside the sweep that completes the
/// second clean window (deadlines in (S3, S4]), so the same sweep expires
/// both targets and attempts a tripwire reopen. Expiry runs first by hook
/// order (db_maint.cpp: expiry, then vault, then oracle/tripwire), and the
/// reopen reads the fresh guilty history: the stage clears to NONE while
/// BOTH frozen flags persist. Committee oracle_unfreeze then clears the
/// oracle (stage NONE admits it — the R4-02 NONE-tightening accept pin)
/// while the guilty vault stays frozen with no committee path.
///
/// Honesty note (joint-outcome pin, not a step-through): the race is benign
/// by double-gating — had the tripwire hypothetically evaluated first, the
/// still-open counters (open_challenges/open_disputes == 1) would refuse the
/// same clears the guilty history refuses post-expiry. No same-sweep order
/// clears either flag, so the final state is order-insensitive; this test
/// pins the engineered coincidence (deadline-interior assertions) plus the
/// joint outcome, while the hook order itself stays documented (not proven)
/// in db_maint.cpp.
BOOST_AUTO_TEST_CASE( expiry_coincides_with_reopen_sweep_frozen_persists )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol)(sam) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   fund( carol, asset( 30000000000000LL ) );
   fund( sam, asset( 4000000000000LL ) );
   fund( sam, asset( 5000000000000LL ) ); // challenge + dispute bonds + pool cycles need headroom
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTS", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USD", 4 );

   const asset_id_type pairp = h2e_create_uia( *this, alice_id, alice_private_key, "R405" );
   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2e_register_vault(
         *this, alice_id, alice_private_key, vault_auth, H2E_VAULT_RAW, H2E_VAULT_USD_CENTS,
         pairp );
   const auto vest = h2e_make_cdd_vesting( *this, alice_id, alice_private_key, H2E_VAULT_RAW );
   h2e_lock_vault_bond( *this, alice_id, alice_private_key, vid, vest, H2E_VAULT_RAW,
                        H2E_VAULT_USD_CENTS );
   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "R405.USD", bts_ref, usd_ref, opts );
   const auto vbb = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, oid, vbb, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   const auto vbc = h2e_make_cdd_vesting( *this, carol_id, carol_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, carol_id, carol_private_key, oid, vbc, H2E_ORACLE_RAW,
                           H2E_ORACLE_USD_CENTS );
   h2e_freeze( *this, alice_id, alice_private_key, vid, oid );
   generate_block();
   db.modify( vid( db ), []( vault_object& v ) { v.frozen = false; } );
   db.modify( oid( db ), []( oracle_object& o ) { o.options.frozen = false; } );

   const asset_id_type s1 = h2e_create_uia( *this, sam_id, sam_private_key, "R4CS1" );
   const asset_id_type s2 = h2e_create_uia( *this, sam_id, sam_private_key, "R4CS2" );
   const liquidity_pool_id_type pool1_id = create_liquidity_pool(
         sam_id, asset_id_type(), pairp, s1, 0, 0 ).get_id();
   const liquidity_pool_id_type pool2_id = create_liquidity_pool(
         sam_id, asset_id_type(), pairp, s2, 0, 0 ).get_id();
   h2e_grant_seasoning( *this, pairp ); // ISS-R14-16: season the bound pair before the print
   issue_uia( sam, asset( 1200000000LL, pairp ) ); // pilot-scale (AC-02): ÷20 pools, drift <2%
   deposit_to_liquidity_pool( sam_id, pool1_id,
                              asset( 50000000000LL ), asset( 500000000LL, pairp ) );
   deposit_to_liquidity_pool( sam_id, pool2_id,
                              asset( 50000000000LL ), asset( 500000000LL, pairp ) );
   auto trade_both = [&]( int64_t sell_p, int64_t tweak )
   {
      exchange_with_liquidity_pool( sam_id, pool1_id,
                                    asset( sell_p + tweak, pairp ),
                                    asset( 1, asset_id_type() ) );
      exchange_with_liquidity_pool( sam_id, pool2_id,
                                    asset( sell_p - tweak, pairp ),
                                    asset( 1, asset_id_type() ) );
   };
   auto pass_window = [&]()
   {
      generate_blocks( db.get_dynamic_global_properties().next_maintenance_time + 3600 );
      generate_block();
   };
   auto publish_both = [&]()
   {
      h2e_publish( *this, oid, bob_id, bob_private_key, 100, 1 );
      h2e_publish( *this, oid, carol_id, carol_private_key, 100, 1 );
   };
   auto reset_pools = [&]()
   {
      for( const liquidity_pool_id_type pid : { pool1_id, pool2_id } )
      {
         const liquidity_pool_object& pool = pid( db );
         const share_type shares = db.get_balance( sam_id, pool.share_asset ).amount;
         withdraw_from_liquidity_pool( sam_id, pid, asset( shares, pool.share_asset ) );
         deposit_to_liquidity_pool( sam_id, pid,
                                    asset( 50000000000LL ), asset( 500000000LL, pairp ) );
      }
   };

   // Halt to DEBT (S0): fill, then breach on the combined median.
   publish_both();
   trade_both( 1000000, 1 );
   pass_window();
   for( const liquidity_pool_id_type pid : { pool1_id, pool2_id } )
   {
      const liquidity_pool_object& pool = pid( db );
      const share_type shares = db.get_balance( sam_id, pool.share_asset ).amount;
      withdraw_from_liquidity_pool( sam_id, pid, asset( shares, pool.share_asset ) );
      deposit_to_liquidity_pool( sam_id, pid,
                                 asset( 100000000000LL ), asset( 500000000LL, pairp ) );
   }
   publish_both();
   trade_both( 1000000, 5 );
   pass_window(); // S0
   BOOST_REQUIRE_EQUAL( h2e_find_tripwire( *this, pairp )->halt_stage,
                        GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT );

   // Pause window P (live feed, no samples): S1 holds the stage, streak 0.
   publish_both();
   pass_window(); // S1
   BOOST_REQUIRE_EQUAL( h2e_find_tripwire( *this, pairp )->halt_stage,
                        GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT );

   // C1: reset pools, aligned market, fresh accused print; open BOTH the
   // vault challenge and the oracle dispute here so both 48h deadlines land
   // in the S4 sweep (opened in (S1, S2] => deadline = opened + 48h in
   // (S3, S4]). S2 evaluates (P-empty, C1-full): pause, streak stays 0.
   reset_pools();
   publish_both();
   const fc::time_point_sec accused = oid( db ).history.back().first;
   const vault_challenge_id_type cid = h2e_post_challenge(
         *this, sam_id, sam_private_key, vid, h2e_evidence( "r405-challenge" ) );
   const oracle_dispute_id_type did = h2e_post_dispute(
         *this, sam_id, sam_private_key, oid, bob_id, accused, 0,
         h2e_evidence( "r405-dispute" ) );
   trade_both( 1000000, 81 );
   pass_window(); // S2
   BOOST_REQUIRE_EQUAL( h2e_find_tripwire( *this, pairp )->halt_stage,
                        GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT );

   // C2: (C1, C2) clean → streak 1. Both targets still open (no expiry yet:
   // deadlines sit a full window out).
   publish_both();
   trade_both( 1000000, 82 );
   pass_window(); // S3
   BOOST_REQUIRE_EQUAL( h2e_find_tripwire( *this, pairp )->halt_stage,
                        GRAPHENE_H2E_TRIPWIRE_STAGE_DEBT );
   const fc::time_point_sec tS3 = db.head_block_time();
   BOOST_REQUIRE( cid( db ).state == GRAPHENE_H2_CHALLENGE_OPEN );
   BOOST_REQUIRE( did( db ).state == GRAPHENE_H2_CHALLENGE_OPEN );
   // Coincidence engineering, asserted before the sweep: both deadlines fall
   // at-or-after tS3 (non-strict: tS3 is read after pass_window's trailing
   // block, ~3s after the maintenance-now the expiry sweep actually used;
   // the OPEN states above already prove the deadlines strictly exceed the
   // S3 maintenance-now, and the post-S4 EXPIRED states below prove they do
   // not exceed the S4 one — together the strict interior (S3, S4]).
   BOOST_TEST_MESSAGE( "R405 timing: cid.opened=" << cid( db ).opened.sec_since_epoch()
                       << " cid.deadline=" << cid( db ).deadline.sec_since_epoch()
                       << " did.deadline=" << did( db ).round_deadline.sec_since_epoch()
                       << " tS3=" << tS3.sec_since_epoch() );
   BOOST_REQUIRE( cid( db ).deadline >= tS3 );
   BOOST_REQUIRE( did( db ).round_deadline >= tS3 );

   // C3: the S4 sweep evaluates (C2, C3) clean (streak 2 → reopen attempted)
   // with both deadlines inside it (deadline <= S4-now is proven post-sweep
   // by the EXPIRED_FROZEN states: expiry only fires at deadline <= now).
   publish_both();
   trade_both( 1000000, 83 );
   pass_window(); // S4: expiry + vault sweep + reopen coincide
   BOOST_REQUIRE_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN );
   BOOST_REQUIRE_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN );
   BOOST_REQUIRE_EQUAL( vid( db ).open_challenges, 0u );
   BOOST_REQUIRE_EQUAL( oid( db ).open_disputes, 0u );

   // Joint outcome: the wire reopened its stage (streak logic ran on clean
   // windows) while BOTH guilty freezes persisted (expiry won the race).
   const tripwire_state_object* tw = h2e_find_tripwire( *this, pairp );
   BOOST_REQUIRE( tw != nullptr );
   BOOST_CHECK_EQUAL( tw->halt_stage, 0u );
   BOOST_CHECK_EQUAL( tw->redemptions_halted, false );
   BOOST_CHECK_EQUAL( vid( db ).tripwire_door_hold, false );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );

   // GOV-R9-02: the committee unfreeze waits 14 days from the S4 expiry
   // clear. Idle chain time only -- no publishes, no trades, so every sweep
   // pauses (stage holds at NONE) and both guilty freezes must survive the
   // whole wait; only then may one seated member clear the oracle half.
   const fc::time_point_sec cleared = db.head_block_time();
   generate_blocks( cleared + GRAPHENE_ORACLE_UNFREEZE_DELAY_SEC + 60 );
   generate_block();
   set_expiration( db, trx );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, true );

   // Committee oracle_unfreeze admits at NONE and clears the oracle; the
   // guilty vault has no committee path and stays frozen through another
   // clean window.
   h2e_committee_unfreeze( *this, alice_id, alice_private_key, oid );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, false );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   publish_both();
   trade_both( 1000000, 84 );
   pass_window();
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   BOOST_CHECK_EQUAL( oid( db ).options.frozen, false );
} FC_LOG_AND_RETHROW() }

/// X-08 lifecycle seam: deleting an oracle with an open dispute is refused
/// (RED: pre-fix only market-issued subscribers block, disputes do not).
/// After a fast-reject resolution the forfeit pool leg still refuses: the
/// undistributed pool must settle through the reward sweep first.
BOOST_AUTO_TEST_CASE( delete_with_open_dispute_refused )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob)(carol) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 3000000000000LL ) );
   fund( carol, asset( 3000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTSD", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USDD", 4 );

   oracle_options opts;
   opts.producers[carol_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "DEL.USD", bts_ref, usd_ref, opts );
   h2e_publish( *this, oid, carol_id, carol_private_key, 100, 1 );
   const fc::time_point_sec accused = oid( db ).history.back().first;

   const oracle_dispute_id_type did = h2e_post_dispute(
         *this, bob_id, bob_private_key, oid, carol_id, accused, 0,
         h2e_evidence( "delete-dispute" ) );
   BOOST_REQUIRE_EQUAL( oid( db ).open_disputes, 1u );

   // Open dispute: refused, oracle still present.
   h2e_delete_oracle_throws( *this, alice_id, alice_private_key, oid );
   BOOST_CHECK( db.find( oid ) != nullptr );

   // Resolve by fast-reject: the dispute closes but the forfeit pool holds
   // the 15% slice until the reward sweep settles it -- deletion still
   // refused on the pool leg.
   h2e_fast_reject_from_genesis( *this, object_id_type( did ) );
   BOOST_REQUIRE_EQUAL( did( db ).state, GRAPHENE_H2_CHALLENGE_FAST_REJECTED );
   BOOST_REQUIRE_EQUAL( oid( db ).open_disputes, 0u );
   BOOST_REQUIRE( oid( db ).forfeit_pool_balance > share_type( 0 ) );
   h2e_delete_oracle_throws( *this, alice_id, alice_private_key, oid );
   BOOST_CHECK( db.find( oid ) != nullptr );
} FC_LOG_AND_RETHROW() }

/// X-08 lifecycle seam: deleting an oracle a vault is canonically bound to
/// (and which still secures a producer bond) is refused (RED: pre-fix the
/// delete path checks only market-issued subscribers and strands the
/// bound_oracle pin with no rebind path).
BOOST_AUTO_TEST_CASE( delete_with_bound_vault_refused )
{ try {
   generate_blocks( HARDFORK_H2_PRICE_TIME );
   generate_block();
   set_expiration( db, trx );

   ACTORS( (alice)(bob) );
   fund( alice, asset( 30000000000000LL ) );
   fund( bob, asset( 30000000000000LL ) );
   h2e_make_committee_member( *this, alice );
   const auto bts_ref = h2e_create_reference( *this, alice_id, alice_private_key, "BTSB", 5 );
   const auto usd_ref = h2e_create_reference( *this, alice_id, alice_private_key, "USDB", 4 );

   oracle_options opts;
   opts.producers[bob_id] = oracle_producer_entry( 1 );
   const oracle_id_type oid =
         h2e_make_oracle( *this, alice_id, alice_private_key, "BINDDEL.USD", bts_ref, usd_ref, opts );
   // Producer bond live on the oracle (third refuse leg).
   const auto obvest = h2e_make_cdd_vesting( *this, bob_id, bob_private_key, H2E_ORACLE_RAW );
   h2e_lock_producer_bond( *this, bob_id, bob_private_key, oid, obvest,
                           H2E_ORACLE_RAW, H2E_ORACLE_USD_CENTS );

   authority vault_auth( 1, alice_id, 1 );
   const vault_id_type vid = h2e_register_vault_default(
         *this, alice_id, alice_private_key, vault_auth );
   h2e_freeze( *this, alice_id, alice_private_key, vid, oid );
   BOOST_REQUIRE( vid( db ).bound_oracle.valid() );

   // Bound vault (and live producer bond): refused, oracle still present.
   h2e_delete_oracle_throws( *this, alice_id, alice_private_key, oid );
   BOOST_CHECK( db.find( oid ) != nullptr );
} FC_LOG_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()
