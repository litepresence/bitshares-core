#include <boost/test/unit_test.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/bond_object.hpp>
#include <graphene/chain/challenge_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/h2_economics_evaluator.hpp>
#include <graphene/chain/h2_economics_object.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/oracle_object.hpp>
#include <graphene/chain/reference_asset_object.hpp>
#include <graphene/chain/vault_object.hpp>
#include <graphene/chain/vesting_balance_object.hpp>
#include <graphene/protocol/challenge_ops.hpp>
#include <graphene/protocol/vault_ops.hpp>
#include <graphene/protocol/h2_economics.hpp>
#include <graphene/protocol/oracle.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>

#include <fc/io/raw.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

namespace {
constexpr int64_t RAW_PER_USD_CENT = 1000000LL;
constexpr uint64_t ORACLE_USD_CENTS = 1005000;
const share_type ORACLE_RAW = share_type( int64_t( ORACLE_USD_CENTS ) * RAW_PER_USD_CENT );
constexpr uint64_t CHALLENGE_USD_CENTS = 83750;
const share_type CHALLENGE_RAW = share_type( int64_t( CHALLENGE_USD_CENTS ) * RAW_PER_USD_CENT );
/// The vault bond floor: $13,400 (GRAPHENE_H2_VAULT_MIN_BOND_USD_CENTS).
constexpr uint64_t VAULT_USD_CENTS = 1340000;
const share_type VAULT_RAW = share_type( int64_t( VAULT_USD_CENTS ) * RAW_PER_USD_CENT );
} // namespace

/// A foreign-backed vault with a bonded attestor set: the vault, its bound
/// foreign chain transaction oracle, the attestor's producer bond, and the
/// vault's own bond. The helper returns the ids the test needs.
struct h3_attestor_fixture : database_fixture
{
   account_id_type owner;
   account_id_type attestor;
   account_id_type challenger;
   account_id_type voter_id;
   fc::ecc::private_key owner_key;
   fc::ecc::private_key attestor_key;
   fc::ecc::private_key challenger_key;
   fc::ecc::private_key voter_key;
   account_object   voter_account;
   account_object   owner_account;
   oracle_id_type    oid;
   vault_id_type     vid;
   asset_id_type     pair_asset;

   void build()
   {
      // Past every H2 gate AND the oracle hardfork (2030-01-01): the
      // reference asset and the oracle both need the oracle leg.
      generate_blocks( HARDFORK_H2_PRICE_TIME );
      generate_block();
      set_expiration( db, trx );

      ACTORS( (alice)(bob)(carol)(dave) );
      owner = alice_id; owner_key = alice_private_key;
      attestor = bob_id; attestor_key = bob_private_key;
      challenger = carol_id; challenger_key = carol_private_key;
      voter_id = dave_id; voter_key = dave_private_key;
      voter_account = dave;
      owner_account = alice;
      fund( alice, asset( 30000000000000LL ) );
      fund( bob, asset( 30000000000000LL ) );
      fund( carol, asset( 30000000000000LL ) );
      fund( dave, asset( 30000000000000LL ) );

      // Reference asset creation is committee-only until the committee opens
      // it, so the owner must be seated first.
      upgrade_to_lifetime_member( owner_account );
      create_and_seat_committee_member( owner_account );

      // The bound foreign chain transaction oracle, with the attestor as a
      // bonded producer.
      reference_asset_create_operation bop;
      bop.creator = owner; bop.symbol = "FTX"; bop.precision = 5; bop.description = "base";
      signed_transaction btx; btx.operations.push_back( bop );
      db.current_fee_schedule().set_fee( btx.operations.back() );
      set_expiration( db, btx ); btx.sign( owner_key, db.get_chain_id() );
      const auto base = reference_asset_id_type {
         PUSH_TX( db, btx ).operation_results.front().get<object_id_type>() };

      reference_asset_create_operation qop;
      qop.creator = owner; qop.symbol = "FTQ"; qop.precision = 4; qop.description = "quote";
      signed_transaction qtx; qtx.operations.push_back( qop );
      db.current_fee_schedule().set_fee( qtx.operations.back() );
      set_expiration( db, qtx ); qtx.sign( owner_key, db.get_chain_id() );
      const auto quote = reference_asset_id_type {
         PUSH_TX( db, qtx ).operation_results.front().get<object_id_type>() };

      oracle_create_operation oop;
      oop.owner = owner; oop.name = "H3ATT.USD"; oop.base = base; oop.quote = quote;
      oop.description = "foreign chain tx oracle";
      oop.series = { oracle_series( oracle_series_kind::foreign_tx,
                                    oracle_series_rounding::unspecified ) };
      oracle_options oopts;
      oopts.producers[attestor] = oracle_producer_entry( 1 );
      oopts.minimum_producers = 1;
      oopts.value_lifetime_sec = 3600;
      oop.options = oopts;
      signed_transaction otx; otx.operations.push_back( oop );
      db.current_fee_schedule().set_fee( otx.operations.back() );
      set_expiration( db, otx ); otx.sign( owner_key, db.get_chain_id() );
      oid = oracle_id_type {
         PUSH_TX( db, otx ).operation_results.front().get<object_id_type>() };

      // The attestor's producer bond on the foreign oracle.
      lock_producer_bond( attestor, attestor_key, oid );

      // The vault: foreign-backed, bound to the foreign oracle.
      asset_create_operation aop;
      aop.issuer = owner; aop.symbol = "H3ATT"; aop.precision = 2;
      aop.common_options.max_supply = GRAPHENE_MAX_SHARE_SUPPLY;
      aop.common_options.core_exchange_rate = price( asset( 2 ), asset( 1, asset_id_type( 1 ) ) );
      aop.issuer = owner;
      signed_transaction atx; atx.operations.push_back( aop );
      db.current_fee_schedule().set_fee( atx.operations.back() );
      set_expiration( db, atx ); atx.sign( owner_key, db.get_chain_id() );
      pair_asset = asset_id_type {
         PUSH_TX( db, atx ).operation_results.front().get<object_id_type>() };

      authority vault_auth( 1, owner, 1 );
      vault_register_operation vop;
      vop.registrar = owner;
      vop.pair = pair_asset;
      vop.vault_authority = vault_auth;
      vop.min_bond = VAULT_RAW;
      vop.min_bond_usd_cents = VAULT_USD_CENTS;
      vop.secure_ratio_bps = 20000;
      vop.challenge_window_sec = GRAPHENE_H2_VAULT_MAX_CHALLENGE_WINDOW_SEC;
      vop.backing_chain = 1;   // bitcoin
      vop.backing_asset = "BTC";
      signed_transaction vtx; vtx.operations.push_back( vop );
      db.current_fee_schedule().set_fee( vtx.operations.back() );
      set_expiration( db, vtx ); vtx.sign( owner_key, db.get_chain_id() );
      vid = vault_id_type {
         PUSH_TX( db, vtx ).operation_results.front().get<object_id_type>() };

      // The vault's own bond.
      vesting_balance_create_operation vbop;
      vbop.creator = owner; vbop.owner = owner;
      vbop.amount = asset( VAULT_RAW, asset_id_type() );
      vbop.policy = cdd_vesting_policy_initializer(
         GRAPHENE_H2_BOND_UNBOND_DELAY_SEC, db.head_block_time() + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC );
      signed_transaction vbtx; vbtx.operations.push_back( vbop );
      db.current_fee_schedule().set_fee( vbtx.operations.back() );
      set_expiration( db, vbtx ); vbtx.sign( owner_key, db.get_chain_id() );
      const auto vest = vesting_balance_id_type {
         PUSH_TX( db, vbtx ).operation_results.front().get<object_id_type>() };

      vault_bond_lock_operation lbop;
      lbop.owner = owner; lbop.vault = vid; lbop.vesting_balance = vest;
      lbop.bond_amount = VAULT_RAW; lbop.bond_usd_cents = VAULT_USD_CENTS;
      signed_transaction lbtx; lbtx.operations.push_back( lbop );
      db.current_fee_schedule().set_fee( lbtx.operations.back() );
      set_expiration( db, lbtx ); lbtx.sign( owner_key, db.get_chain_id() );
      PUSH_TX( db, lbtx );

      // Bind the vault to the foreign oracle and unfreeze for the test.
      pair_freeze_operation fop;
      fop.freezer = owner; fop.vault = vid; fop.oracle = oid;
      signed_transaction ftx; ftx.operations.push_back( fop );
      db.current_fee_schedule().set_fee( ftx.operations.back() );
      set_expiration( db, ftx ); ftx.sign( owner_key, db.get_chain_id() );
      PUSH_TX( db, ftx );
      generate_block();
      db.modify( vid( db ), []( vault_object& v ) { v.frozen = false; } );
      db.modify( oid( db ), []( oracle_object& o ) { o.options.frozen = false; } );
      generate_block();
   }

   void lock_producer_bond( account_id_type producer, const fc::ecc::private_key& key,
                            oracle_id_type oracle )
   {
      vesting_balance_create_operation vop;
      vop.creator = producer; vop.owner = producer;
      vop.amount = asset( ORACLE_RAW, asset_id_type() );
      vop.policy = cdd_vesting_policy_initializer(
         GRAPHENE_H2_BOND_UNBOND_DELAY_SEC, db.head_block_time() + GRAPHENE_H2_BOND_UNBOND_DELAY_SEC );
      signed_transaction vtx; vtx.operations.push_back( vop );
      db.current_fee_schedule().set_fee( vtx.operations.back() );
      set_expiration( db, vtx ); vtx.sign( key, db.get_chain_id() );
      vesting_balance_id_type vid {
         PUSH_TX( db, vtx ).operation_results.front().get<object_id_type>() };

      oracle_bond_lock_operation bop;
      bop.producer = producer; bop.oracle = oracle; bop.vesting_balance = vid;
      bop.bond_amount = ORACLE_RAW; bop.bond_usd_cents = ORACLE_USD_CENTS;
      signed_transaction btx; btx.operations.push_back( bop );
      db.current_fee_schedule().set_fee( btx.operations.back() );
      set_expiration( db, btx ); btx.sign( key, db.get_chain_id() );
      PUSH_TX( db, btx );
   }

   /// Open a foreign attestor-lie challenge. Returns the challenge object id.
   vault_challenge_id_type open_challenge( account_id_type accused,
                                           const graphene::protocol::foreign_tx_id& deposit )
   {
      vault_foreign_challenge_operation op;
      op.challenger = challenger;
      op.vault = vid;
      op.accused_attestor = accused;
      op.deposit_id = deposit;
      op.challenge_bond = CHALLENGE_RAW;
      op.challenge_bond_usd_cents = CHALLENGE_USD_CENTS;
      op.evidence_memo = "attestor attested a transaction that did not happen";
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( challenger_key, db.get_chain_id() );
      return vault_challenge_id_type {
         PUSH_TX( db, tx ).operation_results.front().get<object_id_type>() };
   }

   /// The live 2/3-supermajority threshold over the seated deciding set
   /// (mirrors the evaluator's helper: ceil(2N/3) over the ELECTED set).
   uint64_t vote_threshold()
   {
      const uint64_t n = db.get_global_properties().active_committee_members.size();
      BOOST_REQUIRE( n > 0 );
      return ( n * GRAPHENE_H2_SUPERMAJORITY_BPS + 9999 ) / 10000;
   }

   /// Seat a committee member so the vote path has an elected voter. The
   /// voter is a separate account from the challenger: a party may not vote
   /// on its own challenge.
   account_id_type seat_voter()
   {
      upgrade_to_lifetime_member( voter_account );
      create_and_seat_committee_member( voter_account );
      return voter_id;
   }

   /// Cast the votes a resolution needs: the genesis committee members, none
   /// of whom shares authority with the challenged vault.
   void vote_to_resolve( object_id_type target, uint8_t decision )
   {
      const uint64_t need = vote_threshold();
      for( uint64_t i = 0; i < need; ++i )
         fund( get_account( string( "init" ) + fc::to_string( i ) ), asset( 1000000 ) );
      for( uint64_t i = 0; i < need; ++i )
         vote( get_account( string( "init" ) + fc::to_string( i ) ).get_id(),
               init_account_priv_key, target, decision );
   }

   void vote( account_id_type voter, const fc::ecc::private_key& key,
              object_id_type target, uint8_t decision )
   {
      challenge_vote_operation op;
      op.voter = voter; op.target = target; op.decision = decision;
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
};

BOOST_FIXTURE_TEST_SUITE( h3_attestor_tests, h3_attestor_fixture )

/// A challenge against a foreign-backed vault opens and names the accused
/// attestor and the disputed deposit.
BOOST_AUTO_TEST_CASE( foreign_attestor_challenge_opens )
{
   build();
   graphene::protocol::foreign_tx_id deposit;
   deposit.hash[0] = 0xAB;
   const auto cid = open_challenge( attestor, deposit );
   const auto& c = cid( db );
   BOOST_CHECK_EQUAL( c.state, GRAPHENE_H2_CHALLENGE_OPEN );
   BOOST_CHECK( c.vault == vid );
   BOOST_CHECK( c.attested_account == attestor );
   BOOST_CHECK( c.attested_deposit == deposit );
   BOOST_CHECK_EQUAL( c.challenge_bond.value, CHALLENGE_RAW.value );
   BOOST_CHECK_EQUAL( vid( db ).open_challenges, 1u );
}

/// A challenge against a NON-foreign vault is refused: there is no attestor.
BOOST_AUTO_TEST_CASE( challenge_refused_on_non_foreign_vault )
{
   build();
   db.modify( vid( db ), []( vault_object& v ) { v.backing_chain = 0; } );
   graphene::protocol::foreign_tx_id deposit;
   BOOST_CHECK_THROW( open_challenge( attestor, deposit ), fc::exception );
}

/// A challenge naming a stranger (not a producer of the bound oracle) is
/// refused: the slash leg would have no bond to slash.
BOOST_AUTO_TEST_CASE( challenge_refused_for_non_producer_accused )
{
   build();
   graphene::protocol::foreign_tx_id deposit;
   BOOST_CHECK_THROW( open_challenge( challenger, deposit ), fc::exception );
}

/// The challenge escrow is funded from transparent funds and the challenger's
/// balance is debited at the posted amount.
BOOST_AUTO_TEST_CASE( challenge_escrow_debits_transparent_balance )
{
   build();
   const auto before = db.get_balance( challenger, asset_id_type() ).amount;
   graphene::protocol::foreign_tx_id deposit;
   open_challenge( attestor, deposit );
   const auto after = db.get_balance( challenger, asset_id_type() ).amount;
   BOOST_CHECK_EQUAL( ( before - after ).value, CHALLENGE_RAW.value );
}

/// A sustained challenge slashes the accused attestor's producer bond and
/// freezes the vault. The missed-deadline rule is the opposite path: a missed
/// SLA freezes without a slash, and this is the LIE path.
BOOST_AUTO_TEST_CASE( sustained_challenge_slashes_attestor_bond_and_freezes_vault )
{
   build();
   seat_voter();
   graphene::protocol::foreign_tx_id deposit;
   deposit.hash[0] = 0xCD;
   const auto cid = open_challenge( attestor, deposit );

   // Find the attestor's producer bond and confirm it is live.
   const auto& bond_idx = db.get_index_type<producer_bond_index>()
                             .indices().get<by_oracle_producer>();
   const auto bitr = bond_idx.find( boost::make_tuple( oid, attestor ) );
   BOOST_REQUIRE( bitr != bond_idx.end() );
   BOOST_CHECK_EQUAL( bitr->slashed, false );

   // The committee sustains the challenge.
   vote_to_resolve( object_id_type(cid), 1 );
   generate_block();

   const auto& bond_idx2 = db.get_index_type<producer_bond_index>()
                              .indices().get<by_oracle_producer>();
   const auto bitr2 = bond_idx2.find( boost::make_tuple( oid, attestor ) );
   BOOST_REQUIRE( bitr2 != bond_idx2.end() );
   BOOST_CHECK_EQUAL( bitr2->slashed, true );
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   BOOST_CHECK_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_SUSTAINED );
}

/// An exonerated challenge leaves the attestor's bond live and the vault
/// unfrozen by the challenge leg.
BOOST_AUTO_TEST_CASE( exonerated_challenge_leaves_attestor_bond_live )
{
   build();
   seat_voter();
   graphene::protocol::foreign_tx_id deposit;
   deposit.hash[0] = 0xEF;
   const auto cid = open_challenge( attestor, deposit );

   vote_to_resolve( object_id_type(cid), 0 );  // exonerate
   generate_block();

   const auto& bond_idx = db.get_index_type<producer_bond_index>()
                             .indices().get<by_oracle_producer>();
   const auto bitr = bond_idx.find( boost::make_tuple( oid, attestor ) );
   BOOST_REQUIRE( bitr != bond_idx.end() );
   BOOST_CHECK_EQUAL( bitr->slashed, false );
   BOOST_CHECK_EQUAL( cid( db ).state, GRAPHENE_H2_CHALLENGE_EXONERATED );
}

/// The challenge is fail-closed on the H2 bond floor: a challenge below the
/// $837.50 USD-terms floor is refused.
BOOST_AUTO_TEST_CASE( challenge_refused_below_bond_floor )
{
   build();
   vault_foreign_challenge_operation op;
   op.challenger = challenger;
   op.vault = vid;
   op.accused_attestor = attestor;
   op.challenge_bond = CHALLENGE_RAW;
   op.challenge_bond_usd_cents = 1;
   op.evidence_memo = "too small";
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( challenger_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
}

/// The H3 attestor set governance: a foreign-backed vault's rotation refuses
/// an incoming signer that holds no live producer bond on the bound foreign
/// oracle (a signer with no attestor bond cannot be slashed for a lie).
BOOST_AUTO_TEST_CASE( rotation_refuses_signer_without_attestor_bond )
{
   build();
   // A second signer with no producer bond on the bound oracle.
   account_id_type newcomer = challenger;
   authority new_auth( 1, newcomer, 1 );
   vault_rotate_operation op;
   op.rotator = owner;
   op.vault = vid;
   op.new_authority = new_auth;
   op.memo = "rotate";
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( owner_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
}

BOOST_AUTO_TEST_SUITE_END()
