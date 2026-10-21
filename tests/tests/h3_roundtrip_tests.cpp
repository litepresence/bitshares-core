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
#include <graphene/protocol/issuance_ops.hpp>
#include <graphene/protocol/vault_lifecycle_ops.hpp>

#include <fc/io/raw.hpp>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;

namespace {
constexpr int64_t RAW_PER_USD_CENT = 1000000LL;
constexpr uint64_t ORACLE_USD_CENTS = 1005000;
const share_type ORACLE_RAW = share_type( int64_t( ORACLE_USD_CENTS ) * RAW_PER_USD_CENT );
/// The committed rate: one foreign unit is worth 2 bond raw units
/// (num 2, den 1). A reimbursement of 100 foreign units pays 200 bond raw.
constexpr uint64_t RATE_NUM = 2;
constexpr uint64_t RATE_DEN = 1;
/// The vault bond floor: $13,400 (GRAPHENE_H2_VAULT_MIN_BOND_USD_CENTS).
constexpr uint64_t VAULT_USD_CENTS = 1340000;
const share_type VAULT_RAW = share_type( int64_t( VAULT_USD_CENTS ) * RAW_PER_USD_CENT );
} // namespace

/// The H3 round trip: a foreign lock proof mints vault-backed UIA, the holder
/// redeems it, the attestor publishes the unlock proof, and the vault is
/// never frozen.
struct h3_roundtrip_fixture : database_fixture
{
   account_id_type owner;
   account_id_type attestor;
   account_id_type holder;
   fc::ecc::private_key owner_key;
   fc::ecc::private_key attestor_key;
   fc::ecc::private_key holder_key;
   oracle_id_type    oid;
   vault_id_type     vid;
   asset_id_type     pair_asset;
   account_object    owner_account;

   void build()
   {
      // Past every H2 gate AND the oracle hardfork (2030-01-01): the
      // reference asset and the oracle both need the oracle leg.
      generate_blocks( HARDFORK_H2_PRICE_TIME );
      generate_block();
      set_expiration( db, trx );

      ACTORS( (alice)(bob)(carol) );
      owner = alice_id; owner_key = alice_private_key;
      attestor = bob_id; attestor_key = bob_private_key;
      holder = carol_id; holder_key = carol_private_key;
      owner_account = alice;
      fund( alice, asset( 30000000000000LL ) );
      fund( bob, asset( 30000000000000LL ) );
      fund( carol, asset( 30000000000000LL ) );

      // Reference asset creation is committee-only until the committee opens
      // it, so the owner must be seated first.
      upgrade_to_lifetime_member( owner_account );
      create_and_seat_committee_member( owner_account );
      generate_block();

      const auto base = make_ref( owner, owner_key, "RTX", 5 );
      const auto quote = make_ref( owner, owner_key, "RTQ", 4 );

      oracle_create_operation oop;
      oop.owner = owner; oop.name = "H3RT.USD"; oop.base = base; oop.quote = quote;
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

      lock_producer_bond( attestor, attestor_key, oid );

      asset_create_operation aop;
      aop.issuer = owner; aop.symbol = "H3RT"; aop.precision = 2;
      aop.common_options.max_supply = GRAPHENE_MAX_SHARE_SUPPLY;
      aop.common_options.core_exchange_rate = price( asset( 2 ), asset( 1, asset_id_type( 1 ) ) );
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
      vop.backing_chain = 1;
      vop.backing_asset = "BTC";
      vop.backing_rate_num = RATE_NUM;
      vop.backing_rate_den = RATE_DEN;
      signed_transaction vtx; vtx.operations.push_back( vop );
      db.current_fee_schedule().set_fee( vtx.operations.back() );
      set_expiration( db, vtx ); vtx.sign( owner_key, db.get_chain_id() );
      vid = vault_id_type {
         PUSH_TX( db, vtx ).operation_results.front().get<object_id_type>() };

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

   reference_asset_id_type make_ref( account_id_type creator, const fc::ecc::private_key& key,
                                     const std::string& sym, uint8_t prec )
   {
      reference_asset_create_operation op;
      op.creator = creator; op.symbol = sym; op.precision = prec; op.description = sym;
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( key, db.get_chain_id() );
      return reference_asset_id_type {
         PUSH_TX( db, tx ).operation_results.front().get<object_id_type>() };
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

   /// Promote a foreign transaction record on the bound oracle, so the mint
   /// and unlock reads see it.
   void promote_foreign( const graphene::protocol::foreign_tx_value& val, time_point_sec t )
   {
      h2_ensure_oracle_econ( db, oid );
      db.modify( oid( db ), [&]( oracle_object& o ) {
         o.consumed_foreign_value = std::vector<graphene::protocol::foreign_tx_value>{ val };
         o.consumed_foreign_value_time = t;
         // A live submission keeps the attestor in the bonded live set, which
         // the live read checks.
         if( !o.options.producers.empty() )
         {
            account_id_type p = o.options.producers.begin()->first;
            o.submissions[p] = std::make_pair( t, std::vector<oracle_value>{} );
         }
      } );
      const auto& gidx = db.get_index_type<guard_state_index>().indices().get<by_guard_oracle>();
      const auto gitr = gidx.find( oid );
      if( gitr == gidx.end() ) return;
      const guard_state_object* g = &*gitr;
      const uint32_t delay = db.get_global_properties().parameters.get_oracle_guard_delay_sec();
      const uint32_t anchor = h2_osm_bucket_anchor( uint32_t( t.sec_since_epoch() ), delay );
      db.modify( *g, [&]( guard_state_object& gg ) {
         h2_promotion_record rec;
         rec.promote_time = t;
         rec.producer_count = oid( db ).options.minimum_producers;
         rec.anchor = anchor;
         rec.delay_sec = delay;
         gg.promotion_log.push_back( rec );
         // The foreign promotion proof reads the FOREIGN log (the price log
         // is the price path's; a foreign publish must never evict it).
         gg.foreign_promotion_log.push_back( rec );
         gg.last_promo_time = t;
      } );
   }

   static graphene::protocol::foreign_tx_value make_ftv( graphene::protocol::foreign_tx_kind kind,
                                                uint8_t b0, int64_t amount,
                                                uint64_t height )
   {
      graphene::protocol::foreign_tx_value v;
      v.chain = graphene::protocol::foreign_chain_id::bitcoin;
      v.tx_id.hash[0] = b0;
      v.kind = kind;
      v.amount = amount;
      v.foreign_asset_id = 0;
      v.confirmation_height = height;
      return v;
   }

   graphene::protocol::foreign_tx_id do_mint( account_id_type recipient, int64_t amount,
                                    uint8_t tag )
   {
      graphene::protocol::foreign_tx_id dep;
      dep.hash[0] = tag;
      promote_foreign( make_ftv( graphene::protocol::foreign_tx_kind::lock, tag, amount, 100 ),
                       db.head_block_time() );
      vault_foreign_mint_operation op;
      op.vault = vid;
      op.deposit_id = dep;
      op.amount = share_type( amount );
      op.recipient = recipient;
      op.minter = owner;   // the vault authority member signs
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( owner_key, db.get_chain_id() );
      PUSH_TX( db, tx );
      return dep;
   }

   void do_redeem( account_id_type redeemer, int64_t amount, const graphene::protocol::foreign_tx_id& dep )
   {
      vault_foreign_redeem_operation op;
      op.redeemer = redeemer;
      op.vault = vid;
      op.amount = share_type( amount );
      op.deposit_id = dep;
      op.foreign_recipient = "bc1qexample";
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( redeemer == holder ? holder_key : owner_key,
                                         db.get_chain_id() );
      PUSH_TX( db, tx );
   }

   void do_unlock( int64_t amount, uint8_t tag, const graphene::protocol::foreign_tx_id& dep )
   {
      promote_foreign( make_ftv( graphene::protocol::foreign_tx_kind::unlock, tag, amount, 110 ),
                       db.head_block_time() );
      vault_foreign_unlock_operation op;
      op.publisher = attestor;
      op.vault = vid;
      op.deposit_id = dep;
      op.amount = share_type( amount );
      op.foreign_tx_hash = "deadbeef";
      signed_transaction tx; tx.operations.push_back( op );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx ); tx.sign( attestor_key, db.get_chain_id() );
      PUSH_TX( db, tx );
   }
};

BOOST_FIXTURE_TEST_SUITE( h3_roundtrip_tests, h3_roundtrip_fixture )

/// The full round trip: mint on a lock proof, redeem the minted UIA, publish
/// the unlock proof. The vault is never frozen and the outstanding returns to
/// zero.
BOOST_AUTO_TEST_CASE( mint_redeem_unlock_round_trip )
{
   build();
   const auto dep = do_mint( holder, 1000, 0x11 );
   BOOST_CHECK_EQUAL( db.get_balance( holder, pair_asset ).amount.value, 1000 );
   BOOST_CHECK_EQUAL( vid( db ).outstanding.value, 1000 );

   do_redeem( holder, 1000, dep );
   BOOST_CHECK_EQUAL( db.get_balance( holder, pair_asset ).amount.value, 0 );
   BOOST_CHECK_EQUAL( vid( db ).outstanding.value, 0 );
   BOOST_REQUIRE_EQUAL( vid( db ).foreign_redeems.size(), 1u );

   do_unlock( 1000, 0x11, dep );
   BOOST_REQUIRE_EQUAL( vid( db ).foreign_redeems.size(), 1u );
   BOOST_CHECK_EQUAL( vid( db ).foreign_redeems[0].unlocked, true );
   BOOST_CHECK_EQUAL( vid( db ).frozen, false );
}

/// A redeem on a vault with no committed rate is refused: the reimbursement
/// would be undefined.
BOOST_AUTO_TEST_CASE( redeem_refused_without_committed_rate )
{
   build();
   db.modify( vid( db ), []( vault_object& v ) { v.backing_rate_den = 0; } );
   graphene::protocol::foreign_tx_id dep;
   dep.hash[0] = 0x22;
   BOOST_CHECK_THROW( do_redeem( holder, 100, dep ), fc::exception );
}

/// An unlock proof from a non-attestor is refused.
BOOST_AUTO_TEST_CASE( unlock_refused_from_non_attestor )
{
   build();
   const auto dep = do_mint( holder, 1000, 0x33 );
   do_redeem( holder, 1000, dep );
   promote_foreign( make_ftv( graphene::protocol::foreign_tx_kind::unlock, 0x33, 1000, 110 ),
                    db.head_block_time() );
   vault_foreign_unlock_operation op;
   op.publisher = holder;   // not an attestor
   op.vault = vid;
   op.deposit_id = dep;
   op.amount = share_type( 1000 );
   op.foreign_tx_hash = "deadbeef";
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( holder_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
}

/// A missed SLA freezes the vault and reimburses the redeemer from the bond
/// at the committed rate. A missed deadline is a liveness failure, not a lie:
/// the bond covers it, it does not punish it, and the attestor's bond is
/// untouched.
BOOST_AUTO_TEST_CASE( missed_sla_freezes_and_reimburses_at_committed_rate )
{
   build();
   const auto dep = do_mint( holder, 1000, 0x44 );
   do_redeem( holder, 1000, dep );

   const auto bond_before = db.get_balance( holder, asset_id_type() ).amount;

   // Past the 72h SLA.
   generate_blocks( db.head_block_time() + GRAPHENE_H3_FOREIGN_REDEEM_SLA_SEC + 3600 );
   generate_block();

   // The vault froze and the redeem was cleared.
   BOOST_CHECK_EQUAL( vid( db ).frozen, true );
   BOOST_CHECK_EQUAL( vid( db ).foreign_redeems.size(), 0u );

   // The redeemer was reimbursed in bond terms at the committed rate:
   // 1000 foreign units at num 2 / den 1 = 2000 bond raw units.
   const auto bond_after = db.get_balance( holder, asset_id_type() ).amount;
   BOOST_CHECK_EQUAL( ( bond_after - bond_before ).value, 2000 );
}

/// The committed rate converts a foreign amount to bond terms, rounding DOWN.
BOOST_AUTO_TEST_CASE( rate_conversion_rounds_down )
{
   build();
   BOOST_CHECK_EQUAL( h2_vault_convert_to_bond_terms( vid( db ), share_type( 1000 ) ).value, 2000 );
   BOOST_CHECK_EQUAL( h2_vault_convert_to_bond_terms( vid( db ), share_type( 3 ) ).value, 6 );
   db.modify( vid( db ), []( vault_object& v ) { v.backing_rate_den = 0; } );
   BOOST_CHECK_EQUAL( h2_vault_convert_to_bond_terms( vid( db ), share_type( 1000 ) ).value, 0 );
}

/// C01: a foreign mint against a frozen vault is refused. The freeze is the
/// mint halt: a challenge, the tripwire, or a coverage breach.
BOOST_AUTO_TEST_CASE( mint_refused_on_a_frozen_vault )
{
   build();
   db.modify( vid( db ), []( vault_object& v ) { v.frozen = true; } );
   graphene::protocol::foreign_tx_id dep;
   dep.hash[0] = 0x55;
   BOOST_CHECK_THROW( do_mint( holder, 1000, 0x55 ), fc::exception );
}

/// C02: a deposit may back at most ONE mint. A replayed lock proof would
/// otherwise back unlimited mints.
BOOST_AUTO_TEST_CASE( mint_refused_for_a_replayed_deposit )
{
   build();
   do_mint( holder, 1000, 0x66 );
   BOOST_CHECK_THROW( do_mint( holder, 1000, 0x66 ), fc::exception );
}

/// C03: a deposit may be redeemed at most once. A second redeem would burn
/// twice and open two SLA records for one deposit.
BOOST_AUTO_TEST_CASE( redeem_refused_for_a_replayed_deposit )
{
   build();
   const auto dep = do_mint( holder, 1000, 0x77 );
   do_redeem( holder, 1000, dep );
   BOOST_CHECK_THROW( do_redeem( holder, 1000, dep ), fc::exception );
}

/// C04: the minter may not also be a co-signer: one signature must not
/// satisfy the vault multisig twice.
BOOST_AUTO_TEST_CASE( mint_refused_when_the_minter_is_also_a_cosigner )
{
   build();
   graphene::protocol::foreign_tx_id dep;
   dep.hash[0] = 0x88;
   promote_foreign( make_ftv( graphene::protocol::foreign_tx_kind::lock, 0x88, 1000, 100 ),
                    db.head_block_time() );
   vault_foreign_mint_operation op;
   op.vault = vid;
   op.deposit_id = dep;
   op.amount = share_type( 1000 );
   op.recipient = holder;
   op.minter = owner;
   op.co_signers.insert( owner );   // the minter doubles as a co-signer
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( owner_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
}

/// I04: the unlock must unlock what was redeemed. An unlock of a smaller
/// amount must not clear the whole SLA.
BOOST_AUTO_TEST_CASE( unlock_refused_for_a_mismatched_amount )
{
   build();
   const auto dep = do_mint( holder, 1000, 0x99 );
   do_redeem( holder, 1000, dep );
   // The promoted unlock carries 500, the redeem burned 1000.
   promote_foreign( make_ftv( graphene::protocol::foreign_tx_kind::unlock, 0x99, 500, 110 ),
                    db.head_block_time() );
   vault_foreign_unlock_operation op;
   op.publisher = attestor;
   op.vault = vid;
   op.deposit_id = dep;
   op.amount = share_type( 500 );
   op.foreign_tx_hash = "deadbeef";
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( attestor_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
}

/// I05: a foreign-backed vault must commit a non-zero exchange-rate numerator.
BOOST_AUTO_TEST_CASE( register_refused_without_a_rate_numerator )
{
   build();
   // A second vault with a zero numerator must be refused at registration.
   asset_create_operation aop;
   aop.issuer = owner; aop.symbol = "H3N0"; aop.precision = 2;
   aop.common_options.max_supply = GRAPHENE_MAX_SHARE_SUPPLY;
   aop.common_options.core_exchange_rate = price( asset( 2 ), asset( 1, asset_id_type( 1 ) ) );
   signed_transaction atx; atx.operations.push_back( aop );
   db.current_fee_schedule().set_fee( atx.operations.back() );
   set_expiration( db, atx ); atx.sign( owner_key, db.get_chain_id() );
   const asset_id_type pair2 = asset_id_type {
      PUSH_TX( db, atx ).operation_results.front().get<object_id_type>() };

   authority auth2( 1, owner, 1 );
   vault_register_operation vop;
   vop.registrar = owner;
   vop.pair = pair2;
   vop.vault_authority = auth2;
   vop.min_bond = VAULT_RAW;
   vop.min_bond_usd_cents = VAULT_USD_CENTS;
   vop.secure_ratio_bps = 20000;
   vop.challenge_window_sec = GRAPHENE_H2_VAULT_MAX_CHALLENGE_WINDOW_SEC;
   vop.backing_chain = 1;
   vop.backing_asset = "BTC";
   vop.backing_rate_num = 0;   // refused
   vop.backing_rate_den = 1;
   signed_transaction vtx; vtx.operations.push_back( vop );
   db.current_fee_schedule().set_fee( vtx.operations.back() );
   set_expiration( db, vtx ); vtx.sign( owner_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, vtx ), fc::exception );
}

/// I08: the H2 mint path refuses a foreign-backed vault. The H3 legs serve
/// it, and only one economics may apply to a vault.
BOOST_AUTO_TEST_CASE( h2_mint_refused_on_a_foreign_vault )
{
   build();
   hybrid_mint_operation op;
   op.vault = vid;
   op.deposit = asset( ORACLE_RAW, asset_id_type() );
   op.minter = owner;
   signed_transaction tx; tx.operations.push_back( op );
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx ); tx.sign( owner_key, db.get_chain_id() );
   BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
}

BOOST_AUTO_TEST_SUITE_END()
