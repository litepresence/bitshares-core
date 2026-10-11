/*
 * G1b stealth crypto core tests (BSIP-2 §1 + §4).
 *
 * TDD note: this suite was written BEFORE the implementation
 * (libraries/protocol/stealth.{hpp,cpp}, libraries/chain/stealth_*).
 * Pre-implementation it fails to compile (missing headers/ops) — that
 * compile failure plus the grep evidence of missing consensus verification
 * (no verify_range call anywhere under libraries/chain/) is the RED.
 *
 * Live gap under test: blind-amount validity is currently client-side.
 * validate() inspects range-proof HEADERS (range_get_info) but no chain
 * evaluator calls verify_range, so a commitment carrying an out-of-range
 * (or negative-wrapped) value with a mismatched-but-well-formed proof is
 * accepted by consensus. Test negative_mint_rejected pins the fix:
 * post-STEALTH hardfork the same transaction MUST throw in do_evaluate.
 *
 * Consensus law for everything new here: no floats, no unordered_*,
 * head-block time only, bounded state, deterministic (OpenSSL EC ops on
 * secp256k1 with sha256 Fiat-Shamir; no randomness in consensus paths).
 * The provers below are TEST-ONLY (wallets own proving); consensus code
 * never signs, never generates randomness.
 */

#include <boost/test/unit_test.hpp>

#include <graphene/chain/database.hpp>
#include <graphene/chain/exceptions.hpp>
#include <graphene/chain/hardfork.hpp>

#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/committee_member_object.hpp>
#include <graphene/chain/confidential_object.hpp>
#include <graphene/chain/proposal_object.hpp>

#include <graphene/protocol/confidential.hpp>
#include <graphene/protocol/stealth.hpp>
#include <graphene/protocol/transfer.hpp>

#include <graphene/chain/stealth_proof.hpp>
#include <graphene/chain/stealth_object.hpp>
#include <graphene/chain/stealth_evaluator.hpp>
#include <graphene/chain/liquidity_pool_evaluator.hpp>
#include <graphene/chain/liquidity_pool_object.hpp>
#include <graphene/chain/transaction_evaluation_state.hpp>
#include <graphene/chain/impacted.hpp>
#include <graphene/app/database_api.hpp>
#include <graphene/wallet/wallet.hpp>

#include <graphene/chain/stealth_prover.hpp>
#include <graphene/chain/stealth_pool_builder.hpp>

#include <operation_printer.hpp>
#include <wallet_api_impl.hpp>

#include <fc/crypto/digest.hpp>
#include <fc/io/raw.hpp>
#include <fc/reflect/variant.hpp>

#include <algorithm>
#include <map>
#include <random>
#include <sstream>
#include <vector>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>

#include "../common/database_fixture.hpp"

using namespace graphene::chain;
using namespace graphene::chain::test;
using namespace graphene::protocol;

namespace {

const EC_GROUP* T_group()
{
   static EC_GROUP* g = EC_GROUP_new_by_curve_name( NID_secp256k1 );
   BOOST_REQUIRE( g != nullptr );
   return g;
}

BIGNUM* T_order()
{
   static BIGNUM* n = nullptr;
   if( !n )
   {
      n = BN_new();
      EC_GROUP_get_order( T_group(), n, nullptr );
   }
   return n;
}

BN_CTX* T_ctx()
{
   static BN_CTX* c = nullptr;
   if( !c ) c = BN_CTX_new();
   return c;
}

std::vector<unsigned char> T_compress( const EC_POINT* pt )
{
   std::vector<unsigned char> out( 33 );
   size_t len = EC_POINT_point2oct( T_group(), pt, POINT_CONVERSION_COMPRESSED,
                                    out.data(), out.size(), nullptr );
   BOOST_REQUIRE( len == 33 );
   return out;
}

EC_POINT* T_open( const std::vector<unsigned char>& bytes )
{
   EC_POINT* pt = EC_POINT_new( T_group() );
   BOOST_REQUIRE( EC_POINT_oct2point( T_group(), pt, bytes.data(), bytes.size(), nullptr ) == 1 );
   return pt;
}

EC_POINT* T_open_c( const fc::ecc::commitment_type& c )
{
   EC_POINT* pt = EC_POINT_new( T_group() );
   BOOST_REQUIRE( EC_POINT_oct2point( T_group(), pt,
      (const unsigned char*)c.data(), 33, nullptr ) == 1 );
   return pt;
}

/// Deterministic test scalar from a string (test only, never consensus).
BIGNUM* T_scalar( const std::string& s )
{
   fc::sha256 h = fc::sha256::hash( s );
   BIGNUM* b = BN_new();
   BN_bin2bn( (const unsigned char*)h.data(), 32, b );
   BN_mod( b, b, T_order(), T_ctx() );
   return b;
}

fc::sha256 T_secret( const std::string& s ) { return fc::sha256::hash( s ); }

/**
 * Blind scalar label with a hard guarantee: the returned sha256, parsed as a
 * big-endian integer, is strictly below the curve order. Both backends (fc's
 * libsecp256k1 scalar parse and test OpenSSL BIGNUMs) then agree on the
 * scalar, so Pedersen commitments match byte-for-byte. Deterministic.
 */
fc::sha256 T_blind_secret( const std::string& label )
{
   for( int k = 0; ; ++k )
   {
      std::string s = ( k == 0 ) ? label : ( label + "#ord#" + std::to_string( k ) );
      fc::sha256 h = fc::sha256::hash( s );
      BIGNUM* b = BN_new();
      BN_bin2bn( (const unsigned char*)h.data(), 32, b );
      bool lt = ( BN_cmp( b, T_order() ) < 0 ) && !BN_is_zero( b );
      BN_free( b );
      if( lt ) return h;
      BOOST_REQUIRE_LT( k, 100 );
   }
}

BIGNUM* T_bn( const fc::sha256& h )
{
   BIGNUM* b = BN_new();
   BN_bin2bn( (const unsigned char*)h.data(), 32, b );
   BN_mod( b, b, T_order(), T_ctx() );
   return b;
}

fc::ecc::commitment_type T_commitment( const std::vector<unsigned char>& v )
{
   fc::ecc::commitment_type c;
   BOOST_REQUIRE( v.size() == 33 );
   std::copy( v.begin(), v.end(), c.begin() );
   return c;
}

/// Test-only Pedersen commitment C = b*G + v*H with consensus generators.
std::vector<unsigned char> T_commit( const BIGNUM* b, uint64_t v )
{
   EC_POINT* acc = EC_POINT_new( T_group() );
   EC_POINT* tmp = EC_POINT_new( T_group() );
   EC_POINT* Hp = T_open( stealth_H_point() );
   BIGNUM* vv = BN_new(); BN_set_word( vv, (BN_ULONG)v );
   EC_POINT_mul( (EC_GROUP*)T_group(), acc, b, nullptr, nullptr, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), tmp, nullptr, Hp, vv, T_ctx() );
   EC_POINT_add( (EC_GROUP*)T_group(), acc, acc, tmp, T_ctx() );
   auto out = T_compress( acc );
   EC_POINT_free( acc ); EC_POINT_free( tmp ); EC_POINT_free( Hp ); BN_free( vv );
   return out;
}

/**
 * Test-only linkable-ring prover over Pedersen openings, WITH
 * pseudo-output value binding (Monero/MLSAG-style kernel, G1b-3).
 *
 * Real member s with opening (b_s, v_s): Q_s = b_s*G + v_s*H.
 * Pseudo-output P = b'*G + v_s*H (SAME value, fresh blind b').
 * Key image I = b_s*J1 + v_s*J2 (J1/J2 = version-domain generators).
 * Per member i the verifier forms D_i = P - Q_i: a commitment to zero
 * iff P and Q_i share the value, with known blinding (b' - b_s) only
 * at the real member. Forging a bound signature for an inflated P
 * (value != v_s) requires the discrete log of a non-zero H-multiple
 * w.r.t. G, i.e. log_G(H) — the standard Pedersen binding assumption.
 * Signature: c_0 || (rb_0, rv_0, rd_0) ... (rb_{n-1}, rv_{n-1}, rd_{n-1}),
 * 32-byte big-endian scalars, total 32 + 96*n bytes.
 * Verifier equation (stealth_proof.cpp): L_i = rb_i*G + rv_i*H + c_i*Q_i,
 * R_i = rb_i*J1 + rv_i*J2 + c_i*I, M_i = rd_i*G + c_i*D_i,
 * c_{i+1} = H*(m||L_i||R_i||M_i), wrap c_n == c_0.
 */
void T_prove_ring( uint8_t version,
                   const std::vector<std::vector<unsigned char>>& Q,
                   size_t s, const BIGNUM* b_s, uint64_t v_s,
                   const BIGNUM* b_prime,
                   const std::string& msg32,
                   std::vector<unsigned char>& image_out,
                   std::vector<unsigned char>& pseudo_out,
                   std::vector<char>& sig_out )
{
   size_t n = Q.size();
   BOOST_REQUIRE( s < n && n >= 2 && msg32.size() == 32 );
   EC_POINT* J1 = T_open( stealth_J1_point( version ) );
   EC_POINT* J2 = T_open( stealth_J2_point( version ) );
   EC_POINT* Hp = T_open( stealth_H_point() );
   EC_POINT* I = EC_POINT_new( T_group() );
   EC_POINT* L = EC_POINT_new( T_group() );
   EC_POINT* R = EC_POINT_new( T_group() );
   EC_POINT* T = EC_POINT_new( T_group() );
   EC_POINT* M = EC_POINT_new( T_group() );
   EC_POINT* P = EC_POINT_new( T_group() );

   BIGNUM* vs = BN_new(); BN_set_word( vs, (BN_ULONG)v_s );
   EC_POINT_mul( (EC_GROUP*)T_group(), I, nullptr, J1, b_s, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), T, nullptr, J2, vs, T_ctx() );
   EC_POINT_add( (EC_GROUP*)T_group(), I, I, T, T_ctx() );

   // Pseudo-output: same value as the real member, fresh blind.
   EC_POINT_mul( (EC_GROUP*)T_group(), P, b_prime, nullptr, nullptr, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), T, nullptr, Hp, vs, T_ctx() );
   EC_POINT_add( (EC_GROUP*)T_group(), P, P, T, T_ctx() );
   pseudo_out = T_compress( P );

   // D_i = P - Q_i for every member (verifier recomputes the same).
   std::vector<EC_POINT*> Dv( n, nullptr );
   for( size_t k = 0; k < n; ++k )
   {
      EC_POINT* Qk = T_open( Q[k] );
      Dv[k] = EC_POINT_new( T_group() );
      EC_POINT_copy( Dv[k], P );
      EC_POINT_invert( (EC_GROUP*)T_group(), Qk, T_ctx() );
      EC_POINT_add( (EC_GROUP*)T_group(), Dv[k], Dv[k], Qk, T_ctx() );
      EC_POINT_free( Qk );
   }

   std::vector<BIGNUM*> c( n ), rb( n ), rv( n ), rd( n );
   for( size_t i = 0; i < n; ++i )
      { c[i] = BN_new(); rb[i] = BN_new(); rv[i] = BN_new(); rd[i] = BN_new(); }

   BIGNUM* a_b = T_scalar( "g1b3-testa|" + std::to_string( Q.size() ) + "|" + std::to_string( s ) );
   BIGNUM* a_v = T_scalar( "g1b3-testav|" + std::to_string( Q.size() ) + "|" + std::to_string( s ) );
   BIGNUM* a_d = T_scalar( "g1b3-testad|" + std::to_string( Q.size() ) + "|" + std::to_string( s ) );
   EC_POINT_mul( (EC_GROUP*)T_group(), L, a_b, nullptr, nullptr, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), T, nullptr, Hp, a_v, T_ctx() );
   EC_POINT_add( (EC_GROUP*)T_group(), L, L, T, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), R, nullptr, J1, a_b, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), T, nullptr, J2, a_v, T_ctx() );
   EC_POINT_add( (EC_GROUP*)T_group(), R, R, T, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), M, a_d, nullptr, nullptr, T_ctx() );

   auto Lc = T_compress( L ), Rc = T_compress( R ), Mc = T_compress( M );
   fc::sha256 cc = stealth_challenge( msg32, Lc, Rc, Mc );
   BN_bin2bn( (const unsigned char*)cc.data(), 32, c[(s+1)%n] );
   BN_mod( c[(s+1)%n], c[(s+1)%n], T_order(), T_ctx() );

   size_t i = (s+1) % n;
   size_t guard = 0;
   while( i != s && guard++ <= n )
   {
      BIGNUM* t1 = T_scalar( "g1b3-rb|" + std::to_string( n ) + "|" + std::to_string( i ) );
      BIGNUM* t2 = T_scalar( "g1b3-rv|" + std::to_string( n ) + "|" + std::to_string( i ) );
      BIGNUM* t3 = T_scalar( "g1b3-rd|" + std::to_string( n ) + "|" + std::to_string( i ) );
      BN_copy( rb[i], t1 ); BN_copy( rv[i], t2 ); BN_copy( rd[i], t3 );
      EC_POINT* Qi = T_open( Q[i] );
      EC_POINT_mul( (EC_GROUP*)T_group(), L, rb[i], nullptr, nullptr, T_ctx() );
      EC_POINT_mul( (EC_GROUP*)T_group(), T, nullptr, Hp, rv[i], T_ctx() );
      EC_POINT_add( (EC_GROUP*)T_group(), L, L, T, T_ctx() );
      EC_POINT_mul( (EC_GROUP*)T_group(), T, nullptr, Qi, c[i], T_ctx() );
      EC_POINT_add( (EC_GROUP*)T_group(), L, L, T, T_ctx() );
      EC_POINT_mul( (EC_GROUP*)T_group(), R, nullptr, J1, rb[i], T_ctx() );
      EC_POINT_mul( (EC_GROUP*)T_group(), T, nullptr, J2, rv[i], T_ctx() );
      EC_POINT_add( (EC_GROUP*)T_group(), R, R, T, T_ctx() );
      EC_POINT_mul( (EC_GROUP*)T_group(), T, nullptr, I, c[i], T_ctx() );
      EC_POINT_add( (EC_GROUP*)T_group(), R, R, T, T_ctx() );
      EC_POINT_mul( (EC_GROUP*)T_group(), M, rd[i], nullptr, nullptr, T_ctx() );
      EC_POINT_mul( (EC_GROUP*)T_group(), T, nullptr, Dv[i], c[i], T_ctx() );
      EC_POINT_add( (EC_GROUP*)T_group(), M, M, T, T_ctx() );
      EC_POINT_free( Qi );
      auto lc = T_compress( L ), rc = T_compress( R ), mc = T_compress( M );
      fc::sha256 nx = stealth_challenge( msg32, lc, rc, mc );
      BN_bin2bn( (const unsigned char*)nx.data(), 32, c[(i+1)%n] );
      BN_mod( c[(i+1)%n], c[(i+1)%n], T_order(), T_ctx() );
      BN_free( t1 ); BN_free( t2 ); BN_free( t3 );
      i = (i+1) % n;
   }
   BOOST_REQUIRE( i == s );
   {
      BIGNUM* t = BN_new();
      BIGNUM* bd = BN_new();
      BN_mod_sub( bd, b_prime, b_s, T_order(), T_ctx() );
      BN_mod_mul( t, c[s], b_s, T_order(), T_ctx() );
      BN_mod_sub( rb[s], a_b, t, T_order(), T_ctx() );
      BN_mod_mul( t, c[s], vs, T_order(), T_ctx() );
      BN_mod_sub( rv[s], a_v, t, T_order(), T_ctx() );
      BN_mod_mul( t, c[s], bd, T_order(), T_ctx() );
      BN_mod_sub( rd[s], a_d, t, T_order(), T_ctx() );
      BN_free( t ); BN_free( bd );
   }
   image_out = T_compress( I );
   sig_out.clear();
   unsigned char buf[32];
   BN_bn2binpad( c[0], buf, 32 );
   sig_out.insert( sig_out.end(), (char*)buf, (char*)buf + 32 );
   for( size_t k = 0; k < n; ++k )
   {
      BN_bn2binpad( rb[k], buf, 32 );
      sig_out.insert( sig_out.end(), (char*)buf, (char*)buf + 32 );
      BN_bn2binpad( rv[k], buf, 32 );
      sig_out.insert( sig_out.end(), (char*)buf, (char*)buf + 32 );
      BN_bn2binpad( rd[k], buf, 32 );
      sig_out.insert( sig_out.end(), (char*)buf, (char*)buf + 32 );
   }
   for( size_t k = 0; k < n; ++k )
      { BN_free( c[k] ); BN_free( rb[k] ); BN_free( rv[k] ); BN_free( rd[k] ); }
   BN_free( a_b ); BN_free( a_v ); BN_free( a_d ); BN_free( vs );
   EC_POINT_free( J1 ); EC_POINT_free( J2 ); EC_POINT_free( Hp );
   EC_POINT_free( I ); EC_POINT_free( L ); EC_POINT_free( R );
   EC_POINT_free( T ); EC_POINT_free( M ); EC_POINT_free( P );
   for( auto d : Dv ) EC_POINT_free( d );
}

stealth_ring_input T_make_ring_input( uint8_t version,
      const std::vector<std::vector<unsigned char>>& Q,
      size_t s, const BIGNUM* b_s, uint64_t v_s,
      const BIGNUM* b_prime,
      const std::string& msg32 )
{
   std::vector<unsigned char> img, pseudo;
   std::vector<char> sig;
   T_prove_ring( version, Q, s, b_s, v_s, b_prime, msg32, img, pseudo, sig );
   stealth_ring_input rin;
   for( const auto& q : Q ) rin.ring.push_back( T_commitment( q ) );
   rin.key_image.assign( img.begin(), img.end() );
   rin.pseudo_output = T_commitment( pseudo );
   rin.ring_sig = sig;
   return rin;
}

/**
 * Task 5 (M05/GC-07) dual-image ring input: the test prover knows the opening
 * (b,v), so it authorizes under BOTH versions in one input — main image+sig
 * under `version` with msg_main32, alternate under `alt_version` with
 * msg_alt32, over the same ring and pseudo-output. The pseudo-output is
 * version-independent (P = b'*G + v*H uses the fixed bases G/H), pinned
 * equal here; the images differ (version-domain J bases).
 */
stealth_ring_input T_make_dual_ring_input( uint8_t version, uint8_t alt_version,
      const std::vector<std::vector<unsigned char>>& Q,
      size_t s, const BIGNUM* b_s, uint64_t v_s,
      const BIGNUM* b_prime,
      const std::string& msg_main32, const std::string& msg_alt32 )
{
   stealth_ring_input rin = T_make_ring_input( version, Q, s, b_s, v_s,
                                               b_prime, msg_main32 );
   stealth_ring_input alt = T_make_ring_input( alt_version, Q, s, b_s, v_s,
                                               b_prime, msg_alt32 );
   BOOST_REQUIRE( alt.pseudo_output == rin.pseudo_output );
   rin.alt_key_image = alt.key_image;
   rin.alt_ring_sig = alt.ring_sig;
   return rin;
}

/// Dry-run both versions to learn both images (+ shared pseudo) before
/// building the version-bound ring messages (mirrors the happy-path pattern).
struct T_dual_dry_run_result
{
   std::vector<unsigned char> img_main, img_alt, pseudo;
};
T_dual_dry_run_result T_dual_dry_run( uint8_t v_main, uint8_t v_alt,
      const std::vector<std::vector<unsigned char>>& Q,
      size_t s, const BIGNUM* b_s, uint64_t v_s, const BIGNUM* b_prime )
{
   T_dual_dry_run_result r;
   std::vector<char> sig0;
   std::string m0( 32, '\0' );
   std::vector<unsigned char> pseudo_alt;
   T_prove_ring( v_main, Q, s, b_s, v_s, b_prime, m0, r.img_main, r.pseudo, sig0 );
   T_prove_ring( v_alt, Q, s, b_s, v_s, b_prime, m0, r.img_alt, pseudo_alt, sig0 );
   BOOST_REQUIRE( pseudo_alt == r.pseudo );
   return r;
}

/**
 * Test-only BP+ prover (m=1, n=64).
 *
 * Ported from S1 bulletproof_plus_PROVE (monero @ e4fbca88, vendored) to
 * secp256k1/OpenSSL with the G1 transcript (stealth_bp_hash domains
 * "G1BPy"/"G1BPz"/"G1BPr"/"G1BPf", R9C-chained S1-style) and prime-order form (S1's x8/INV_EIGHT cofactor
 * clearing dropped as identity — no cofactor exists on secp256k1, same
 * adaptation the consensus verifier documents). Generators Gi/Hi/G/H come
 * from the consensus accessors so prover and verifier share every constant.
 *
 * Deterministic (labels + attempt counter, no randomness): wallets
 * reimplement proving from the verifier spec; this exists only to feed the
 * consensus verifier in tests.
 *
 * Wire (stealth_bp_proof_size(1) == 592 bytes):
 *   m || A || A1 || B || r1 || s1 || d1 || (L_j || R_j per round, 6 rounds).
 */
namespace {
BIGNUM* Bp_mod_add( BIGNUM* r, const BIGNUM* a, const BIGNUM* b )
{ BN_mod_add( r, a, b, T_order(), T_ctx() ); return r; }
BIGNUM* Bp_mod_sub( BIGNUM* r, const BIGNUM* a, const BIGNUM* b )
{ BN_mod_sub( r, a, b, T_order(), T_ctx() ); return r; }
BIGNUM* Bp_mod_mul( BIGNUM* r, const BIGNUM* a, const BIGNUM* b )
{ BN_mod_mul( r, a, b, T_order(), T_ctx() ); return r; }
}

static BIGNUM* Bp_scalar( const std::string& label )
{
   BIGNUM* b = T_scalar( label );
   if( BN_is_zero( b ) ) BN_set_word( b, 1 );
   return b;
}

static bool Bp_point_mul( EC_POINT* r, const EC_POINT* p, const BIGNUM* s )
{
   return EC_POINT_mul( (EC_GROUP*)T_group(), r, nullptr, p, s, T_ctx() ) == 1;
}
static bool Bp_base_mul( EC_POINT* r, const BIGNUM* s )
{
   return EC_POINT_mul( (EC_GROUP*)T_group(), r, s, nullptr, nullptr, T_ctx() ) == 1;
}
static bool Bp_add( EC_POINT* r, const EC_POINT* a, const EC_POINT* b )
{
   return EC_POINT_add( (EC_GROUP*)T_group(), r, a, b, T_ctx() ) == 1;
}

static BIGNUM* Bp_hash_scalar( const std::string& domain,
                               const std::vector<std::vector<unsigned char>>& items )
{
   fc::sha256 h = stealth_bp_hash( domain, items );
   BIGNUM* b = BN_new();
   BN_bin2bn( (const unsigned char*)h.data(), 32, b );
   return b; // already reduced mod n by stealth_bp_hash
}

static std::vector<unsigned char> Bp_bytes33( EC_POINT* p, bool& ok )
{
   std::vector<unsigned char> out( 33 );
   size_t len = EC_POINT_point2oct( T_group(), p, POINT_CONVERSION_COMPRESSED,
                                    out.data(), out.size(), nullptr );
   if( len != 33 ) { ok = false; return {}; }
   return out;
}

static void Bp_bin32( unsigned char out[32], const BIGNUM* b )
{
   BN_bn2binpad( b, out, 32 );
}

std::vector<char> T_bp_prove_attempt( const fc::ecc::commitment_type& C,
                                      const fc::sha256& blind, uint64_t value,
                                      int attempt, bool chained )
{
   const size_t N = 64, MN = 64, ROUNDS = 6;
   std::string tag = "|try" + std::to_string( attempt );
   bool ok = true;

   // Scalars gamma (blind mod n) and bit vectors aL/aR.
   BIGNUM* gamma = T_bn( blind );
   std::vector<BIGNUM*> aL( MN ), aR( MN );
   for( size_t i = 0; i < MN; ++i )
   {
      aL[i] = BN_new(); aR[i] = BN_new();
      if( ( value >> i ) & 1ULL ) BN_set_word( aL[i], 1 );
      BIGNUM* one = BN_new(); BN_set_word( one, 1 );
      BN_mod_sub( aR[i], aL[i], one, T_order(), T_ctx() );
      BN_free( one );
   }

   // Generators.
   EC_POINT* G0 = T_open( stealth_G_point() );
   EC_POINT* H0 = T_open( stealth_H_point() );
   std::vector<EC_POINT*> Gv( MN ), Hv( MN );
   for( size_t i = 0; i < MN; ++i )
   {
      Gv[i] = T_open( stealth_BP_G( i ) );
      Hv[i] = T_open( stealth_BP_H( i ) );
   }
   std::vector<unsigned char> Vb( C.begin(), C.end() );

   // A = sum(aL*G + aR*H) + alpha*G.
   BIGNUM* alpha = Bp_scalar( "g1b-bp-alpha" + tag );
   EC_POINT* A = EC_POINT_new( T_group() );
   EC_POINT* T = EC_POINT_new( T_group() );
   EC_POINT* U = EC_POINT_new( T_group() );
   EC_POINT_set_to_infinity( T_group(), A );
   for( size_t i = 0; i < MN && ok; ++i )
   {
      ok &= ( Bp_point_mul( T, Gv[i], aL[i] ) && Bp_point_mul( U, Hv[i], aR[i] ) &&
              Bp_add( T, T, U ) && Bp_add( A, A, T ) );
   }
   EC_POINT* At = EC_POINT_new( T_group() );
   ok &= ( Bp_base_mul( At, alpha ) && Bp_add( A, A, At ) );
   std::vector<unsigned char> Ab = Bp_bytes33( A, ok );
   if( !ok ) return {};

   // Challenges y, z.
   BIGNUM* y = Bp_hash_scalar( "G1BPy", { Vb, Ab } );
   if( BN_is_zero( y ) ) return {};
   unsigned char yb[32]; Bp_bin32( yb, y );
    BIGNUM* z = Bp_hash_scalar( "G1BPz", { std::vector<unsigned char>( yb, yb + 32 ) } );
    if( BN_is_zero( z ) ) return {};
    BIGNUM* z2 = BN_new(); Bp_mod_mul( z2, z, z );
    // R9C chained transcript (S1-style): state_0 is the z bytes (z binds
    // y binds V||A, so the seed binds the full statement). Flat mode
    // (chained==false) keeps the pre-R9C transcript — H("G1BPe"||points)
    // with no chaining — as a frozen reference: its proofs MUST reject
    // under the chained verifier (r9c_flat_transcript_rejects pins the
    // protocol break). Flat mode exists ONLY for that pin, never for
    // consensus-bound proofs.
    unsigned char zb0[32]; Bp_bin32( zb0, z );
    std::vector<unsigned char> tstate( zb0, zb0 + 32 );

   // d[i] = z^2 * 2^i; y_powers[0..MN+1].
   std::vector<BIGNUM*> d( MN ), ypw( MN + 2 );
   for( size_t i = 0; i < MN; ++i ) d[i] = BN_new();
   for( size_t i = 0; i < MN + 2; ++i ) ypw[i] = BN_new();
   BN_copy( d[0], z2 );
   BIGNUM* two = BN_new(); BN_set_word( two, 2 );
   for( size_t i = 1; i < MN; ++i ) Bp_mod_mul( d[i], d[i-1], two );
   BN_set_word( ypw[0], 1 );
   for( size_t i = 1; i < MN + 2; ++i ) Bp_mod_mul( ypw[i], ypw[i-1], y );
   BN_free( two );

   // aL1 = aL - z; aR1 = aR + z + d[i]*y^{MN-i}.
   std::vector<BIGNUM*> aL1( MN ), aR1( MN );
   for( size_t i = 0; i < MN; ++i )
   {
      aL1[i] = BN_new(); aR1[i] = BN_new();
      Bp_mod_sub( aL1[i], aL[i], z );
      BIGNUM* t = BN_new();
      Bp_mod_mul( t, d[i], ypw[MN-i] );
      Bp_mod_add( aR1[i], aR[i], z );
      Bp_mod_add( aR1[i], aR1[i], t );
      BN_free( t );
   }

   // alpha1 = alpha + z^2 * y^{MN+1} * gamma.
   BIGNUM* alpha1 = BN_new();
   {
      BIGNUM* t = BN_new();
      Bp_mod_mul( t, z2, ypw[MN+1] );
      Bp_mod_mul( t, t, gamma );
      Bp_mod_add( alpha1, alpha, t );
      BN_free( t );
   }

   // Fold state.
   std::vector<EC_POINT*> Gp = Gv, Hp = Hv;
   std::vector<BIGNUM*> ap = aL1, bp = aR1;
   BIGNUM* yinv = BN_new();
   if( !BN_mod_inverse( yinv, y, T_order(), T_ctx() ) ) return {};
   std::vector<BIGNUM*> yinvpw( MN );
   for( size_t i = 0; i < MN; ++i ) yinvpw[i] = BN_new();
   BN_set_word( yinvpw[0], 1 );
   for( size_t i = 1; i < MN; ++i ) Bp_mod_mul( yinvpw[i], yinvpw[i-1], yinv );

   std::vector<std::vector<unsigned char>> Lb( ROUNDS ), Rb( ROUNDS );
   size_t nprime = MN;
   int round = 0;
   std::vector<BIGNUM*> ch( ROUNDS );
   for( size_t j = 0; j < ROUNDS; ++j ) ch[j] = BN_new();

   auto wip = [&]( const std::vector<BIGNUM*>& a, size_t a0,
                   const std::vector<BIGNUM*>& b, size_t b0,
                   size_t n, const BIGNUM* yy ) {
      BIGNUM* res = BN_new(); BN_zero( res );
      BIGNUM* yp = BN_new(); BN_set_word( yp, 1 );
      BIGNUM* t = BN_new();
      for( size_t i = 0; i < n; ++i )
      {
         Bp_mod_mul( yp, yp, yy );
         Bp_mod_mul( t, a[a0+i], b[b0+i] );
         Bp_mod_mul( t, t, yp );
         Bp_mod_add( res, res, t );
      }
      BN_free( yp ); BN_free( t );
      return res;
   };

   while( nprime > 1 && ok )
   {
      nprime /= 2;
      // cL = <a_lo, b_hi>_y ; cR = <a_hi * y^n, b_lo>_y.
      BIGNUM* cL = wip( ap, 0, bp, nprime, nprime, y );
      std::vector<BIGNUM*> ahi( nprime );
      for( size_t i = 0; i < nprime; ++i )
      {
         ahi[i] = BN_new();
         Bp_mod_mul( ahi[i], ap[nprime+i], ypw[nprime] );
      }
      BIGNUM* cR = wip( ahi, 0, bp, 0, nprime, y );
      for( auto x : ahi ) BN_free( x );
      BIGNUM* dL = Bp_scalar( "g1b-bp-dL|r" + std::to_string( round ) + tag );
      BIGNUM* dR = Bp_scalar( "g1b-bp-dR|r" + std::to_string( round ) + tag );

      // L = sum(a_lo*yinv^n * G_hi + b_hi * H_lo) + cL*H + dL*G.
      EC_POINT* L = EC_POINT_new( T_group() );
      EC_POINT_set_to_infinity( T_group(), L );
      for( size_t i = 0; i < nprime && ok; ++i )
      {
         BIGNUM* t = BN_new();
         Bp_mod_mul( t, ap[i], yinvpw[nprime] );
         ok &= ( Bp_point_mul( T, Gp[nprime+i], t ) && Bp_add( L, L, T ) &&
                 Bp_point_mul( T, Hp[i], bp[nprime+i] ) && Bp_add( L, L, T ) );
         BN_free( t );
      }
      ok &= ( Bp_point_mul( T, H0, cL ) && Bp_add( L, L, T ) &&
              Bp_base_mul( T, dL ) && Bp_add( L, L, T ) );
      // R = sum(a_hi*y^n * G_lo + b_lo * H_hi) + cR*H + dR*G.
      EC_POINT* R = EC_POINT_new( T_group() );
      EC_POINT_set_to_infinity( T_group(), R );
      for( size_t i = 0; i < nprime && ok; ++i )
      {
         BIGNUM* t = BN_new();
         Bp_mod_mul( t, ap[nprime+i], ypw[nprime] );
         ok &= ( Bp_point_mul( T, Gp[i], t ) && Bp_add( R, R, T ) &&
                 Bp_point_mul( T, Hp[nprime+i], bp[i] ) && Bp_add( R, R, T ) );
         BN_free( t );
      }
      ok &= ( Bp_point_mul( T, H0, cR ) && Bp_add( R, R, T ) &&
              Bp_base_mul( T, dR ) && Bp_add( R, R, T ) );
      Lb[round] = Bp_bytes33( L, ok );
      Rb[round] = Bp_bytes33( R, ok );
      if( !ok ) return {};

      BIGNUM* challenge = chained
         ? Bp_hash_scalar( "G1BPr", { tstate, Lb[round], Rb[round] } )
         : Bp_hash_scalar( "G1BPe", { Lb[round], Rb[round] } );
      if( BN_is_zero( challenge ) ) return {};
      if( chained )
      {
         unsigned char cb[32]; Bp_bin32( cb, challenge );
         tstate.assign( cb, cb + 32 );
      }
      BIGNUM* challenge_inv = BN_new();
      if( !BN_mod_inverse( challenge_inv, challenge, T_order(), T_ctx() ) ) return {};
      ch[round] = challenge;

      // Fold generators and vectors.
      BIGNUM* gt = BN_new();
      Bp_mod_mul( gt, yinvpw[nprime], challenge );
      std::vector<EC_POINT*> G2( nprime ), H2( nprime );
      for( size_t i = 0; i < nprime && ok; ++i )
      {
         G2[i] = EC_POINT_new( T_group() );
         H2[i] = EC_POINT_new( T_group() );
         ok &= ( Bp_point_mul( T, Gp[i], challenge_inv ) &&
                 Bp_point_mul( U, Gp[nprime+i], gt ) && Bp_add( G2[i], T, U ) &&
                 Bp_point_mul( T, Hp[i], challenge ) &&
                 Bp_point_mul( U, Hp[nprime+i], challenge_inv ) && Bp_add( H2[i], T, U ) );
      }
      if( !ok ) return {};
      BIGNUM* at = BN_new();
      Bp_mod_mul( at, challenge_inv, ypw[nprime] );
      std::vector<BIGNUM*> ap2( nprime ), bp2( nprime );
      for( size_t i = 0; i < nprime; ++i )
      {
         ap2[i] = BN_new(); bp2[i] = BN_new();
         BIGNUM* t1 = BN_new(), *t2 = BN_new();
         Bp_mod_mul( t1, ap[i], challenge );
         Bp_mod_mul( t2, ap[nprime+i], at );
         Bp_mod_add( ap2[i], t1, t2 );
         Bp_mod_mul( t1, bp[i], challenge_inv );
         Bp_mod_mul( t2, bp[nprime+i], challenge );
         Bp_mod_add( bp2[i], t1, t2 );
         BN_free( t1 ); BN_free( t2 );
      }
      // alpha1 += dL*ch^2 + dR*chi^2.
      {
         BIGNUM* e2 = BN_new(), *ei2 = BN_new(), *t = BN_new();
         Bp_mod_mul( e2, challenge, challenge );
         Bp_mod_mul( ei2, challenge_inv, challenge_inv );
         Bp_mod_mul( t, dL, e2 );
         Bp_mod_add( alpha1, alpha1, t );
         Bp_mod_mul( t, dR, ei2 );
         Bp_mod_add( alpha1, alpha1, t );
         BN_free( e2 ); BN_free( ei2 ); BN_free( t );
      }
      Gp = G2; Hp = H2; ap = ap2; bp = bp2;
      BN_free( cL ); BN_free( cR ); BN_free( dL ); BN_free( dR );
      BN_free( gt ); BN_free( at ); BN_free( challenge_inv );
      EC_POINT_free( L ); EC_POINT_free( R );
      ++round;
   }
   if( !ok || nprime != 1 ) return {};

   // Final round: r, s, d_, eta.
   BIGNUM* r = Bp_scalar( "g1b-bp-r" + tag );
   BIGNUM* s = Bp_scalar( "g1b-bp-s" + tag );
   BIGNUM* d_ = Bp_scalar( "g1b-bp-d" + tag );
   BIGNUM* eta = Bp_scalar( "g1b-bp-eta" + tag );
   // A1 = r*G' + s*H' + d_*G + (r*y*b' + s*y*a')*H.
   EC_POINT* A1 = EC_POINT_new( T_group() );
   EC_POINT_set_to_infinity( T_group(), A1 );
   {
      BIGNUM* t1 = BN_new(), *t2 = BN_new(), *t3 = BN_new();
      Bp_mod_mul( t1, r, y ); Bp_mod_mul( t1, t1, bp[0] );
      Bp_mod_mul( t2, s, y ); Bp_mod_mul( t2, t2, ap[0] );
      Bp_mod_add( t3, t1, t2 );
      ok &= ( Bp_point_mul( T, Gp[0], r ) && Bp_add( A1, A1, T ) &&
              Bp_point_mul( T, Hp[0], s ) && Bp_add( A1, A1, T ) &&
              Bp_base_mul( T, d_ ) && Bp_add( A1, A1, T ) &&
              Bp_point_mul( T, H0, t3 ) && Bp_add( A1, A1, T ) );
      BN_free( t1 ); BN_free( t2 ); BN_free( t3 );
   }
   // B = eta*G + (r*y*s)*H.
   EC_POINT* B = EC_POINT_new( T_group() );
   EC_POINT_set_to_infinity( T_group(), B );
   {
      BIGNUM* t = BN_new();
      Bp_mod_mul( t, r, y ); Bp_mod_mul( t, t, s );
      ok &= ( Bp_base_mul( T, eta ) && Bp_add( B, B, T ) &&
              Bp_point_mul( T, H0, t ) && Bp_add( B, B, T ) );
      BN_free( t );
   }
   std::vector<unsigned char> A1b = Bp_bytes33( A1, ok );
   std::vector<unsigned char> Bb = Bp_bytes33( B, ok );
   if( !ok ) return {};
    BIGNUM* e = chained
       ? Bp_hash_scalar( "G1BPf", { tstate, A1b, Bb } )
       : Bp_hash_scalar( "G1BPe", { A1b, Bb } );
    if( BN_is_zero( e ) ) return {};
   BIGNUM* e2 = BN_new(); Bp_mod_mul( e2, e, e );
   BIGNUM* r1 = BN_new(), *s1 = BN_new(), *d1 = BN_new();
   {
      BIGNUM* t = BN_new();
      Bp_mod_mul( t, ap[0], e ); Bp_mod_add( r1, t, r );
      Bp_mod_mul( t, bp[0], e ); Bp_mod_add( s1, t, s );
      Bp_mod_mul( t, d_, e ); Bp_mod_add( d1, t, eta );
      Bp_mod_mul( t, alpha1, e2 ); Bp_mod_add( d1, d1, t );
      BN_free( t );
   }
   // Verifier requires strict-canonical nonzero responses.
   if( BN_is_zero( r1 ) || BN_is_zero( s1 ) || BN_is_zero( d1 ) ) return {};

   // Wire: m || A || A1 || B || r1 || s1 || d1 || L/R pairs.
   std::vector<char> proof;
   proof.push_back( (char)1 );
   proof.insert( proof.end(), Ab.begin(), Ab.end() );
   proof.insert( proof.end(), A1b.begin(), A1b.end() );
   proof.insert( proof.end(), Bb.begin(), Bb.end() );
   unsigned char buf[32];
   Bp_bin32( buf, r1 ); proof.insert( proof.end(), (char*)buf, (char*)buf + 32 );
   Bp_bin32( buf, s1 ); proof.insert( proof.end(), (char*)buf, (char*)buf + 32 );
   Bp_bin32( buf, d1 ); proof.insert( proof.end(), (char*)buf, (char*)buf + 32 );
   for( size_t j = 0; j < ROUNDS; ++j )
   {
      proof.insert( proof.end(), Lb[j].begin(), Lb[j].end() );
      proof.insert( proof.end(), Rb[j].begin(), Rb[j].end() );
   }
   return proof;
}

std::vector<char> T_bp_prove( const fc::ecc::commitment_type& C,
                              const fc::sha256& blind, uint64_t value )
{
   for( int attempt = 0; attempt < 100; ++attempt )
   {
      std::vector<char> p = T_bp_prove_attempt( C, blind, value, attempt, true );
      if( !p.empty() )
         return p;
   }
   BOOST_REQUIRE_MESSAGE( false, "T_bp_prove failed after 100 attempts" );
   return {};
}

// Pre-R9C flat-transcript reference prover (frozen): every challenge is
// H("G1BPe"||points) with no chaining. Its proofs MUST reject under the
// chained consensus verifier (r9c_flat_transcript_rejects). Test-only,
// never consensus-bound.
std::vector<char> T_bp_prove_flat( const fc::ecc::commitment_type& C,
                                   const fc::sha256& blind, uint64_t value )
{
   for( int attempt = 0; attempt < 100; ++attempt )
   {
      std::vector<char> p = T_bp_prove_attempt( C, blind, value, attempt, false );
      if( !p.empty() )
         return p;
   }
   BOOST_REQUIRE_MESSAGE( false, "T_bp_prove_flat failed after 100 attempts" );
   return {};
}

} // anonymous namespace

// G1c parity economics (BSIP-2 §2): pre-parity (G1b-era) cases price blind
// fee schedules at zero and pay zero fees, so every blind op carries a full
// cost-anchor gap (1M CORE per transfer_to_blind output under the pinned
// anchor). Seeding the per-asset parity pool to `need` (top-up style, so
// exact sizing is unnecessary) keeps those cases on the subsidized path —
// they exercise their cryptographic assertions instead of floating to cost.
// The float rule itself is covered by the parity_* cases below. Seeding is
// supply-neutral (fee legs mirror pay_market_fees exactly: the nominal never
// moves inside pay_market_fees, so only the fee amount leaves the payer).
// Task 7 legacy gate (BSIP-2 §2, GP-01/GP-02): the parity fee-share routes
// only for assets whose issuer set additional_asset_options
// .parity_fee_share_enabled (absent == false, the state of every legacy
// asset). Cases below fund the pool through the real routing leg
// (pay_market_fees / stealth_parity_route_fee), so they opt the fee asset
// in first. Test-setup direct write (same standing as the fee-scale pins
// above — CORE's issuer is the committee account, which has no test key):
// the issuer-signed production opt-in path, including its pre-fork
// refusal, is pinned separately by g1_parity_legacy_tests.
static void g1c_opt_in_parity( database& db, asset_id_type aid )
{
   const asset_object& a = aid( db );
   const auto& e = a.options.extensions.value.parity_fee_share_enabled;
   if( e.valid() && *e )
      return;
   db.modify( a, []( asset_object& o ) {
      o.options.extensions.value.parity_fee_share_enabled = true;
   } );
}

static void g1c_seed_pool( database& db, account_id_type payer,
                           const asset_object& core, int64_t need )
{
   // Task 7 legacy gate: pool funding routes only for opted-in assets.
   g1c_opt_in_parity( db, core.get_id() );
   const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
   auto itr = st.parity_pool.find( core.get_id() );
   share_type have = ( itr == st.parity_pool.end() ) ? share_type( 0 ) : itr->second;
   if( have.value >= need )
      return;
   int64_t fee = ( need - have.value ) * 20; // 5% routes to the pool, exact
   db.adjust_balance( payer, core.amount( -fee ) );
   db.pay_market_fees( nullptr, core, core.amount( fee ), true, core.amount( fee ) );
}

// Seed helper: fund parity_pool[UIA] through the real Task-7 funding path
// (opt-in + pay_market_fees routing at the 5% share, mirroring
// g1c_seed_pool) so the builder's parity leg can clear the float rule.
//
// DURABILITY (db_block.cpp:423). This helper performs DIRECT state writes ONLY
// and must be called on SEALED state with no push in between: PUSH_TX opens
// _pending_tx_session, and any direct modify made while a session is open is
// discarded when generate_block resets it. The earlier version of this helper
// called f.issue_uia() (a PUSH_TX) before adjusting balances, so its opt-in,
// debit and market-fee routing all landed inside that session and were silently
// wiped — the seeding never took effect, which only went unnoticed while op109
// had no float rule at all. Callers must top the payer's UIA balance through a
// real transaction BEFORE calling this.
static void T_seed_pool_uia( database_fixture& f, const account_object& payer,
                             const asset_object& uia, int64_t need )
{
   database& db = f.db;
   g1c_opt_in_parity( db, uia.get_id() );
   const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
   auto itr = st.parity_pool.find( uia.get_id() );
   share_type have = ( itr == st.parity_pool.end() ) ? share_type( 0 ) : itr->second;
   if( have.value >= need )
      return;
   int64_t fee = ( need - have.value ) * 20; // 5% routes to the pool, exact
   BOOST_REQUIRE_MESSAGE(
      db.get_balance( payer.get_id(), uia.get_id() ).amount.value >= fee,
      "T_seed_pool_uia: payer lacks the UIA balance to seed the "
      "parity pool — issue it in a real transaction first" );
   db.adjust_balance( payer.get_id(), uia.amount( -fee ) );
   db.pay_market_fees( nullptr, uia, uia.amount( fee ), true, uia.amount( fee ) );
   const auto& st2 = *db.get_index_type<stealth_status_index>().indices().begin();
   auto itr2 = st2.parity_pool.find( uia.get_id() );
   BOOST_REQUIRE( itr2 != st2.parity_pool.end() );
   BOOST_REQUIRE( itr2->second.value >= need );
}


// Task 3 (flag retirement): give a post-fork-created balance grandfathered
// status so the legacy op40/op41 legs still accept it. Mirrors exactly what
// a pre-fork balance looks like: created_block == 0 (never counted — back
// out the +1 the post-fork create added). Supply/shadow untouched, so
// verify_asset_supplies and the shadow reconciliation cannot see it.
// CALL ONLY ON SEALED DEPOSITS: _generate_block throws away the pending
// session and re-applies pending txs (db_block.cpp), wiping direct modifies
// to not-yet-sealed objects (both the created_block zeroing AND the counter
// back-out). Pattern: PUSH_TX, generate_block, THEN T_grandfather.
static void T_grandfather( database& db, asset_id_type asset,
                           const fc::ecc::commitment_type& c )
{
   const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
   auto itr = bbi.find( c );
   BOOST_REQUIRE( itr != bbi.end() );
   db.modify( *itr, []( blinded_balance_object& b ) { b.created_block = 0; } );
   stealth_pool_count_add( db, asset, -1 );
}

// Task 3 (flag retirement): replacement for T_r15_mark_decoyed. The flag
// conflated "was a ring member" with "was really spent"; under nullifier
// semantics those are distinct, and the recovery guard is about the second.
// Inserts the nullifiers the real spend would have left (both version legs,
// mirroring the ring do_apply write). Callers pass the commitment's REAL
// I1/I2 from the proof helper. Links the single production identity
// (nullifier_key, stealth_evaluator.hpp) — never duplicated.
static void T_r15_nullify( database& db,
                           const fc::ecc::commitment_type& I1,
                           const fc::ecc::commitment_type& I2 )
{
   // nullifier_key takes const std::vector<char>&; commitment_type does NOT
   // convert implicitly. Convert explicitly, mirroring the turnstile.
   const std::vector<char> i1( I1.begin(), I1.end() );
   const std::vector<char> i2( I2.begin(), I2.end() );
   db.create<stealth_nullifier_object>( [&]( stealth_nullifier_object& n ) {
      n.key_image = nullifier_key( i1 ); n.proof_version = GRAPHENE_STEALTH_PROOF_V1;
      n.created = db.head_block_time();
   } );
   db.create<stealth_nullifier_object>( [&]( stealth_nullifier_object& n ) {
      n.key_image = nullifier_key( i2 ); n.proof_version = GRAPHENE_STEALTH_PROOF_V2;
      n.created = db.head_block_time();
   } );
}

BOOST_FIXTURE_TEST_SUITE( g1_stealth_tests, database_fixture )

/// V-03 (audit-round-2): every stealth operation must be refused before the
/// hardfork, or a node running this code could produce a block that a node
/// running the previous release cannot validate. The shape below passes
/// validate() (11 distinct members, 33-byte image, well-sized sig, V1 output
/// with proof), so the refusal proves the consensus gate in do_evaluate fires
/// first (stealth_evaluator.cpp:324), not a shape check.
BOOST_AUTO_TEST_CASE( stealth_ops_are_refused_before_the_hardfork )
{ try {
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);

   stealth_transfer_operation op;
   op.fee = core.amount( 0 );
   op.asset_id = core.get_id();
   op.proof_version = GRAPHENE_STEALTH_PROOF_V1;
   stealth_ring_input in;
   for( int i = 0; i < 11; ++i )
   {
      std::vector<unsigned char> raw( 33, 0 );
      raw[32] = char( i + 1 );
      in.ring.push_back( T_commitment( raw ) );
   }
   in.key_image.assign( 33, 0 );
   in.key_image[0] = 2;
   in.ring_sig.assign( 32 + 96 * 11, 0 );
   // Dummy alt linkage (rejected at the pre-fork hardfork gate, never verified).
   in.alt_key_image.assign( 33, 0 );
   in.alt_ring_sig.assign( 32 + 96 * 11, 0 );
   op.inputs = { in };
   stealth_blind_output out;
   out.commitment = T_commitment( std::vector<unsigned char>( 33, 1 ) );
   out.range_proof.assign( 64, 0 );
   out.owner = authority( 1, dan_id, 1 );
   op.outputs = { out };
   BOOST_CHECK_NO_THROW( op.validate() );

   signed_transaction tx;
   tx.operations.push_back( op );
   // Fee set on the funded path so the refusal reaches the consensus gate
   // (H1-03: with fee 0 the tx dies in insufficient_fee and deleting the
   // hardfork gate stays green).
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   // No signatures: temp fee payer (threshold 0) + ring authorization.
   try
   {
      PUSH_TX( db, tx );
      BOOST_FAIL( "pre-fork stealth_transfer was ACCEPTED" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "stealth hardfork" ) != std::string::npos,
                           e.to_detail_string() );
   }
} FC_CAPTURE_AND_RETHROW() }

// Task 6 (R7 C-10): the ring-scheme migration slot fails closed. An unknown
// scheme refuses at relay-side validate() AND at the consensus gate
// (proposal-embedded ops bypass validate — dispatch directly to pin it).
BOOST_AUTO_TEST_CASE( unknown_ring_scheme_refused )
{ try {
   auto make_op = []( uint8_t scheme ) {
      stealth_transfer_operation op;
      op.fee = asset( 0, asset_id_type() );
      op.asset_id = asset_id_type();
      op.proof_version = GRAPHENE_STEALTH_PROOF_V1;
      stealth_ring_input in;
      for( int i = 0; i < 16; ++i )
      {
         std::vector<unsigned char> raw( 33, 0 );
         raw[32] = char( i + 1 );
         in.ring.push_back( T_commitment( raw ) );
      }
      in.key_image.assign( 33, 2 );
      in.ring_sig.assign( 32 + 96 * 16, 0 );
      in.alt_key_image.assign( 33, 3 );
      in.alt_ring_sig.assign( 32 + 96 * 16, 0 );
      in.pseudo_output = in.ring[0];
      in.ring_scheme = scheme;
      op.inputs = { in };
      // Real V1 output (valid range proof): output checks run before the
      // per-input scheme gate, so a fake proof would mask the assertion
      // under test.
      stealth_blind_output out;
      auto Bo = T_blind_secret( "t6-scheme-out" );
      auto No = T_secret( "t6-scheme-nout" );
      out.commitment = fc::ecc::blind( Bo, 990 );
      out.range_proof = fc::ecc::range_proof_sign( 0, out.commitment, Bo, No, 0, 0, 990 );
      auto ok = fc::ecc::private_key::generate();
      out.owner = authority( 1, public_key_type( ok.get_public_key() ), 1 );
      op.outputs = { out };
      return op;
   };
   // Relay side: unknown scheme fails validate.
   {
      auto bad = make_op( 99 );
      BOOST_CHECK_THROW( bad.validate(), fc::exception );
      try { bad.validate(); BOOST_FAIL( "unknown scheme must fail validate" ); }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "ring scheme" ) != std::string::npos,
                              e.to_detail_string() );
      }
      // The genesis scheme passes wire-shape validate (consensus gates
      // below still refuse the fake members — shape is not soundness).
      BOOST_CHECK_NO_THROW( make_op( GRAPHENE_STEALTH_RING_SCHEME_V1 ).validate() );
   }
   // Consensus side: post-fork direct dispatch (validate bypassed) fails at
   // the scheme gate — before membership/policy/signature math. The pool
   // floor is satisfied by direct counter setup, and the fee gate by a
   // seeded parity pool (test-only surgery isolating the gate under test:
   // neither depth nor fees are what this pins; both have their own tests).
   // The scheme assert sits before membership, so fake members never matter.
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), dan, core.amount( 400000000 ) );
   generate_block();
   g1c_seed_pool( db, dan_id, core, 5000000 );
   {
      const auto& st = db.get_index_type<stealth_status_index>().indices().begin();
      db.modify( *st, [&]( stealth_status_object& o ) {
         o.unspent_blind_count[ core.get_id() ] = 16;
      } );
   }
   {
      transaction_evaluation_state es( &db );
      try
      {
         db.apply_operation( es, operation( make_op( 99 ) ) );
         BOOST_FAIL( "unknown ring scheme must fail closed in do_evaluate" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Unknown ring scheme" )
                               != std::string::npos, e.to_detail_string() );
      }
   }
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( ring_vectors_11_and_16 )
{ try {
   // Golden vectors: fixed scalars, no randomness. The consensus verifier
   // must accept; any single-byte tamper must reject. The same vectors are
   // replayed by tooling/g1_ring_xcheck.py (independent pure-Python model).
   for( size_t n : { (size_t)11, (size_t)16 } )
   {
      std::vector<std::vector<unsigned char>> Q;
      std::vector<BIGNUM*> blinds;
      for( size_t i = 0; i < n; ++i )
      {
         BIGNUM* b = T_scalar( "g1b-vec-b|" + std::to_string( n ) + "|" + std::to_string( i ) );
         blinds.push_back( b );
         Q.push_back( T_commit( b, 1000 + i ) );
      }
      size_t s = 3;
      BIGNUM* bp = T_scalar( "g1b3-vec-bp|" + std::to_string( n ) );
      std::string msg32( (const char*)fc::sha256::hash(
         "g1b-golden-msg-ring-" + std::to_string( n ) ).data(), 32 );
      stealth_ring_input rin = T_make_ring_input( GRAPHENE_STEALTH_PROOF_V1,
         Q, s, blinds[s], 1003, bp, msg32 );
      BOOST_REQUIRE_EQUAL( rin.ring_sig.size(), 32 + 96*n );
      // Pseudo-output binds the real member's value (1003) under a fresh blind.
      {
         auto Pv = T_commit( bp, 1003 );
         BOOST_CHECK( std::vector<unsigned char>( rin.pseudo_output.begin(),
                      rin.pseudo_output.end() ) == Pv );
      }
      std::string err;
      BOOST_CHECK_MESSAGE( stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V1, rin, msg32, err ),
                           "ring-" << n << " golden vector must verify: " << err );
      stealth_ring_input bad = rin;
      bad.ring_sig[10] ^= 0x01;
      BOOST_CHECK_MESSAGE( !stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V1, bad, msg32, err ),
                           "ring-" << n << " tampered sig must reject" );
      bad = rin;
      bad.ring_sig[32 + 64*n + 5] ^= 0x01; // rd-response tamper (binding leg)
      BOOST_CHECK_MESSAGE( !stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V1, bad, msg32, err ),
                           "ring-" << n << " tampered binding response must reject" );
      bad = rin;
      bad.key_image[5] ^= 0x02;
      BOOST_CHECK_MESSAGE( !stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V1, bad, msg32, err ),
                           "ring-" << n << " tampered image must reject" );
      bad = rin;
      bad.pseudo_output[7] ^= 0x04; // inflated/detached pseudo must reject
      BOOST_CHECK_MESSAGE( !stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V1, bad, msg32, err ),
                           "ring-" << n << " tampered pseudo must reject" );
      bad = rin;
      std::string msg2 = msg32; msg2[0] ^= 0x04;
      BOOST_CHECK_MESSAGE( !stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V1, bad, msg2, err ),
                           "ring-" << n << " wrong message must reject" );
      BN_free( bp );
      for( auto b : blinds ) BN_free( b );
   }
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( generator_provenance_vectors )
{ try {
   // H is consensus-critical: every legacy fc::blind commitment AND every
   // new stealth commitment uses it as the value base. It is pinned to a
   // golden vector (independent Python model: tooling/g1_gen_vectors.py) so
   // any backend/seed change breaks loudly here instead of forking the chain.
   std::vector<unsigned char> H = stealth_H_point();
   BOOST_REQUIRE_EQUAL( H.size(), 33u );
   // Golden: S2 secp256k1-zkp generator H, compressed.
   // Provenance: src/modules/generator/main_impl.h @ b247e1ec
   // (secp256k1_generator_const_h). The quoted Sage NUMS one-liner in that
   // file does NOT reproduce (its G_bytes hex carries a typo'd Y), so H's
   // authority is deployment history + on-curve + blind-equality below.
   const std::string H_golden_hex = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
   std::vector<unsigned char> H_golden;
   for( size_t i = 0; i < H_golden_hex.size(); i += 2 )
      H_golden.push_back( (unsigned char)std::stoul( H_golden_hex.substr( i, 2 ), nullptr, 16 ) );
   BOOST_CHECK_MESSAGE( H == H_golden,
      "H generator does not match pinned S2 golden — backend changed" );
   // Determinism: re-derivation gives the same point on every node.
   BOOST_CHECK( stealth_H_point() == H );
   // J bases: version-domain separated, pinned goldens from the same model.
   auto expect_hex = []( const std::string& hex ) {
      std::vector<unsigned char> v;
      for( size_t i = 0; i < hex.size(); i += 2 )
         v.push_back( (unsigned char)std::stoul( hex.substr( i, 2 ), nullptr, 16 ) );
      return v;
   };
   BOOST_CHECK( stealth_J1_point( 1 ) == expect_hex( "02386167f17be5180b1c5588b4a2897a04f0a15dd553eb54219646ad44d2689801" ) );
   BOOST_CHECK( stealth_J2_point( 1 ) == expect_hex( "03bd0bcdc62437761ac7746f9171670c2252af994f8e04758694b3ee3f45bd9299" ) );
   BOOST_CHECK( stealth_J1_point( 2 ) == expect_hex( "026dc9d657123cb196f96828a893fddb08352e4f99dfe7920b6a87e4c1ae60aa0b" ) );
   BOOST_CHECK( stealth_J2_point( 2 ) == expect_hex( "03ac6eab33dc31ff12f4c93842e117647621c7d4d5ae4ab92ea83374a59ba6e335" ) );
   // BP+ vector generators: full 64+64 golden pin (F-04, R9A) — any
   // generator change fails loudly here instead of surfacing as liveness
   // ("no honest proof verifies"). J/H pins above unchanged.
   BOOST_CHECK_EQUAL( stealth_BP_count(), 64u );
   // (R9B Minor-3: the old self-comparison determinism spot
   // BOOST_CHECK(G(0)==G(0)) is removed — a tautology. Determinism is pinned
   // properly by the golden loop below, which compares every Gi/Hi against
   // the model-generated vectors.)
// --- pasted from tooling/g1_gen_vectors.py --cpp ---
static const char* const BP_G_GOLDEN[64] = {
  "026b5fa2ac909d6f5dca68029ab3c9f59cbf6cf50404abde089bedff033fdc36e7",
  "036aa76ffe7b8ecd7df7cfea3a65c4a59fe484be287cba6f5b02d3f95d35762d92",
  "0206b18703b99da12608b32a04ee7823b1c38fe6c40b8472a231139949c9733640",
  "02a13ca1ebf03992207a8dffa23b56ba58f4aa782566ce337fc7133098a28c0b9d",
  "03cd1afd0d5796a7bbefb8283e46ba0cbf83613c971d7a08b3a168f0b835318cee",
  "037f8eba149d98c6d7e6af7fd88097d37e95eabffbd7129de96e93c54152e17b81",
  "02ed9f890d7c2903a8af96fcad74701be37fbb1d5c628c6281c57d850bfc07959e",
  "0371fba9809933f576286954bcf624a3ff15a35c3522773f110136b07a6703bf06",
  "0267487f0056d687344b931b4b29b45fe57eb52589d37db8ab985cab32a15f04fa",
  "029bb4d1b446e699e9e18edfb1b23cd0fbea2c0e0afa862c9843d8902ac84c25ad",
  "03aeb37e5d05c0cb1a1a3328b5dfeced1ff9c172f62a1e71016bf905a3234d17d1",
  "024831e3ad4916e3f3a824d896130f883880530440cc302d44e1abfea0dd2c23d9",
  "037367012acd3a583bad25e6391412074c5a8a2e149ff2bddf2711aa186f69a278",
  "035d35ccc2281bd9b986a32f61df8823c0d393ea379ab5b15512665484127745b2",
  "02a4ed968db68cccfdcfbded545a2c30cd48585cb4ca6ad9af9c7307e56c897a32",
  "0287674dcec197031d53a26368c4e2798c08169414dea91e85eeaab8e3ae63a422",
  "032827d36d94bf37dc1f7543994d70c7ea6afc2bfda907058d75993d030bb19afa",
  "025cc92bfc9f07de8ade1cf6305a10afa88587c2f7509122e247fbc99898cc6f7c",
  "03cdd60debc0ae817e3e7589bd482d9777b236c0499d285723971b1e004b662f57",
  "0238d73f87f24178971b28c3e01545696563b58910c820a57fc8ff4e90c44438f6",
  "02a1e8132197085415eb139dc1ef85f5511b81646ad7274e5e67342b5294c6b310",
  "02b7804145ba03aba94230dd7b9f2f595f50467c062babda8c2a3aefe05881a856",
  "033a90e5f2a7d576031ac0dc942a0b38b6d81b2fba157183dab5822c34d24c80d8",
  "020b457141ad015a620f365d3888f63e5781b0965d32463d65a669956997d7909a",
  "03722d9b1bd4db2dbfeaf735d68089da9f4a52e6b1e35011299c006bdb25716146",
  "023fc0f7ad35ae52bf3fd1bcdaf59e88c8e921142df52ce9fed0696f4583eced9f",
  "02802c94e98ab7a24bdb02f44971efb62b3f78fa20c6266bac12726fa33487177f",
  "02b18ebd34a448b2bd92244d0a4f8863dac620237d609cab3636b5dac666c8bbde",
  "03346a43f8f0772d8d85a782e2c5c825674fdef46f29cf60361a8bc381631e2ad2",
  "037fceb89ecc3a42be9574c59d9db79d1009410ac3298b4e90b706cbfa3297e643",
  "03398929bbe4de270b4994152ab9f808e69ad22706125988908f657f742f5939bd",
  "03ef401e97e5868628ad0a95d9ad5c3c73348cde68dc8ce982d6d45b984173dd63",
  "02105220abd990b0b7c34fc1a472a415fd5ea171efd0565c1a30830e55ae2c6d90",
  "023ba4a93cb44639c9e2b648e3e5a61447b4c943dadcaebba91bf84c011df3201d",
  "0397cb34c8558d55cdce31f1ee5a48952ac41ff25f0320eba5444714ec33c23e23",
  "020528bf2be887ce9a80df7ac7b954a87931a145b1dd299fab21ef7c94aa23dd3e",
  "0304832dba88f5d42f0e86152718e337f171f211562852a4374c890fe4822ccd97",
  "03710b57094341a71c01d7de1aa73d8929ada4526619cfd0b2a287f4dd40dbe8b0",
  "03dc931b60eb7e30c9787c3f219b41c5cdb867e2433a2f957ebc8a76b1cd924be3",
  "03501ab2e7472a0763b667b14367a1030a758a71ee75ccc058243c80f7b3140b03",
  "022bb2c14de247d10988c06d09a78b222cb1b9cf4c0630985a75d544971b9213be",
  "037820fc9c24b6665029340ea1088137ad90bd4a5d93cf868b025725a513ad2ca9",
  "0394ebe96f004f9d88639bbae0ea8632d70caeb4a517a9db8d7bdb78674cc3ab39",
  "02f2ac40568f9d56f7c23d242c31743e8927888a783cfdd6bb1a5dfeb80cb0962d",
  "0260e203a3f095a586c8dac22e2f3a7b49ca628a7d7dd19c1292640a20edd67d54",
  "020b179b6c8b235cbdde088e159ed0a31c01434e1dc529de13d749950955d5a9cc",
  "02328795cba20deef0a05e7e82ee9d71b6904637451034446814b14fb29d0ff1d5",
  "020ff82068280aea6c9c3d0152557fe2e6c229920138d44bfd3c5556e6902186f5",
  "03a7d14da7fb62ffea6ac580ca09fc2a56d70e966b61cdf433e9bead33d8ebaf6b",
  "03d7e8d30ab9acb5b41261a7d9089d42cb5b577a8cf8b71c0518a20be1cb2b2239",
  "0202c9ed61b9613d762484dad97a246497f58d63c4b14bf01217021e92f7a43a6d",
  "02c2880b5496b322cbbf29dbc9d419ddc9d705ed9011deb528128b2f211c4b22c5",
  "0365f7b8348d102c696f4185695ede4ed11d2e90ecdc458d04b3a860ab3dc29053",
  "02ebb8ebe1efcde59b60be88265b702ba4ab792a8ca693d92817ff3e90ea460985",
  "020c1888c9316b8e1c548c956c634aecdbc0f4174ff175201199d99d7e792cca8f",
  "025a4b74705c5945476762d00205143900f64896a3d8a5c72697b508c284d05574",
  "034fb8a91cc131ca17f3b5d3a716b6e3af77cf2c07f8ab51cf492e8d7f40582094",
  "0287e911d6d883559092f2af2e78293ff74a2f3652e6071728fe98b4e4b938512f",
  "03fdf1f13a87a452e193a2b00f1be6b36bff0fec7741ff7b62db1e172d8a8bb498",
  "022766836a8b1ecdb6f2a8e95c63d0b1263accd7c6c6e4fc5a9784ad35cfbfe225",
  "025d453a661af384608eab4a83d264fde2c7eb1e65417dfdec4992d93aa9eb2ebf",
  "02779f3b8283068d0aebe3019d45eba185c2f5d42a88204eec63a732f4a7dfe02e",
  "0235fec2d0a8fca62fe14f7eb0e49295ef52d004ba043dbc902c8b26754ac78732",
  "025a712d9ff10bb26d6e7b8c3bd35328e04719a3e7932e7fccf888fbe599e31e3e",
};
static const char* const BP_H_GOLDEN[64] = {
  "0319ff1a3915c93b9764a43d5b1837edfdd13b906f09ddb13d91fd059d865266c4",
  "0349642991c7694eb7cb2fb9f196dd1778295e893c7c862ab7b3acd499fc432ee1",
  "02d8701ee3a5644f4675b89fa4d9e1ad4692890b278249710960aab2da19717c83",
  "03b9a9fa3edda96595d423bd13a99ce4d66b5303ccaf6094b0d3bb1db193f7bfca",
  "024ee1b23795269ee94350e92e9cd6081cfca1d77b0b3622cfd61bfcf37ba8bc27",
  "0393f48a1b391bc7721566e1be3ad907d02aa4bddc4d9d531e32409c9a1958724d",
  "025f007b450d77f747a64b97fc37802a47ecf739a85a853bf8c041f5e749951490",
  "030e8cde16f474e9053c4333605ecd9061dd6812a17372d0ba4a48f4956f3ec052",
  "031b3131e5d4bf50643b41f4670a4afad3ce2cc5082283c3cc841df2e2b8df5aef",
  "02aa2f056f1daa315f6252c5de7685c8a2322089233dd0eb32c57f39de0a3e7e17",
  "0255f987e0180debf047de34cce28157ac1cc8d4327c78f10e9609a1db9ce38f7b",
  "024a7ff84a357dce611f8281b749865b0e62d17dd9f60f0affed01f66816a51f25",
  "02cf8b436e7853c397981f2e741d86afc7f7a58a0b696500850065383a8635ccd7",
  "03a736b3e223c1e600010b3d654ed5d1249b897cf17c179c27028ecfc0c2d42b44",
  "02b4370b60d224b7dc61600f90f3d68b9f27b027c1d43c1c4cf9875d01241dcde6",
  "02ec1d7bd64e0b5281c96a490f51fc548b78280159c4f013b9d63687dc336bfb1d",
  "02133f9a2722f83483cc5f36d31a1fa4aacf5f7eb7089e936ba9bdb345111c3a8e",
  "0297afaef305e9a7d5c5ffe8376cd0ff7ca226554e96666f3e4837ebcfbf266f5f",
  "0239780f2dfd7affc68073d1fe27029a89e74a780f661c632fc62aeb9a7ba4da6e",
  "03abf62fe7b5d257f031521fe0b344540108c3a64e0be0d9374764e902a26f32da",
  "0241e58127bbe2b5372e689d6f0c94bcb576432091f9a31b23ef7aab8328ea3641",
  "024f3a06929c396c7f73bf6646cf3a193f45af26466e7182c1a32422bf67cb6299",
  "034cb365eda90d8abc0423950f13748ab5533244ab040c9c3645650f963f9ea601",
  "02d01703d8b3cea6a3728a406ef4bd8d3231e2532d06a4d2a7794e7ae68668c738",
  "02fd41e8da37b50bfb27443e0740c01fe65ad4d5b59ca8cd3418a4675832607fc4",
  "02bd42a9dc059977ae4a4da938a15e38927351eee725a64a54c9f0739e7ed0b565",
  "021b1deef1948bf30a22b837f3f99debe9c272b1ed91acffd676626caa2ed18e79",
  "023c3c36363b7899c0ac93856310fcf1f9ea510bb3def2a00618c70fe48e19bf28",
  "027fa29aa19c90c1944f2bed6c53cb976221236c83caf5589bfc424a2328d148aa",
  "028a499eba5982620e95a14fe8b91686493bfdb969f642065e03647cae22b39b83",
  "026031e9e97047fa1de58d1b0fca15fd24c28cb9df80418e69bd51e389c6f27df1",
  "037c88ff2c98ee43408766e40452fad2d6ea2ae28b62869c24f649e3804583122d",
  "030eecf4d13e92ce09b2ba4503e70e8e5bbfcc20c0d891aedfb2c8027e9d455a1b",
  "03f2b761d5ce91c261777f0b90c6ae007461187b4dcf437b88eec639adaead3675",
  "03d787738da378f2915af361763e0964aa5437649fe3171665280122ee4549a2d6",
  "02e8cd5aabce01721f767139c5ccc5f7e7a134adb22ea56dd3d8c49d8638bc0bce",
  "02a48e3be13a6a84692840109ed5042ce3d03d233406ecd52e22b68257776ac8cd",
  "02146c0680a028417b64ace91481580acc718746ab1446fb7e3b9ca33976dab4a5",
  "03ab656d260e1d0d2ee815628fc82fc891750452162f1c81dfb80fd7b4d4b9bdbb",
  "02dc610fd565705445149fed213c6bdf3a2340710130b8db30c09823559bf1fa76",
  "02069086e28f0287c24463c0168d8ad6171def8c4290b0086c90b5b1ff8b7bc6a8",
  "032302913c421ccc69a8aaec0e440752891695cd0702afdd4b40b9479f30e76f8c",
  "02aabbb0f2478d21242dee5a8c728904c133b055d7e1ee1e165307b54531b30f9a",
  "0230381c81f6bf56061227bb2ee9938f47bf1a2dbfd4cd7d7c826aebf3f6a7d5be",
  "02a6e56774d2b6bc3b67ec4070307dc3879a8d5730bea7eb2a153528a610045d88",
  "026a16040b8129272e8fecdb71a74a60e6a6d06c20ea420e5c825a96abc0f4b539",
  "0249441f529c3a104e997d4c823a8699696d147892b64b89642c3ea587452b4b7c",
  "0388ec567e92ad8a974949fb12ebfdac4e05b9cdeb53cf4bc1320465005d957204",
  "027a40fae0cc23db2191856b3de05c34fdc50bc22a38b2af0ace3bae82ef61cb88",
  "02033ae7e2c9c19de1ee02982e65d7f2812a8274f88e83ec202d7234adcc1b30bd",
  "0245fe53f90aa8ff0fbc30a9d056092e7a596fe70dbf1505b5c4f37a50f5196e59",
  "0276eaf8211bf12ea6f76336f2a17ed6022098a26d3140ca79918f9f51f5f13c2e",
  "0363f9b3bd075733db0ceca04e2205f7ed062d491ac6ed80e5109b60327150cb0e",
  "02a1cd762d574e2b68afc3738d9e573619c30992a215b8ea16c49f039a6da436ef",
  "03f6b91a04a1d9387439e5d2d2c9127ff4fd48e7317b8a818764b5278f60907bf4",
  "0200ff8cf060bc2f37a61a4fa674072f4ab2a23a6bf3af493aa0cad11fe70cf40b",
  "02ed59d64f9de88a96798ea68a849ba66c0d97aaa3c527fa420047492b97bd9312",
  "02a088a83208a3b51c13b5cb4ad3da94584a07aa7658f1f939c0d3dfc6a9303f49",
  "03af9c578f256d39d7426c9902377d135df34016fde66289e07d82eab5e1386f63",
  "0301e723ebd23e092fad9e8359d12c2b61fd65a18e1e11c14dccf8bfe29250ca4a",
  "0290492a5dd69f619677469b70e1f5e69ed007d7de8f444a7ea9c5fa78a964cf56",
  "03e78b873db0fa8a0ffde032960d904aae29a770e455a4c1d91951cc9d22022904",
  "03d3d71a8c87d6ab69756a681e83e5343be116deda8fbfecf3e5f6786e3fb16164",
  "034f8983a51567d0280eb759f2850edc47d1a591d471a5b6c822714be7033dba4d",
};
   for( size_t i = 0; i < 64; ++i )
   {
      BOOST_CHECK_MESSAGE( stealth_BP_G( i ) == expect_hex( BP_G_GOLDEN[i] ),
         "BP_G[" << i << "] does not match golden — generator derivation changed" );
      BOOST_CHECK_MESSAGE( stealth_BP_H( i ) == expect_hex( BP_H_GOLDEN[i] ),
         "BP_H[" << i << "] does not match golden — generator derivation changed" );
   }
   // Pairwise distinctness (F-04): 64 Gi distinct, 64 Hi distinct, no Gi==Hi,
   // none equals G/H/J1v*/J2v* — degenerate generators would collapse the
   // IPA weight vector the verifier equation depends on.
   {
      std::vector<unsigned char> Gpt = stealth_G_point();
      std::vector<std::vector<unsigned char>> reserved;
      reserved.push_back( Gpt );
      reserved.push_back( H );
      reserved.push_back( stealth_J1_point( 1 ) );
      reserved.push_back( stealth_J2_point( 1 ) );
      reserved.push_back( stealth_J1_point( 2 ) );
      reserved.push_back( stealth_J2_point( 2 ) );
      for( size_t i = 0; i < 64; ++i )
      {
         for( size_t j = i + 1; j < 64; ++j )
         {
            BOOST_CHECK_MESSAGE( stealth_BP_G( i ) != stealth_BP_G( j ),
               "BP_G[" << i << "] == BP_G[" << j << "]" );
            BOOST_CHECK_MESSAGE( stealth_BP_H( i ) != stealth_BP_H( j ),
               "BP_H[" << i << "] == BP_H[" << j << "]" );
         }
         for( size_t k = 0; k < 64; ++k )
            BOOST_CHECK_MESSAGE( stealth_BP_G( i ) != stealth_BP_H( k ),
               "BP_G[" << i << "] == BP_H[" << k << "]" );
         for( size_t r = 0; r < reserved.size(); ++r )
         {
            BOOST_CHECK_MESSAGE( stealth_BP_G( i ) != reserved[r],
               "BP_G[" << i << "] collides with reserved generator " << r );
            BOOST_CHECK_MESSAGE( stealth_BP_H( i ) != reserved[r],
               "BP_H[" << i << "] collides with reserved generator " << r );
         }
      }
   }
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( commitments_match_fc_backend )
{ try {
   // Byte-compatibility between the consensus OpenSSL commitment path and
   // fc's libsecp256k1 backend: the SAME (blind, value) MUST give the SAME
   // 33 bytes, or turnstile/excess/range checks would fork against history.
   for( const auto& label : { "g1b-compat-a", "g1b-compat-b", "g1b-compat-c" } )
   {
      auto B = T_blind_secret( label );
      for( uint64_t v : { (uint64_t)0, (uint64_t)1, (uint64_t)1000,
                          (uint64_t)GRAPHENE_MAX_SHARE_SUPPLY } )
      {
         auto mine = T_commit( T_bn( B ), v );
         auto fc_c = fc::ecc::blind( B, v );
         BOOST_CHECK_MESSAGE( mine == std::vector<unsigned char>( fc_c.begin(), fc_c.end() ),
            "commitment mismatch for " << label << " v=" << v );
      }
   }
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( negative_mint_rejected )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), dan, core.amount( 200000000 ) );
   // G1c parity economics (BSIP-2 §2): schedules are zero, so the forgery
   // setup below carries a full cost-anchor gap; seed the pool so the
   // range-proof check (not the float rule) is what rejects the forgery.
   // NOTE: the funding transfer above opens a pending-tx undo session, so
   // seal it first — direct db modifications made while pushed transactions
   // are pending are rolled back by the next generate_block (which rewinds
   // to head and replays). Everything below follows the same
   // seal-then-modify discipline.
   generate_block();
   g1c_seed_pool( db, dan_id, core, 5000000 );

   // Forgery with BALANCED sums but MISMATCHED range proofs: in 1000,
   // outs 600 + 400 (sums cancel mod n, so validate()'s verify_sum passes),
   // but both outputs carry well-formed proofs for value 300 on OTHER
   // commitments (headers parse, max_value in range, so header-only checks
   // pass). Pre-fix consensus accepts (no verify_range in any evaluator);
   // post-fix do_evaluate must throw.
   // NOTE (corrected G1b-2): G1b-1's "negative wrap" narrative (1300 +
   // 2^64-300) cannot reach consensus at all — EC sums live mod n, where
   // 1000-1300-(2^64-300) = -2^64 != 0, so validate()'s verify_sum already
   // rejects it. The live gap is unverified proofs, exercised here with
   // balanced sums: the same consensus path that would admit a wrap forgery
   // if sums ever passed it.
   fc::sha256 S_bin = T_blind_secret( "g1b-mint-bin" );
   fc::sha256 S_b1 = T_blind_secret( "g1b-mint-b1" );
   fc::sha256 S_bb = T_blind_secret( "g1b-mint-bb" );
   BIGNUM* b_in = T_bn( S_bin );
   BIGNUM* b1 = T_bn( S_b1 );
   BIGNUM* b2 = BN_new();
   BN_mod_sub( b2, b_in, b1, T_order(), T_ctx() );
   auto C_in = T_commit( b_in, 1000 );
   auto C1 = T_commit( b1, 600 );
   auto C2 = T_commit( b2, 400 );
   auto owner_key = fc::ecc::private_key::generate();
   authority own( 1, public_key_type( owner_key.get_public_key() ), 1 );

   // Fund the input with a VALID transfer_to_blind first.
   {
      transfer_to_blind_operation fund;
      fund.amount = core.amount( 1000 );
      fund.from = dan.id;
      blind_output fo;
      fo.commitment = T_commitment( C_in );
      fo.owner = own;
      auto nonce = T_secret( "g1b-mint-nonce" );
      fc::sha256 bsec = S_bin;
      fo.range_proof = fc::ecc::range_proof_sign( 0, fo.commitment, bsec, nonce, 0, 0, 1000 );
      fund.blinding_factor = bsec;
      fund.outputs = { fo };
      trx.operations = { fund };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear();
      generate_block(); // seal first: _generate_block re-applies pending txs,
      // wiping direct modifies — T_grandfather must run on sealed state.
      // Task 3: the forgery below must reach the sound-range-proof gate, not
      // the legacy-leg created_block gate — grandfather the funded input.
      T_grandfather( db, core.get_id(), fo.commitment );
   }

   // The forgery: spend C_in (1000), create C1 (600) + C2 (400) with
   // mismatched proofs. Sums balance; proofs do not verify.
   blind_transfer_operation mint;
   mint.fee = core.amount( 0 );
   blind_input bi; bi.commitment = T_commitment( C_in ); bi.owner = own;
   mint.inputs = { bi };
   blind_output o1, o2;
   o1.commitment = T_commitment( C1 ); o1.owner = own;
   o2.commitment = T_commitment( C2 ); o2.owner = own;
   // Mismatched proofs: genuine proofs for value 300, wrong commitments.
   BIGNUM* bbb = T_bn( S_bb );
   auto Cb = T_commit( bbb, 300 );
   BN_free( bbb );
   auto nonce = T_secret( "g1b-mint-nonce2" );
   fc::sha256 bbsec = S_bb;
   auto forged = fc::ecc::range_proof_sign( 0, T_commitment( Cb ), bbsec, nonce, 0, 0, 300 );
   o1.range_proof = forged;
   o2.range_proof = forged;
   if( o2.commitment < o1.commitment ) mint.outputs = { o2, o1 };
   else mint.outputs = { o1, o2 };
   BOOST_CHECK_NO_THROW( mint.validate() ); // header-only checks pass: the gap
   trx.operations = { mint };
   sign( trx, owner_key );
   BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception ); // consensus must reject
   trx.clear();

   BN_free( b_in ); BN_free( b1 ); BN_free( b2 );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( legacy_range_proof_enforced )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), dan, core.amount( 200000000 ) );
   // G1c parity economics (BSIP-2 §2): seed the pool so the honest setup and
   // the tampered-proof rejection below both run past the float rule — the
   // sound-proof check stays the deciding assertion. Sealed first: direct
   // modifies are lost if pushed transactions are still pending (see above).
   generate_block();
   g1c_seed_pool( db, dan_id, core, 5000000 );
   // Honest flow with REAL proofs keeps working post-fork (no regression).
   transfer_to_blind_operation to_blind;
   to_blind.amount = core.amount( 1000 );
   to_blind.from = dan.id;
   auto k1 = fc::ecc::private_key::generate();
   blind_output out1;
   out1.owner = authority( 1, public_key_type( k1.get_public_key() ), 1 );
   auto B1 = T_secret( "g1b-honest-b1" );
   auto N1 = T_secret( "g1b-honest-n1" );
   out1.commitment = fc::ecc::blind( B1, 1000 );
   out1.range_proof = fc::ecc::range_proof_sign( 0, out1.commitment, B1, N1, 0, 0, 1000 );
   to_blind.blinding_factor = B1;
   to_blind.outputs = { out1 };
   trx.operations = { to_blind };
   sign( trx, dan_private_key );
   BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) ); trx.clear();
   generate_block();
   // Tampered proof (parses, does not verify) must now reject.
   transfer_to_blind_operation evil = to_blind;
   evil.outputs.front().range_proof[20] ^= 0x40;
   trx.operations = { evil };
   sign( trx, dan_private_key );
   BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
   trx.clear();
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( decoy_rules_enforced )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_DECOY_MIN_AGE_SEC, 86400u );
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_DECOY_SKEW_MAX_PCT, 40u );
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_BLIND_POOL_FLOOR, 11u );
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_RING_MIN, 11u );
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_RING_MAX, 32u );

   auto now = db.head_block_time();
   std::string err;
   // policy unit: 16 members all old, spread over windows -> accept (deep
   // pool: the thin rule needs an explicit depth, so deep callers pass one —
   // 1000 selects the target-16 floor with the 40% skew regime). Task 6
   // (R7 C-01): the TARGET floor binds deep too; 11-rings throw everywhere
   // (see thin_pool_decoy_tightening for the pinned boundaries).
   {
      std::vector<uint32_t> h;
      for( uint32_t w : { 10u, 20u, 30u, 40u } )
         for( uint32_t k = 0; k < 4; ++k )
            h.push_back( w * 100 + k );
      std::vector<fc::time_point_sec> t( 16, now - 90000 );
      BOOST_CHECK_MESSAGE( stealth_check_decoy_policy( h, t, now, 5000, err, 1000 ), err );
   }
   // one under-age decoy (younger than 24h) -> reject
   {
      std::vector<uint32_t> h( 16, 1900 );
      std::vector<fc::time_point_sec> t( 16, now - 90000 );
      t[5] = now - 3600;
      BOOST_CHECK_MESSAGE( !stealth_check_decoy_policy( h, t, now, 2000, err, 1000 ),
                           "under-age decoy must reject" );
   }
   // skew: 7 of 16 decoys inside one 100-block window (>40%) -> reject
   {
      std::vector<uint32_t> h = { 1000, 1001, 1002, 1003, 1004, 1005, 1006,
                                  2000, 2100, 2200, 2300, 2400, 2500,
                                  2600, 2700, 2800 };
      std::vector<fc::time_point_sec> t( 16, now - 90000 );
      BOOST_CHECK_MESSAGE( !stealth_check_decoy_policy( h, t, now, 2500, err, 1000 ),
                           "skewed ring must reject" );
   }
   // op level: the pool floor gates stealth_transfer SPENDS (rings need
   // decoys), never transfer_to_blind DEPOSITS (which create decoys:
   // gating them would deadlock bootstrapping — pool 0 could never grow).
   // Corrected G1b-3 (review Findings 4-5): the G1b-1/G1b-2 form asserted
   // the floor on transfer_to_blind, which the header never gated.
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), dan, core.amount( 200000000 ) );
   BOOST_CHECK_EQUAL( stealth_pool_depth( db, core.get_id() ), 0u );
   // G1c parity economics (BSIP-2 §2): seed the parity pool (fee accounting,
   // not decoy depth — the depth assertion above is unaffected) so the
   // deposit below proves "deposits always allowed" on the subsidized path
   // and the thin spend still throws on the pool FLOOR (funded pool covers
   // its gap, so the floor — not the float rule — rejects it). Sealed first
   // (see the seal-then-modify note in negative_mint_rejected): the seed
   // must survive the deposit's replay at block production.
   generate_block();
   g1c_seed_pool( db, dan_id, core, 5000000 );
   transfer_to_blind_operation ttb;
   ttb.amount = core.amount( 500 );
   ttb.from = dan.id;
   auto k = fc::ecc::private_key::generate();
   blind_output o;
   o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
   auto B = T_secret( "g1b-thin-b" );
   auto N = T_secret( "g1b-thin-n" );
   o.commitment = fc::ecc::blind( B, 500 );
   o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 500 );
   ttb.blinding_factor = B;
   ttb.outputs = { o };
   trx.operations = { ttb };
   sign( trx, dan_private_key );
   BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) ); // deposits always allowed
   trx.clear();
   BOOST_CHECK_EQUAL( stealth_pool_depth( db, core.get_id() ), 1u );
   // ...but a ring spend at pool 1 < 11 halts (availability yields to privacy).
   stealth_transfer_operation thin;
   thin.asset_id = core.get_id();
   thin.proof_version = GRAPHENE_STEALTH_PROOF_V1;
   thin.fee = core.amount( 0 );
   {
      stealth_ring_input frin;
      for( int i = 0; i < 11; ++i )
      {
         fc::ecc::commitment_type fc_;
         fc_.data()[0] = (char)( 0x02 + ( i & 1 ) );
         fc_.data()[1] = (char)i; fc_.data()[2] = (char)0x77;
         frin.ring.push_back( fc_ );
      }
      frin.key_image = std::vector<char>( 33, 0x03 );
      frin.pseudo_output = frin.ring[0];
      frin.ring_sig = std::vector<char>( 32 + 96 * 11, 0x01 );
      // Dummy alt linkage (rejected at the pool floor, never verified).
      frin.alt_key_image = std::vector<char>( 33, 0x04 );
      frin.alt_ring_sig = std::vector<char>( 32 + 96 * 11, 0x01 );
      thin.inputs = { frin };
      stealth_blind_output fout;
      fout.commitment = frin.ring[1];
      fout.range_proof = std::vector<char>( 1, 0x02 );
      fout.owner = o.owner;
      thin.outputs = { fout };
   }
   BOOST_CHECK_NO_THROW( thin.validate() ); // wire shape is fine...
   trx.operations = { thin };
   BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception ); // ...floor rejects
   trx.clear();
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( stealth_transfer_happy_path )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), dan, core.amount( 500000000 ) );
   // G1c parity economics (BSIP-2 §2): 16 deposits (1M gap each) + the ring
   // spend (1.5M) run subsidized; seed once so the kernel assertions hold.
   // Sealed first (see note above). Seed 24M (not 20M): the +25h aging jump
   // below crosses a maintenance that recomputes the burn ratio from
   // interval flow — 16M granted / 20M routed = 80% would fire
   // burn_critical and halt subsidies before the spend. At 16/24 = 66% only
   // the (non-gating) warn fires and 8M remains for the 1.5M spend.
   generate_block();
   g1c_seed_pool( db, dan_id, core, 24000000 );
   // Fund 16 post-fork outputs (4/4/4/4) spread over four 100-block windows
   // so the thin-pool 25%-skew rule (R-04: depth 16 < 64) is satisfiable at
   // the target ring size 16; then age them 25h in one jump.
   std::vector<fc::sha256> blinds;
   std::vector<fc::ecc::commitment_type> commits;
   auto fund_one = [&]( int i, uint64_t v ) {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( v );
      ttb.from = dan.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_blind_secret( "g1b-happy-b|" + std::to_string( i ) );
      auto N = T_secret( "g1b-happy-n|" + std::to_string( i ) );
      // NOTE: fc::blind uses the S2 H backend; the compatibility test above
      // proves T_commit openings below match these commitments byte-for-byte.
      o.commitment = fc::ecc::blind( B, v );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, v );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      blinds.push_back( B );
      commits.push_back( o.commitment );
   };
   for( int i = 0; i < 4; ++i ) { fund_one( i, 1000 ); generate_block(); }
   generate_blocks( 110 );
   for( int i = 4; i < 8; ++i ) { fund_one( i, 1000 ); generate_block(); }
   generate_blocks( 110 );
   for( int i = 8; i < 12; ++i ) { fund_one( i, 1000 ); generate_block(); }
   generate_blocks( 110 );
   for( int i = 12; i < 16; ++i ) { fund_one( i, 1000 ); generate_block(); }
   generate_blocks( db.head_block_time() + 90000 ); // +25h: all decoys old
   generate_block();
   set_expiration( db, trx );
   BOOST_CHECK_EQUAL( stealth_pool_depth( db, core.get_id() ), 16u );
   // Ring + range-proof ops exceed the 2048B default transaction ceiling by
   // design (16-member rings alone are ~1.6kB). Production enables them via
   // committee-set maximum_transaction_size; the test mirrors that governance
   // action directly (precedent: db.modify on global properties in
   // authority_tests/block_tests).
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      p.parameters.maximum_transaction_size = 1024 * 1024;
   } );

    // Spend output #5 (value 1000) into two V1 outputs (600 + 390, fee 10).
    // No signatures: knowledge-of-opening authorizes (temp fee payer, thr 0).
    // Conservation kernel (G1b-3): pseudo-output P commits to the SAME value
    // (1000) under a fresh blind; excess = b'_pseudo - b_o1 - b_o2 proves
    // 1000 - 600 - 390 - 10 == 0 without revealing which member is real.
    size_t s = 5;
    BIGNUM* bs = T_bn( blinds[s] );
    BIGNUM* bprime = T_bn( T_blind_secret( "g1b-happy-pseudo" ) );
    auto Bk1 = T_blind_secret( "g1b-happy-out1" );
    auto Bk2 = T_blind_secret( "g1b-happy-out2" );
   auto Nk1 = T_secret( "g1b-happy-nout1" );
   auto Nk2 = T_secret( "g1b-happy-nout2" );
   auto rk1 = fc::ecc::private_key::generate();
   auto rk2 = fc::ecc::private_key::generate();
   stealth_blind_output so1, so2;
   so1.commitment = fc::ecc::blind( Bk1, 600 );
   so1.range_proof = fc::ecc::range_proof_sign( 0, so1.commitment, Bk1, Nk1, 0, 0, 600 );
   so1.owner = authority( 1, public_key_type( rk1.get_public_key() ), 1 );
   so2.commitment = fc::ecc::blind( Bk2, 390 );
   so2.range_proof = fc::ecc::range_proof_sign( 0, so2.commitment, Bk2, Nk2, 0, 0, 390 );
   so2.owner = authority( 1, public_key_type( rk2.get_public_key() ), 1 );

   stealth_transfer_operation stop;
   stop.asset_id = core.get_id();
   stop.proof_version = GRAPHENE_STEALTH_PROOF_V1;
   stop.fee = core.amount( 10 );
   stop.outputs = { so1, so2 };
    // excess = b'_pseudo - b_o1 - b_o2 (mod n): binds the HIDDEN value
    // equation sum(P) - sum(outs) - fee*H == excess*G (kernel, G1b-3).
    {
       BIGNUM* e = BN_new();
       BIGNUM* t = BN_new();
       BIGNUM* b1 = T_bn( Bk1 );
       BIGNUM* b2 = T_bn( Bk2 );
       BN_copy( e, bprime );
       BN_mod_sub( e, e, b1, T_order(), T_ctx() );
       BN_mod_sub( e, e, b2, T_order(), T_ctx() );
       unsigned char eb[32]; BN_bn2binpad( e, eb, 32 );
       std::copy( eb, eb + 32, (char*)stop.excess.data() );
       BN_free( e ); BN_free( t ); BN_free( b1 ); BN_free( b2 );
    }
   // ring over all 16 commitments (Q as raw points via OpenSSL below).
   // Depth 16 < 64 selects the R-04 thin regime: target-size ring with the
   // 25% skew ceiling (4/4/4/4 passes exactly) — this spend IS the
   // thin-pool-16 op-level case.
   std::vector<std::vector<unsigned char>> Q;
   for( const auto& c : commits )
      Q.push_back( std::vector<unsigned char>( c.begin(), c.end() ) );
    // message from the consensus transcript builder (single-sourced).
    // Pseudo-output participates (bound spend authorization, G1b-3).
    std::vector<fc::ecc::commitment_type> out_cs = { so1.commitment, so2.commitment };
    auto Pv = T_commit( bprime, 1000 );
    fc::ecc::commitment_type pseudo_c = T_commitment( Pv );
    // provisional image for message: prover computes image first via a dry run
    std::vector<unsigned char> img0, pseudo0; std::vector<char> sig0;
    {
       std::string m0( 32, '\0' );
       T_prove_ring( GRAPHENE_STEALTH_PROOF_V1, Q, s, bs, 1000, bprime,
                     m0, img0, pseudo0, sig0 );
    }
    BOOST_REQUIRE( pseudo0 == Pv ); // deterministic pseudo derivation
    // Task 5 (M05/GC-07): the same opening authorized under V2 as well —
    // consensus nullifies both images (dual-verify window).
    std::vector<unsigned char> img2, pseudo2; std::vector<char> sig2;
    {
       std::string m0( 32, '\0' );
       T_prove_ring( GRAPHENE_STEALTH_PROOF_V2, Q, s, bs, 1000, bprime,
                     m0, img2, pseudo2, sig2 );
    }
    BOOST_REQUIRE( pseudo2 == Pv ); // pseudo is version-independent
    std::vector<char> img0c( img0.begin(), img0.end() );
    std::vector<char> img2c( img2.begin(), img2.end() );
    fc::sha256 m = stealth_ring_message( stop.proof_version, stop.asset_id,
       img0c, commits, pseudo_c, out_cs, stop.fee.amount );
    fc::sha256 m_alt = stealth_ring_message( GRAPHENE_STEALTH_PROOF_V2, stop.asset_id,
       img2c, commits, pseudo_c, out_cs, stop.fee.amount );
    std::string ms( (const char*)m.data(), 32 );
    std::string ms_alt( (const char*)m_alt.data(), 32 );
    stealth_ring_input rin = T_make_dual_ring_input( GRAPHENE_STEALTH_PROOF_V1,
       GRAPHENE_STEALTH_PROOF_V2, Q, s, bs, 1000, bprime, ms, ms_alt );
   // image must be stable across runs (deterministic image derivation)
   BOOST_REQUIRE( std::vector<unsigned char>( rin.key_image.begin(), rin.key_image.end() ) == img0 );
   BOOST_REQUIRE( std::vector<unsigned char>( rin.alt_key_image.begin(), rin.alt_key_image.end() ) == img2 );
   stop.inputs = { rin };
   BOOST_CHECK_NO_THROW( stop.validate() );
   trx.operations = { stop };
   // no signatures at all: temp fee payer (threshold 0) + ring authorization
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   // Nullifier recorded: same image double-spend rejects...
   {
      stealth_transfer_operation dbl = stop;
      trx.operations = { dbl };
      BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
      trx.clear();
   }
      // ...and the new outputs exist as blinded balances.
      // Task 3 (nullifier migration): every member stays indexed AND stays
      // decoy-eligible — re-spend is blocked by the nullifier set alone
      // (proven by the double-spend rejection above), while the anonymity
      // set grows with usage instead of draining.
      {
         const auto& idx = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
         BOOST_CHECK( idx.find( so1.commitment ) != idx.end() );
         BOOST_CHECK( idx.find( so2.commitment ) != idx.end() );
         BOOST_CHECK( idx.find( commits[s] ) != idx.end() ); // retained (still live)
      }
      // Live-set pool counter (Task 3): 16 funded, the ring removes nothing,
      // 2 outputs created -> 18 decoy candidates. Each ring spend grows the
      // set; the floor gate (not this counter) enforces thin-pool halts.
      BOOST_CHECK_EQUAL( stealth_pool_depth( db, core.get_id() ), 18u );
     BN_free( bs ); BN_free( bprime );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( deposit_histogram_tracks_depositor )
{
   // TDD RED first: helper + getters do not exist yet; this case must fail
   // to compile until Steps 3-5 land.
   //
   // B2 DEVIATION (documented, load-bearing): preamble the brief omitted,
   // without which GREEN is unreachable —
   //  (a) the STEALTH fork jump: stealth_deposit_histogram_add is specified
   //      (Step 4) to no-op pre-STEALTH, and the fixture genesis is May-2015
   //      vs HARDFORK_STEALTH_TIME 2030-01-01, so without the jump every
   //      getter (and stealth_pool_depth) reads 0;
   //  (b) the parity-pool seed: post-fork with the test-zeroed fee schedule
   //      every fee-0 1-output deposit carries the 1M CORE pinned-anchor gap
   //      (see the g1c note at :806-811), so an unseeded pool makes
   //      stealth_require_blind_fee throw on the first deposit.
   // Both follow sibling-case precedent (decoy_rules_enforced,
   // stealth_transfer_happy_path) in form.
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   ACTORS( (alice)(bob)(c1)(c2)(c3)(c4)(c5)(c6)(c7)(c8)(c9)(c10)(c11)(c12)(c13)(c14) );
   const asset_object& core = asset_id_type()(db);
   const std::vector<const account_object*> fund =
      { &alice, &bob, &c1, &c2, &c3, &c4, &c5, &c6, &c7, &c8,
        &c9, &c10, &c11, &c12, &c13, &c14 };
   for( const account_object* who : fund )
      transfer( account_id_type()(db), *who, core.amount( 200000000 ) );
   generate_block();
   // B2 DEVIATION (b): seed-payer top-up + seal + parity seed. 19 deposits x
   // 1M gap need >= 19M in the pool; 24M mirrors stealth_transfer_happy_path.
   // g1c_seed_pool debits 20x need (5% routing), so alice's 200M cannot cover
   // it — top up first. Sealed state required (direct writes; see the
   // g1c_seed_pool durability note).
   transfer( account_id_type()(db), alice, core.amount( 400000000 ) );
   generate_block();
   g1c_seed_pool( db, alice_id, core, 24000000 );
   auto do_deposit = [&]( const account_object& who, const fc::ecc::private_key& key,
                          const std::string& tag )
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 500 );
      ttb.from = who.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_secret( (tag + "-b").c_str() );
      auto N = T_secret( (tag + "-n").c_str() );
      o.commitment = fc::ecc::blind( B, 500 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 500 );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      trx.operations = { ttb };
      sign( trx, key );
      BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
      trx.clear();
   };
   for( int i = 0; i < 4; ++i )
      do_deposit( alice, alice_private_key, "h-alice-" + std::to_string(i) );
   BOOST_REQUIRE_EQUAL( stealth_deposited_outputs( db, core.get_id() ), 4u );
   BOOST_REQUIRE_EQUAL( stealth_effective_depositor_count( db, core.get_id() ), 1u );
   do_deposit( bob, bob_private_key, "h-bob-0" );
   // counts {4,1}: N=5, sumsq=16+1=17, E=25/17=1.
   BOOST_REQUIRE_EQUAL( stealth_deposited_outputs( db, core.get_id() ), 5u );
   BOOST_REQUIRE_EQUAL( stealth_effective_depositor_count( db, core.get_id() ), 1u );
   const std::vector<std::pair<const account_object*, const fc::ecc::private_key*>> rest =
      { {&c1,&c1_private_key}, {&c2,&c2_private_key}, {&c3,&c3_private_key},
        {&c4,&c4_private_key}, {&c5,&c5_private_key}, {&c6,&c6_private_key},
        {&c7,&c7_private_key}, {&c8,&c8_private_key}, {&c9,&c9_private_key},
        {&c10,&c10_private_key}, {&c11,&c11_private_key}, {&c12,&c12_private_key},
        {&c13,&c13_private_key}, {&c14,&c14_private_key} };
   int j = 0;
   for( const auto& p : rest )
      do_deposit( *p.first, *p.second, "h-rest-" + std::to_string(j++) );
   // counts {4,1x15}: N=19, sumsq=16+15=31, E=361/31=11 (11*31=341<=361<372).
   BOOST_REQUIRE_EQUAL( stealth_deposited_outputs( db, core.get_id() ), 19u );
   BOOST_REQUIRE_EQUAL( stealth_effective_depositor_count( db, core.get_id() ), 11u );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 19u );
}

BOOST_AUTO_TEST_CASE( deposit_histogram_detects_sybil_share )
{
   // Detection, not scale: 9+1 shape carries the same 90% share as P2's 90+10.
   // Preamble (fork jump + seeded pool — REQUIRED, found by B2's implementer:
   // fixture genesis predates HARDFORK_STEALTH_TIME so the helper no-ops
   // without the jump; test-genesis zero fees open the full pinned-anchor gap
   // without a seeded pool. Same pattern as decoy_rules_enforced and B2's
   // deposit_histogram_tracks_depositor).
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (sybil)(u1)(u2)(u3)(u4)(u5)(u6)(u7)(u8)(u9)(u10) );
   const asset_object& core = asset_id_type()(db);
   const std::vector<const account_object*> fund =
      { &sybil, &u1, &u2, &u3, &u4, &u5, &u6, &u7, &u8, &u9, &u10 };
   for( const account_object* who : fund )
      transfer( account_id_type()(db), *who, core.amount( 200000000 ) );
   transfer( account_id_type()(db), sybil, core.amount( 400000000 ) ); // seed-payer top-up
   generate_block(); // seal: seed does direct writes
   g1c_seed_pool( db, sybil_id, core, 24000000 ); // 19 deposits x 1M need; 24M mirrors B2
   auto do_deposit = [&]( const account_object& who, const fc::ecc::private_key& key,
                          const std::string& tag )
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 500 );
      ttb.from = who.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_secret( (tag + "-b").c_str() );
      auto N = T_secret( (tag + "-n").c_str() );
      o.commitment = fc::ecc::blind( B, 500 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 500 );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      trx.operations = { ttb };
      sign( trx, key );
      BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
      trx.clear();
   };
   for( int i = 0; i < 9; ++i )
      do_deposit( sybil, sybil_private_key, "s-sybil-" + std::to_string(i) );
   do_deposit( u1, u1_private_key, "s-u1-0" );
   // counts {9,1}: N=10, sumsq=81+1=82, E=100/82=1. Nominal says 10, E says 1.
   BOOST_REQUIRE_EQUAL( stealth_deposited_outputs( db, core.get_id() ), 10u );
   BOOST_REQUIRE_EQUAL( stealth_effective_depositor_count( db, core.get_id() ), 1u );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 10u );
   const std::vector<std::pair<const account_object*, const fc::ecc::private_key*>> rest =
      { {&u2,&u2_private_key}, {&u3,&u3_private_key}, {&u4,&u4_private_key},
        {&u5,&u5_private_key}, {&u6,&u6_private_key}, {&u7,&u7_private_key},
        {&u8,&u8_private_key}, {&u9,&u9_private_key}, {&u10,&u10_private_key} };
   int j = 0;
   for( const auto& p : rest )
      do_deposit( *p.first, *p.second, "s-rest-" + std::to_string(j++) );
   // counts {9,1x10}: N=19, sumsq=81+10=91, E=361/91=3 (3*91=273<=361<364).
   BOOST_REQUIRE_EQUAL( stealth_deposited_outputs( db, core.get_id() ), 19u );
   BOOST_REQUIRE_EQUAL( stealth_effective_depositor_count( db, core.get_id() ), 3u );
}

// C1 forward declaration (compile-necessitated): ee_bal + T_ee_deposit are
// defined later in this suite (~:12152); declared here so these tests can sit
// with the other pool-depth tests per the brief. Bodies below are verbatim.
struct ee_bal;
static std::vector<ee_bal> T_ee_deposit( database_fixture& f, account_id_type from,
      const fc::ecc::private_key& from_key, const authority& owner,
      const std::string& tag, const std::vector<int64_t>& values, int64_t fee );

BOOST_AUTO_TEST_CASE( cold_start_refuses_oversize_deposit )
{
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (alice) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), alice, core.amount( 200000000 ) );
   generate_block();
   // EE-test pattern (cf. subsidy_exit_cap_enforced): multi-output stealth
   // txs exceed the default max-transaction-size; raise it so the fee/refusal
   // guards decide, not the size gate.
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      p.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   auto ok = fc::ecc::private_key::generate();
   const authority own( 1, public_key_type( ok.get_public_key() ), 1 );
   // 17 outputs x 500 = 8500; fee anchor(17) = 9,000,000 covers the full
   // pre-change cost, so RED (pre-change) SUCCEEDS and GREEN refuses.
   std::vector<int64_t> seventeen( 17, 500 );
   BOOST_CHECK_THROW(
      T_ee_deposit( *this, alice_id, alice_private_key, own,
                    "c1-big", seventeen, 9000000 ),
      fc::exception );
   trx.clear_signatures(); trx.operations.clear();
}

BOOST_AUTO_TEST_CASE( cold_start_base_only_cost )
{
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (alice) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), alice, core.amount( 200000000 ) );
   generate_block();
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      p.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   auto ok = fc::ecc::private_key::generate();
   const authority own( 1, public_key_type( ok.get_public_key() ), 1 );
   // 4 outputs x 500 = 2000; fee anchor(0) = 500,000. Pre-change cost is
   // anchor(4) = 2,500,000 so RED throws; post-change cost is anchor(0).
   auto chk = T_ee_deposit( *this, alice_id, alice_private_key, own,
                                                 "c1-four", { 500, 500, 500, 500 }, 500000 );
   BOOST_REQUIRE_EQUAL( chk.size(), 4u );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 4u );
}

BOOST_AUTO_TEST_CASE( cold_start_terminates_at_floor )
{
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (alice) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), alice, core.amount( 200000000 ) );
   generate_block();
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      p.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   auto ok = fc::ecc::private_key::generate();
   const authority own( 1, public_key_type( ok.get_public_key() ), 1 );
   // 11 singles at anchor(1) = 1,000,000 each (unseeded pool, exact cost).
   // Funding check: 11*1M + 9M + (11*500 + 8500) amounts << 200M. ✓
   for( int i = 0; i < 11; ++i )
      T_ee_deposit( *this, alice_id, alice_private_key, own,
                    "c1-seed-" + std::to_string(i), { 500 }, 1000000 );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 11u );
   // Cap lifted at depth 11: green-green by design (documents self-termination).
   std::vector<int64_t> seventeen( 17, 500 );
   T_ee_deposit( *this, alice_id, alice_private_key, own, "c1-big", seventeen, 9000000 );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 28u );
}

BOOST_AUTO_TEST_CASE( cold_start_crossing_agrees_on_cold )
{
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (alice) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), alice, core.amount( 200000000 ) );
   generate_block();
   // EE-test pattern (cf. cold_start_refuses_oversize_deposit): multi-output
   // stealth txs exceed the default max-transaction-size; raise it so the
   // agreement guards decide, not the size gate.
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      p.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   auto ok = fc::ecc::private_key::generate();
   const authority own( 1, public_key_type( ok.get_public_key() ), 1 );
   // Seed to depth 8 with singles at anchor(1) = 1,000,000 (cold: cost is
   // anchor(0) = 500,000; unseeded pool, exact-or-better fees throughout).
   for( int i = 0; i < 8; ++i )
      T_ee_deposit( *this, alice_id, alice_private_key, own,
                    "c1x-seed-" + std::to_string(i), { 500 }, 1000000 );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 8u );
   // One 8-output deposit (8x500 = 4000) at base-only fee 500,000 straddles
   // the floor (8 -> 16): require reads cold (8 < 11), and only the pre-add
   // consume placement agrees. Without it, consume would read warm (16) and
   // throw on the empty pool. GREEN iff the refinement holds.
   std::vector<int64_t> eight( 8, 500 );
   T_ee_deposit( *this, alice_id, alice_private_key, own, "c1x-cross", eight, 500000 );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 16u );
}

BOOST_AUTO_TEST_CASE( window_dominant_classifier )
{
   // Empty window: never dominant (cold inclusion beats discipline).
   stealth_depositor_window w0;
   BOOST_CHECK( !stealth_window_dominant( w0, account_id_type(7), 16 ) );
   // Full window, 900x acct7 + 124 distinct singles: 900*16 = 14400 > 1024.
   stealth_depositor_window w;
   for( uint32_t i = 0; i < 900; ++i )
      w.events[i] = stealth_deposit_event{ account_id_type(7), 1u };
   for( uint32_t i = 900; i < 1024; ++i )
      w.events[i] = stealth_deposit_event{ account_id_type(1000 + i), 1u };
   w.count = 1024;
   BOOST_CHECK( stealth_window_dominant( w, account_id_type(7), 16 ) );
   BOOST_CHECK( !stealth_window_dominant( w, account_id_type(1000), 16 ) );
   // Exact 1/16 boundary is NOT dominant (strict >): 64*16 = 1024, not > 1024.
   stealth_depositor_window w2;
   for( uint32_t i = 0; i < 64; ++i )
      w2.events[i] = stealth_deposit_event{ account_id_type(9), 1u };
   for( uint32_t i = 64; i < 1024; ++i )
      w2.events[i] = stealth_deposit_event{ account_id_type(2000 + i), 1u };
   w2.count = 1024;
   BOOST_CHECK( !stealth_window_dominant( w2, account_id_type(9), 16 ) );
}

BOOST_AUTO_TEST_CASE( stealth_conservation_kernel_rejects_mint )
{ try {
   // Finding 1 (Critical) end-to-end proof: the conservation kernel
   // (pseudo-output binding + excess equation) rejects mint attempts that
   // the G1b-2 code accepted ((void) o.excess — no check at all).
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), dan, core.amount( 500000000 ) );
   // G1c parity economics (BSIP-2 §2): 11 deposits (1M gap each) + 3 kernel
   // attempts (1.5M each) run subsidized; seed once so the kernel/binding
   // checks (not the float rule) decide every attempt. Sealed first (see
   // the seal-then-modify note in negative_mint_rejected).
   generate_block();
   g1c_seed_pool( db, dan_id, core, 20000000 );
   // Fund 16 post-fork outputs (4/4/4/4 over four skew windows), age 25h.
   // Depth 16 < 64 selects the R-04 thin regime: every attempt below rings
   // over all 16 (target size, 25% skew each window passes exactly), so the
   // kernel/binding checks — not the decoy gate — decide each attempt.
   std::vector<fc::sha256> blinds;
   std::vector<fc::ecc::commitment_type> commits;
   auto fund_one = [&]( int i, uint64_t v ) {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( v );
      ttb.from = dan.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_blind_secret( "g1b-ker-b|" + std::to_string( i ) );
      auto N = T_secret( "g1b-ker-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, v );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, v );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      blinds.push_back( B );
      commits.push_back( o.commitment );
   };
   for( int i = 0; i < 4; ++i ) { fund_one( i, 1000 ); generate_block(); }
   generate_blocks( 110 );
   for( int i = 4; i < 8; ++i ) { fund_one( i, 1000 ); generate_block(); }
   generate_blocks( 110 );
   for( int i = 8; i < 12; ++i ) { fund_one( i, 1000 ); generate_block(); }
   generate_blocks( 110 );
   for( int i = 12; i < 16; ++i ) { fund_one( i, 1000 ); generate_block(); }
   generate_blocks( db.head_block_time() + 90000 );
   generate_block();
   set_expiration( db, trx );
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      p.parameters.maximum_transaction_size = 1024 * 1024;
   } );

   // Attempt builder: real input commits[idx] (value 1000). The ring is
   // proven honestly for (b_s, 1000) under pseudo blind `plabel`; when
   // detach_pseudo is set the wire pseudo is swapped for P' (value
   // pseudo_value under a second blind) to simulate an inflated kernel
   // input. Returns true iff consensus rejected.
   auto attempt = [&]( size_t idx, const std::string& plabel,
                       uint64_t pseudo_value,
                       const std::vector<uint64_t>& out_values,
                       bool detach_pseudo, bool mismatched_proofs ) -> bool {
      BIGNUM* bs = T_bn( blinds[idx] );
      BIGNUM* bp = T_bn( T_blind_secret( plabel ) );
      BIGNUM* bp2 = detach_pseudo ? T_bn( T_blind_secret( plabel + "|2" ) ) : nullptr;
      std::vector<fc::sha256> ob;
      std::vector<stealth_blind_output> souts;
      for( size_t j = 0; j < out_values.size(); ++j )
      {
         auto Bj = T_blind_secret( plabel + "|out|" + std::to_string( j ) );
         auto Nj = T_secret( plabel + "|nout|" + std::to_string( j ) );
         auto rk = fc::ecc::private_key::generate();
         stealth_blind_output so;
         {
            BIGNUM* bjj = T_bn( Bj );
            auto Cv = T_commit( bjj, out_values[j] );
            BN_free( bjj );
            std::copy( Cv.begin(), Cv.end(), so.commitment.begin() );
         }
         if( mismatched_proofs )
         {
            // Well-formed proofs for OTHER commitments (headers parse):
            // the stealth-path analog of negative_mint_rejected.
            BIGNUM* bbb = T_bn( T_blind_secret( plabel + "|bb" ) );
            auto Cb = T_commit( bbb, 300 );
            BN_free( bbb );
            auto nonce = T_secret( plabel + "|nonce" );
            so.range_proof = fc::ecc::range_proof_sign(
               0, T_commitment( Cb ), T_blind_secret( plabel + "|bb" ),
               nonce, 0, 0, 300 );
         }
         else
            so.range_proof = fc::ecc::range_proof_sign(
               0, so.commitment, Bj, Nj, 0, 0, out_values[j] );
         so.owner = authority( 1, public_key_type( rk.get_public_key() ), 1 );
         ob.push_back( Bj );
         souts.push_back( so );
      }
      // Wire pseudo: honest P, or detached inflated P'.
      fc::ecc::commitment_type pseudo_wire;
      {
         BIGNUM* use = detach_pseudo ? bp2 : bp;
         auto Pv = T_commit( use, pseudo_value );
         std::copy( Pv.begin(), Pv.end(), pseudo_wire.begin() );
      }
      // Excess from the wire pseudo's blind (so the excess leg passes in
      // the detach case, isolating the binding leg as the defense).
      BIGNUM* bex = detach_pseudo ? bp2 : bp;
      stealth_transfer_operation stop;
      stop.asset_id = core.get_id();
      stop.proof_version = GRAPHENE_STEALTH_PROOF_V1;
      stop.fee = core.amount( 10 );
      stop.outputs = souts;
      {
         BIGNUM* e = BN_new();
         BN_copy( e, bex );
         for( const auto& Bj : ob )
         {
            BIGNUM* bj = T_bn( Bj );
            BN_mod_sub( e, e, bj, T_order(), T_ctx() );
            BN_free( bj );
         }
         unsigned char eb[32]; BN_bn2binpad( e, eb, 32 );
         std::copy( eb, eb + 32, (char*)stop.excess.data() );
         BN_free( e );
      }
      std::vector<std::vector<unsigned char>> Q;
      for( const auto& c : commits )
         Q.push_back( std::vector<unsigned char>( c.begin(), c.end() ) );
      std::vector<fc::ecc::commitment_type> out_cs;
      for( const auto& so : souts ) out_cs.push_back( so.commitment );
      std::vector<unsigned char> img0, pseudo0; std::vector<char> sig0;
      {
         std::string m0( 32, '\0' );
         T_prove_ring( GRAPHENE_STEALTH_PROOF_V1, Q, idx, bs, 1000, bp,
                       m0, img0, pseudo0, sig0 );
      }
      if( !detach_pseudo )
         BOOST_REQUIRE( std::vector<unsigned char>( pseudo_wire.begin(),
                        pseudo_wire.end() ) == pseudo0 );
      std::vector<char> img0c( img0.begin(), img0.end() );
      fc::sha256 m = stealth_ring_message( stop.proof_version, stop.asset_id,
         img0c, commits, pseudo_wire, out_cs, stop.fee.amount );
      // Task 5 dual linkage: same opening under V2 (proven against the TRUE
      // pseudo; the detach swap below invalidates both legs identically).
      std::vector<unsigned char> imgA, pseudoA; std::vector<char> sigA;
      {
         std::string m0( 32, '\0' );
         T_prove_ring( GRAPHENE_STEALTH_PROOF_V2, Q, idx, bs, 1000, bp,
                       m0, imgA, pseudoA, sigA );
      }
      std::vector<char> imgAc( imgA.begin(), imgA.end() );
      fc::sha256 m_alt = stealth_ring_message( GRAPHENE_STEALTH_PROOF_V2, stop.asset_id,
         imgAc, commits, pseudo_wire, out_cs, stop.fee.amount );
      std::string ms( (const char*)m.data(), 32 );
      std::string ms_alt( (const char*)m_alt.data(), 32 );
      stealth_ring_input rin = T_make_dual_ring_input( GRAPHENE_STEALTH_PROOF_V1,
         GRAPHENE_STEALTH_PROOF_V2, Q, idx, bs, 1000, bp, ms, ms_alt );
      if( detach_pseudo )
         rin.pseudo_output = pseudo_wire; // swap in the inflated kernel input
      stop.inputs = { rin };
      BOOST_REQUIRE_NO_THROW( stop.validate() );
      trx.operations = { stop };
      bool threw = false;
      try { PUSH_TX( db, trx ); }
      catch( const fc::exception& ) { threw = true; }
      trx.clear();
      BN_free( bs ); BN_free( bp );
      if( bp2 ) BN_free( bp2 );
      return threw;
   };

   // (a) Unbalanced ring spend: 1000 in, 600 + 500 + 10 fee out. Honest
   // pseudo (kernel input 1000), honest excess — sums do not balance.
   BOOST_CHECK_MESSAGE( attempt( 5, "g1b-kerA", 1000, { 600, 500 },
                                 false, false ),
                        "unbalanced ring spend (1100 + fee > 1000) must reject" );
   // (b) Inflated pseudo: wire P' commits to 2000 while the real input is
   // 1000; outputs 1200 + 790 + 10 fee balance against P', and the excess
   // leg passes in isolation...
   {
      BIGNUM* bp2 = T_bn( T_blind_secret( std::string( "g1b-kerB|2" ) ) );
      auto Pv = T_commit( bp2, 2000 );
      fc::ecc::commitment_type Pc = T_commitment( Pv );
      BIGNUM* b1 = T_bn( T_blind_secret( "g1b-kerB|out|0" ) );
      BIGNUM* b2 = T_bn( T_blind_secret( "g1b-kerB|out|1" ) );
      BIGNUM* e = BN_new();
      BN_copy( e, bp2 );
      BN_mod_sub( e, e, b1, T_order(), T_ctx() );
      BN_mod_sub( e, e, b2, T_order(), T_ctx() );
      unsigned char eb[32]; BN_bn2binpad( e, eb, 32 );
      fc::sha256 ex; std::copy( eb, eb + 32, (char*)ex.data() );
      auto C1v = T_commit( b1, 1200 ), C2v = T_commit( b2, 790 );
      std::string err;
      BOOST_CHECK_MESSAGE(
         stealth_verify_excess( { Pc },
            { T_commitment( C1v ), T_commitment( C2v ) }, 10, ex, err ),
         "excess leg passes for the inflated kernel input: " << err );
      BN_free( bp2 ); BN_free( b1 ); BN_free( b2 ); BN_free( e );
   }
   // ...but consensus rejects: the binding leg ties P' to the real 1000.
   BOOST_CHECK_MESSAGE( attempt( 6, "g1b-kerB", 2000, { 1200, 790 },
                                 true, false ),
                        "inflated pseudo-output spend must reject" );
   // (c) Negative-amount analog on the stealth path: balanced sums with
   // mismatched (non-verifying) output proofs must reject.
   BOOST_CHECK_MESSAGE( attempt( 4, "g1b-kerC", 1000, { 600, 390 },
                                 false, true ),
                        "mismatched-proof stealth spend must reject" );
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Task 5 (M04/M05/SUP-03/GC-07/V-04/V-05): G1 double-spend closure.
// A stealth-spent commitment stays indexed (future decoy), so the legacy
// explicit-spend legs must refuse it (created_block gate: post-fork spends
// route to op108); one opening must not spend once per proof version
// (dual-image linkage); amount/fee asset confusion must fail in consensus,
// not just relay validate. The supply identity (confidential_supply ==
// test-ledger sum over live blinds, all values test-known) pins that
// refused re-spends move nothing.
// ---------------------------------------------------------------------------

// Funded pool with KNOWN blinds AND owner keys, so every spend leg (ring +
// owner-signed legacy/turnstile) is constructible. All values are 1000.
struct t5_pool
{
   std::vector<fc::ecc::commitment_type> commits;
   std::vector<fc::sha256>               blinds;
   std::vector<fc::ecc::private_key>     keys;
   std::vector<authority>                owners;
   int64_t                               each = 1000;
   int64_t                               funded_total = 0;
};

// Pool scaffold (mirrors stealth_transfer_happy_path): the caller has run
// generate_blocks(HARDFORK_STEALTH_TIME) + generate_block + ACTORS first.
// aged==true requires n_out==16 (4/4/4/4 windows + 25h age for the decoy
// policy); aged==false funds consecutively (the gates under test fire before
// any age check, and the pool-floor counter needs no aging).
static t5_pool t5_fund_pool( database_fixture& f, const account_object& funder,
                             const fc::ecc::private_key& funder_key,
                             const std::string& tag, int n_out, bool aged )
{
   database& db = f.db;
   signed_transaction& trx = f.trx;
   const asset_object& core = asset_id_type()( db );
   f.transfer( account_id_type()( db ), funder, core.amount( 500000000 ) );
   f.generate_block();
   g1c_seed_pool( db, funder.get_id(), core, n_out * 1000000 + 5000000 );
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      p.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   t5_pool p;
   auto fund_one = [&]( int i ) {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( p.each );
      ttb.from = funder.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_blind_secret( tag + "-b|" + std::to_string( i ) );
      auto N = T_secret( tag + "-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, p.each );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, p.each );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      f.sign( trx, funder_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      p.commits.push_back( o.commitment );
      p.blinds.push_back( B );
      p.keys.push_back( k );
      p.owners.push_back( o.owner );
      p.funded_total += p.each;
   };
   if( aged )
   {
      BOOST_REQUIRE_EQUAL( n_out, 16 );
      for( int i = 0; i < 4; ++i ) { fund_one( i ); f.generate_block(); }
      f.generate_blocks( 110 );
      for( int i = 4; i < 8; ++i ) { fund_one( i ); f.generate_block(); }
      f.generate_blocks( 110 );
      for( int i = 8; i < 12; ++i ) { fund_one( i ); f.generate_block(); }
      f.generate_blocks( 110 );
      for( int i = 12; i < 16; ++i ) { fund_one( i ); f.generate_block(); }
      f.generate_blocks( db.head_block_time() + 90000 ); // +25h: decoys old
      f.generate_block();
      set_expiration( db, trx );
   }
   else
   {
      for( int i = 0; i < n_out; ++i ) { fund_one( i ); f.generate_block(); }
   }
   return p;
}

// Honest dual-image stealth spend of pool output s: each (1000) splits into
// out1 + out2 + fee. Output proofs match `version` (V1 Borromean / V2 BP+).
// Returns the op; the caller pushes.
static stealth_transfer_operation t5_build_spend( const asset_object& core,
      const t5_pool& p, size_t s, uint8_t version, const std::string& tag,
      int64_t out1, int64_t out2, int64_t fee )
{
   BOOST_REQUIRE( out1 + out2 + fee == p.each );
   const uint8_t alt_v = ( version == GRAPHENE_STEALTH_PROOF_V1 )
                         ? GRAPHENE_STEALTH_PROOF_V2
                         : GRAPHENE_STEALTH_PROOF_V1;
   BIGNUM* bs = T_bn( p.blinds[s] );
   BIGNUM* bprime = T_bn( T_blind_secret( tag + "-pseudo" ) );
   auto Bk1 = T_blind_secret( tag + "-o1" );
   auto Bk2 = T_blind_secret( tag + "-o2" );
   auto rk1 = fc::ecc::private_key::generate();
   auto rk2 = fc::ecc::private_key::generate();
   stealth_blind_output so1, so2;
   so1.commitment = fc::ecc::blind( Bk1, out1 );
   so2.commitment = fc::ecc::blind( Bk2, out2 );
   if( version == GRAPHENE_STEALTH_PROOF_V1 )
   {
      auto Nk1 = T_secret( tag + "-n1" );
      auto Nk2 = T_secret( tag + "-n2" );
      so1.range_proof = fc::ecc::range_proof_sign( 0, so1.commitment, Bk1, Nk1, 0, 0, out1 );
      so2.range_proof = fc::ecc::range_proof_sign( 0, so2.commitment, Bk2, Nk2, 0, 0, out2 );
   }
   else
   {
      so1.range_proof = T_bp_prove( so1.commitment, Bk1, (uint64_t)out1 );
      so2.range_proof = T_bp_prove( so2.commitment, Bk2, (uint64_t)out2 );
   }
   so1.owner = authority( 1, public_key_type( rk1.get_public_key() ), 1 );
   so2.owner = authority( 1, public_key_type( rk2.get_public_key() ), 1 );
   stealth_transfer_operation stop;
   stop.asset_id = core.get_id();
   stop.proof_version = version;
   stop.fee = core.amount( fee );
   stop.outputs = { so1, so2 };
   {
      BIGNUM* e = BN_new();
      BIGNUM* b1 = T_bn( Bk1 );
      BIGNUM* b2 = T_bn( Bk2 );
      BN_copy( e, bprime );
      BN_mod_sub( e, e, b1, T_order(), T_ctx() );
      BN_mod_sub( e, e, b2, T_order(), T_ctx() );
      unsigned char eb[32]; BN_bn2binpad( e, eb, 32 );
      std::copy( eb, eb + 32, (char*)stop.excess.data() );
      BN_free( e ); BN_free( b1 ); BN_free( b2 );
   }
   std::vector<std::vector<unsigned char>> Q;
   for( const auto& c : p.commits )
      Q.push_back( std::vector<unsigned char>( c.begin(), c.end() ) );
   std::vector<fc::ecc::commitment_type> out_cs = { so1.commitment, so2.commitment };
   auto Pv = T_commit( bprime, (uint64_t)p.each );
   fc::ecc::commitment_type pseudo_c = T_commitment( Pv );
   auto dry = T_dual_dry_run( version, alt_v, Q, s, bs, (uint64_t)p.each, bprime );
   BOOST_REQUIRE( dry.pseudo == Pv );
   std::vector<char> img_c( dry.img_main.begin(), dry.img_main.end() );
   std::vector<char> img_a( dry.img_alt.begin(), dry.img_alt.end() );
   fc::sha256 m = stealth_ring_message( version, stop.asset_id, img_c,
                                        p.commits, pseudo_c, out_cs, stop.fee.amount );
   fc::sha256 ma = stealth_ring_message( alt_v, stop.asset_id, img_a,
                                         p.commits, pseudo_c, out_cs, stop.fee.amount );
   std::string ms( (const char*)m.data(), 32 );
   std::string msa( (const char*)ma.data(), 32 );
   stop.inputs = { T_make_dual_ring_input( version, alt_v, Q, s, bs,
                                           (uint64_t)p.each, bprime, ms, msa ) };
   BN_free( bs ); BN_free( bprime );
   return stop;
}

static int64_t t5_supply( database& db, const asset_object& core )
{
   return core.dynamic_asset_data_id( db ).confidential_supply.value;
}

// M04/V-04: a stealth-spent commitment re-spent via transfer_from_blind.
BOOST_AUTO_TEST_CASE( cross_path_respend_rejected_via_withdrawal )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "t5-wd", 16, true );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 16u );
   // Honest stealth spend of output #5 (1000 -> 600 + 390 + fee 10).
   const size_t s = 5;
   stealth_transfer_operation stop = t5_build_spend( core, p, s,
      GRAPHENE_STEALTH_PROOF_V1, "t5-wd-sp", 600, 390, 10 );
   BOOST_CHECK_NO_THROW( stop.validate() );
   trx.operations = { stop };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   const int64_t live = t5_supply( db, core );
   BOOST_REQUIRE_EQUAL( live, p.funded_total - 10 ); // 16000 - fee
   // Re-spend the SAME commitment via transfer_from_blind (owner-signed,
   // conservation-exact: 990 + 10 == 1000 under the true blind).
   transfer_from_blind_operation x;
   x.to = dan.id;
   x.amount = core.amount( 990 );
   x.fee = core.amount( 10 );
   blind_input bi; bi.commitment = p.commits[s]; bi.owner = p.owners[s];
   x.inputs = { bi };
   x.blinding_factor = p.blinds[s];
   BOOST_CHECK_NO_THROW( x.validate() ); // relay shape is fine...
   set_expiration( db, trx );
   trx.operations = { x };
   sign( trx, p.keys[s] );
   // Task 3: post-fork balances refuse the legacy legs — the ring spend left
   // this commitment indexed with metadata, so op41 routes to op108.
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "post-fork transfer_from_blind must be routed to stealth_explicit_spend" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "stealth_explicit_spend" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
   // Supply identity: the refused re-spend moved nothing; the test ledger
   // (15 live deposits + 600 + 390) matches the chain counter.
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live );
   BOOST_CHECK_EQUAL( t5_supply( db, core ), 15 * p.each + 600 + 390 );
} FC_CAPTURE_AND_RETHROW() }

// M04/V-04: a stealth-spent commitment re-spent via blind_transfer.
BOOST_AUTO_TEST_CASE( cross_path_respend_rejected_via_blind_transfer )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "t5-bt", 16, true );
   const size_t s = 5;
   stealth_transfer_operation stop = t5_build_spend( core, p, s,
      GRAPHENE_STEALTH_PROOF_V1, "t5-bt-sp", 600, 390, 10 );
   trx.operations = { stop };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   const int64_t live = t5_supply( db, core );
   BOOST_REQUIRE_EQUAL( live, p.funded_total - 10 );
   // Re-spend the SAME commitment via blind_transfer (1000 -> 990 under the
   // SAME blind + fee 10: conservation-exact with a real range proof).
   blind_transfer_operation btx;
   btx.fee = core.amount( 10 );
   blind_input bi; bi.commitment = p.commits[s]; bi.owner = p.owners[s];
   btx.inputs = { bi };
   blind_output bo;
   bo.owner = p.owners[s];
   auto N = T_secret( "t5-bt-nout" );
   bo.commitment = fc::ecc::blind( p.blinds[s], 990 );
   bo.range_proof = fc::ecc::range_proof_sign( 0, bo.commitment, p.blinds[s], N, 0, 0, 990 );
   btx.outputs = { bo };
   BOOST_CHECK_NO_THROW( btx.validate() );
   set_expiration( db, trx );
   trx.operations = { btx };
   sign( trx, p.keys[s] );
   // Task 3: post-fork balances refuse the legacy legs (spec §6 item 3 keeps
   // the refusal, item 5 changes the reason) — the ring spend left this
   // commitment indexed with metadata, so op40 routes to op108.
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "post-fork blind_transfer must be routed to stealth_explicit_spend" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "stealth_explicit_spend" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live );
   BOOST_CHECK_EQUAL( t5_supply( db, core ), 15 * p.each + 600 + 390 );
} FC_CAPTURE_AND_RETHROW() }

// Forward declarations (Task 3 re-point): the R15 recovery helpers are
// defined with the R15 suite below, but the turnstile cross-path case needs
// them here. Single definitions live below; t5_pool is defined above.
static void T_set_recovery_v2( turnstile_reproof_operation& t,
                               const fc::ecc::commitment_type& I1,
                               const fc::ecc::commitment_type& I2,
                               const std::vector<char>& proof );
static void T_r15_prove_true( const t5_pool& p, size_t s, asset_id_type asset,
                              fc::ecc::commitment_type& I1,
                              fc::ecc::commitment_type& I2,
                              std::vector<char>& proof );
// Task 4: turnstile_migration attaches the true recovery proof (defined with
// the R15 suite below); the turnstile proves on every path now.
static void T_prove_recovery( const std::vector<unsigned char>& C_bytes,
                              const BIGNUM* b, uint64_t v,
                              asset_id_type asset,
                              fc::ecc::commitment_type& I1_out,
                              fc::ecc::commitment_type& I2_out,
                              std::vector<char>& proof_out );

// M04/V-04: a stealth-spent commitment re-spent via turnstile_reproof.
BOOST_AUTO_TEST_CASE( cross_path_respend_rejected_via_turnstile )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "t5-ts", 16, true );
   const size_t s = 5;
   stealth_transfer_operation stop = t5_build_spend( core, p, s,
      GRAPHENE_STEALTH_PROOF_V1, "t5-ts-sp", 600, 390, 10 );
   trx.operations = { stop };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   const int64_t live = t5_supply( db, core );
   BOOST_REQUIRE_EQUAL( live, p.funded_total - 10 );
   // Migrate the SAME commitment (1000 -> V2 990 + fee 10, transparent leg
   // conservation-exact under the revealed blinds).
   turnstile_reproof_operation t;
   t.asset_id = core.get_id();
   t.old_commitment = p.commits[s];
   t.owner = p.owners[s];
   t.new_proof_version = GRAPHENE_STEALTH_PROOF_V2;
   stealth_blind_output no;
   auto Bn = T_blind_secret( "t5-ts-bn" );
   {
      BIGNUM* bnn = T_bn( Bn );
      no.commitment = T_commitment( T_commit( bnn, 990 ) );
      BN_free( bnn );
   }
   no.range_proof = T_bp_prove( no.commitment, Bn, 990 );
   no.owner = p.owners[s];
   t.new_output = no;
   t.fee = core.amount( 10 );
   t.old_blind = p.blinds[s];
   t.new_blind = Bn;
   // Task 3: the retired flag no longer refuses this (the no-extension hole,
   // pinned by op106_turnstile_without_extension_refuses, closed in Task 4) — submit WITH
   // the true extension so the production nullifier guard decides, exactly
   // as a wallet-driven recovery of a really-spent output would.
   {
      fc::ecc::commitment_type I1, I2; std::vector<char> proof;
      T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
      T_set_recovery_v2( t, I1, I2, proof );
   }
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "turnstile recovery of a nullified output must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "nullifier" ) != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live );
   BOOST_CHECK_EQUAL( t5_supply( db, core ), 15 * p.each + 600 + 390 );
} FC_CAPTURE_AND_RETHROW() }

// M05/GC-07: the same opening (b,v) spent under V1, then under V2.
BOOST_AUTO_TEST_CASE( cross_version_double_spend_rejected )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "t5-xv", 16, true );
   stealth_transfer_operation v1 = t5_build_spend( core, p, 5,
      GRAPHENE_STEALTH_PROOF_V1, "t5-xv-1", 600, 390, 10 );
   trx.operations = { v1 };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   BOOST_REQUIRE_EQUAL( t5_supply( db, core ), p.funded_total - 10 );
   // Same opening, fresh outputs, now versioned V2: the V1 leg already
   // nullified this opening's images, so consensus must refuse — at the
   // nullifier gate. Top the pool up with cost-path deposits and a direct
   // pool top-up (the honest spend grew it 16 + 2) — no time jump, so no
   // maintenance recomputes burn-critical under the attempt.
   for( int i = 0; i < 14; ++i )
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 1000 );
      ttb.from = dan.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_blind_secret( "t5-xv-top-b|" + std::to_string( i ) );
      auto N = T_secret( "t5-xv-top-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, 1000 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 1000 );
      ttb.blinding_factor = B;
      ttb.fee = core.amount( 1000000 ); // cost path
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      generate_block();
   }
   set_expiration( db, trx );
   // Live-set counter (Task 3): 16 funded + 2 from the honest spend + 14
   // cost-path top-ups (the ring removed nothing) = 32 decoy candidates.
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 32u );
   g1c_seed_pool( db, dan_id, core, 5000000 );
   stealth_transfer_operation v2 = t5_build_spend( core, p, 5,
      GRAPHENE_STEALTH_PROOF_V2, "t5-xv-2", 600, 390, 10 );
    trx.operations = { v2 };
    try
    {
       PUSH_TX( db, trx );
       BOOST_FAIL( "cross-version same-opening spend must reject" );
    }
   catch( const fc::exception& e )
   {
      // Nullifier gate (not the retired spent-membership gate): the exact
      // new message pins the refusal reason.
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Key image already spent" ) != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear();
   // Supply identity: the refused re-spend moved nothing (the 14 cost-path
   // top-ups added 14x1000 of live value before it).
   BOOST_CHECK_EQUAL( t5_supply( db, core ), p.funded_total - 10 + 14 * 1000 );
} FC_CAPTURE_AND_RETHROW() }

// V-05: the surviving post-sunset path, end to end (V2 rings + BP+ outputs).
// Also pins the dual linkage: exactly two nullifiers per one-input spend.
BOOST_AUTO_TEST_CASE( v2_stealth_transfer_end_to_end )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "t5-v2", 16, true );
   const size_t nul_before =
      db.get_index_type<stealth_nullifier_index>().indices().size();
   stealth_transfer_operation v2 = t5_build_spend( core, p, 5,
      GRAPHENE_STEALTH_PROOF_V2, "t5-v2-sp", 600, 390, 10 );
   BOOST_CHECK_NO_THROW( v2.validate() );
   trx.operations = { v2 };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   const size_t nul_after =
      db.get_index_type<stealth_nullifier_index>().indices().size();
   BOOST_CHECK_EQUAL( nul_after - nul_before, 2u ); // main + alternate image
   const auto& idx = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
    BOOST_CHECK( idx.find( v2.outputs[0].commitment ) != idx.end() );
    BOOST_CHECK( idx.find( v2.outputs[1].commitment ) != idx.end() );
     BOOST_CHECK( idx.find( p.commits[5] ) != idx.end() ); // retained (still live)
     // Live-set pool counter (Task 3): 16 funded, the ring removes nothing,
     // 2 outputs created -> 18 decoy candidates.
     BOOST_CHECK_EQUAL( stealth_pool_depth( db, core.get_id() ), 18u );
   BOOST_CHECK_EQUAL( t5_supply( db, core ), p.funded_total - 10 );
} FC_CAPTURE_AND_RETHROW() }

// V-05: V1 ring spends stay frozen past sunset (spend-only-via-turnstile).
BOOST_AUTO_TEST_CASE( v1_stealth_transfer_refused_post_sunset )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "t5-ss", 11, false );
   generate_blocks( stealth_v1_sunset_time( db ) + 10 );
   generate_block();
   set_expiration( db, trx );
   // The ~1-year jump lapses the parity review: re-arm the subsidized path
   // with a two-member review (Task 6 quorum; turnstile_migration precedent)
   // so the sunset gate is what rejects.
   ACTORS( (alice)(bob) );
   upgrade_to_lifetime_member( alice ); upgrade_to_lifetime_member( bob );
   create_committee_member( alice ); create_committee_member( bob );
   generate_block();
   for( auto voter : { std::make_pair( alice.id, alice_private_key ),
                       std::make_pair( bob.id, bob_private_key ) } )
   {
      parity_review_operation r;
      r.voter = voter.first;
      r.kind = GRAPHENE_STEALTH_REVIEW_PARITY;
      r.note = "parity review ahead of the sunset refusal check";
      signed_transaction tx; tx.operations.push_back( r );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      sign( tx, voter.second );
      PUSH_TX( db, tx );
   }
   set_expiration( db, trx );
   // Otherwise-valid V1 dual spend over the 11-output pool.
   stealth_transfer_operation stop = t5_build_spend( core, p, 5,
      GRAPHENE_STEALTH_PROOF_V1, "t5-ss-sp", 600, 390, 10 );
   trx.operations = { stop };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "V1 stealth spend past sunset must reject" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "sunset" ) != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear();
} FC_CAPTURE_AND_RETHROW() }

// V-05/GC-11: the same key image twice in one op is a same-opening spend.
BOOST_AUTO_TEST_CASE( duplicate_key_image_within_op_rejected )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "t5-di", 11, false );
   stealth_transfer_operation stop = t5_build_spend( core, p, 5,
      GRAPHENE_STEALTH_PROOF_V1, "t5-di-sp", 600, 390, 10 );
   stop.inputs = { stop.inputs[0], stop.inputs[0] }; // same image twice
   trx.operations = { stop };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "duplicate key image within one op must reject" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Duplicate key image" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear();
} FC_CAPTURE_AND_RETHROW() }

// V-05/GC-11: duplicate ring members shrink the real set; consensus refuses
// (validate also refuses at relay: dispatch directly to pin the gate).
BOOST_AUTO_TEST_CASE( duplicate_ring_member_rejected_consensus )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "t5-dm", 11, false );
   stealth_transfer_operation stop = t5_build_spend( core, p, 5,
      GRAPHENE_STEALTH_PROOF_V1, "t5-dm-sp", 600, 390, 10 );
   stop.inputs[0].ring[1] = stop.inputs[0].ring[0];
   transaction_evaluation_state es( &db );
   try
   {
      db.apply_operation( es, operation( stop ) );
      BOOST_FAIL( "duplicate ring member must fail closed in do_evaluate" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Duplicate ring member" )
                           != std::string::npos, e.to_detail_string() );
   }
} FC_CAPTURE_AND_RETHROW() }

// GC-11: a non-canonical (>= n) scalar in the ALT leg must reject — proving
// the alternate signature is VERIFIED, not merely parsed (a lying prover's
// garbage alt would otherwise bypass the cross-version linkage).
BOOST_AUTO_TEST_CASE( non_canonical_alt_scalar_rejected )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "t5-nc", 16, true );
   stealth_transfer_operation stop = t5_build_spend( core, p, 5,
      GRAPHENE_STEALTH_PROOF_V1, "t5-nc-sp", 600, 390, 10 );
   // 0xFF..FF is >= the curve order: rb_0 of the alt leg is non-canonical.
   std::fill( stop.inputs[0].alt_ring_sig.begin() + 32,
              stop.inputs[0].alt_ring_sig.begin() + 64, (char)0xFF );
   trx.operations = { stop };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "non-canonical alt scalar must reject" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Ring signature does not verify" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear();
} FC_CAPTURE_AND_RETHROW() }

// V-05: pre-fork (grandfathered, metadata-absent) outputs are NEVER decoys.
BOOST_AUTO_TEST_CASE( grandfathered_output_not_decoy_eligible )
{ try {
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   transfer( account_id_type()( db ), dan, core.amount( 500000000 ) );
   // One pre-fork blind output (no creation metadata: created_block == 0).
   fc::ecc::commitment_type pre_c;
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 1000 );
      ttb.from = dan.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_blind_secret( "t5-gf-pre-b" );
      auto N = T_secret( "t5-gf-pre-n" );
      o.commitment = fc::ecc::blind( B, 1000 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 1000 );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      pre_c = o.commitment;
   }
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "t5-gf", 11, false );
   // Valid dual spend shape, then swap one member for the grandfathered one
   // (sigs no longer verify — but the metadata gate fires first).
   stealth_transfer_operation stop = t5_build_spend( core, p, 5,
      GRAPHENE_STEALTH_PROOF_V1, "t5-gf-sp", 600, 390, 10 );
   stop.inputs[0].ring[0] = pre_c;
   trx.operations = { stop };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "grandfathered ring member must reject" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Grandfathered" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear();
} FC_CAPTURE_AND_RETHROW() }

// SUP-03: amount/fee asset confusion must fail in CONSENSUS (do_evaluate),
// not only in relay-side validate (proposal-embedded ops bypass validate).
BOOST_AUTO_TEST_CASE( transfer_from_blind_asset_gate_consensus )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   transfer( account_id_type()( db ), dan, core.amount( 500000000 ) );
   generate_block(); // seal before direct pool seeding (G1c pattern)
   g1c_seed_pool( db, dan_id, core, 2000000 );
   fc::ecc::commitment_type c;
   authority own;
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 1000 );
      ttb.from = dan.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_blind_secret( "t5-sup-b" );
      auto N = T_secret( "t5-sup-n" );
      o.commitment = fc::ecc::blind( B, 1000 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 1000 );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      c = o.commitment;
      own = o.owner;
   }
   generate_block(); // seal BEFORE grandfathering (see T_grandfather note)
   // Task 3: the control leg below must reach the asset gate (and apply),
   // not the legacy-leg created_block gate — grandfather the sealed balance.
   T_grandfather( db, core.get_id(), c );
   // Mismatched assets, validate bypassed: the consensus gate must refuse.
   transfer_from_blind_operation bad;
   bad.to = dan.id;
   bad.amount = asset( 90, asset_id_type( 7 ) );
   bad.fee = core.amount( 10 );
   blind_input bi; bi.commitment = c; bi.owner = own;
   bad.inputs = { bi };
   bad.blinding_factor = T_blind_secret( "t5-sup-b" );
   {
      transaction_evaluation_state es( &db );
      try
      {
         db.apply_operation( es, operation( bad ) );
         BOOST_FAIL( "cross-asset transfer_from_blind must fail closed in do_evaluate" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "must be the same asset" )
                              != std::string::npos, e.to_detail_string() );
      }
   }
   // Control: the matching-asset shape dispatches past the gate (and applies).
   {
      transfer_from_blind_operation good = bad;
      good.amount = core.amount( 990 );
      transaction_evaluation_state es( &db );
      BOOST_CHECK_NO_THROW( db.apply_operation( es, operation( good ) ) );
   }
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( per_block_cap_enforced )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_MAX_BLIND_TX_PER_BLOCK, 100u );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), dan, core.amount( 200000000 ) );
   // G1c cost path (BSIP-2 §2): 100+ deposits in ONE block exceed the
   // 50-subsidy cap, so pay the pinned cost anchor (5 + 5*1 BTS = 1M CORE)
   // per deposit from transparent funds — no pool, no subsidy-cap units,
   // and the 100-op blind budget still binds at the 101st exactly as before.
   // Pre-fill a deep pool first (11 honest blinds, sealed per block so the
   // cap under test never trips during setup).
   for( int i = 0; i < 11; ++i )
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 100 );
      ttb.from = dan.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      ttb.fee = core.amount( 1000000 ); // G1c cost path (pinned anchor, n=1)
      auto B = T_secret( "g1b-prefill-b|" + std::to_string( i ) );
      auto N = T_secret( "g1b-prefill-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, 100 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 100 );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      generate_block();
   }
   // Fill the block's blind budget with 100 cheap honest blinds in ONE block.
   set_expiration( db, trx );
   for( int i = 0; i < 100; ++i )
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 100 );
      ttb.from = dan.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
         o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
         ttb.fee = core.amount( 1000000 ); // G1c cost path (pinned anchor, n=1)
         auto B = T_secret( "g1b-cap-b|" + std::to_string( i ) );
      auto N = T_secret( "g1b-cap-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, 100 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 100 );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
   }
   BOOST_CHECK_EQUAL( stealth_blind_count_this_block( db ), 100u );
   // The 101st blind op in the same block trips the cap.
   transfer_to_blind_operation over;
   over.amount = core.amount( 100 );
   over.from = dan.id;
   auto k = fc::ecc::private_key::generate();
   blind_output o;
   o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
   auto B = T_secret( "g1b-cap-b|over" );
   auto N = T_secret( "g1b-cap-n|over" );
   o.commitment = fc::ecc::blind( B, 100 );
   o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 100 );
   over.blinding_factor = B;
   over.fee = core.amount( 1000000 ); // G1c cost path: budget (not float) rejects
   over.outputs = { o };
   trx.operations = { over };
   sign( trx, dan_private_key );
   BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
   trx.clear();
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( tripwire_fires_on_divergence )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), dan, core.amount( 400000000 ) );
   // G1c parity economics (BSIP-2 §2): seed the pool so the 11 honest blinds
   // run subsidized; the halted-op rejection below still throws on the blind
   // gate (checked before any fee logic), and teardown supply math counts
   // the pool exactly. Sealed first (see the seal-then-modify note in
   // negative_mint_rejected).
   generate_block();
   g1c_seed_pool( db, dan_id, core, 15000000 );
   for( int i = 0; i < 11; ++i )
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 100 );
      ttb.from = dan.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_secret( "g1b-trip-b|" + std::to_string( i ) );
      auto N = T_secret( "g1b-trip-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, 100 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 100 );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      generate_block();
   }
   BOOST_CHECK( !stealth_blind_halted( db ) );
   BOOST_CHECK( !stealth_asset_halted( db, core.get_id() ) );
   // Induce divergence exactly like a verifier-bug mint would: bump the
   // aggregate counter without creating spendable outputs.
   db.modify( core.dynamic_asset_data_id( db ), []( asset_dynamic_data_object& d ) {
      d.confidential_supply += 1000;
   } );
   stealth_reconcile_supplies( db ); // maintenance-interval reconciliation
   // Task 6 (SUP-07): per-asset scope — the diverged asset is recorded, the
   // GLOBAL flag does NOT flap (healthy assets keep moving; committee action
   // stays committee-only).
   BOOST_CHECK( !stealth_blind_halted( db ) );
   BOOST_CHECK( stealth_asset_halted( db, core.get_id() ) );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK( st.diverged_assets.find( core.get_id() ) != st.diverged_assets.end() );
   }
   BOOST_CHECK( stealth_tripwire_fire_block( db ) > 0 );
   // While halted, even honest blind ops of the diverged asset reject
   // (fail-closed at the per-asset gate, before any fee logic).
   transfer_to_blind_operation ttb;
   ttb.amount = core.amount( 100 );
   ttb.from = dan.id;
   auto k = fc::ecc::private_key::generate();
   blind_output o;
   o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
   auto B = T_secret( "g1b-trip-b|halted" );
   auto N = T_secret( "g1b-trip-n|halted" );
   o.commitment = fc::ecc::blind( B, 100 );
   o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 100 );
   ttb.blinding_factor = B;
   ttb.outputs = { o };
   set_expiration( db, trx );
   trx.operations = { ttb };
   sign( trx, dan_private_key );
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "diverged-asset blind op must reject at the asset gate" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "halted" ) != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear();
   // Cleanup: repair the intentionally-induced divergence so the fixture
   // teardown's supply verification (which runs after every test) sees a
   // consistent chain. The tripwire assertions above already recorded the
   // fire; this only restores teardown invariants.
   db.modify( core.dynamic_asset_data_id( db ), []( asset_dynamic_data_object& d ) {
      d.confidential_supply -= 1000;
   } );
   stealth_reconcile_supplies( db ); // healing: the asset leaves the set
   BOOST_CHECK( !stealth_asset_halted( db, core.get_id() ) );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK( st.diverged_assets.empty() );
   }
} FC_CAPTURE_AND_RETHROW() }

/// Shadow-ahead divergence (stealth_evaluator.cpp stealth_reconcile_supplies,
/// SUP-07): the tripwire fires in BOTH directions — not only when live
/// confidential_supply runs ahead of the shadow (tripwire_fires_on_divergence)
/// but when the SHADOW runs ahead of live (e.g. a fee-credit bookkeeping slip
/// that inflates the shadow without moving the counter). While diverged the
/// asset's blind ops reject at the asset gate; healing (shadow back to live)
/// drops it from the set with no vote.
BOOST_AUTO_TEST_CASE( shadow_ahead_divergence_halts_asset )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()(db), dan, core.amount( 400000000 ) );
   generate_block();
   g1c_seed_pool( db, dan_id, core, 15000000 );

   BOOST_REQUIRE( !stealth_asset_halted( db, core_id ) );
   // Push the SHADOW ahead of live (live untouched): +1000 with no backing
   // counter move — the opposite direction from the live-ahead case.
   db.modify( *db.get_index_type<stealth_status_index>().indices().begin(),
              []( stealth_status_object& s ) {
         auto itr = s.blinded_supply_shadow.find( asset_id_type() );
         if( itr == s.blinded_supply_shadow.end() )
            s.blinded_supply_shadow[ asset_id_type() ] = share_type( 1000 );
         else
            itr->second += 1000;
      } );
   stealth_reconcile_supplies( db );
   BOOST_CHECK( !stealth_blind_halted( db ) ); // no global flap
   BOOST_CHECK( stealth_asset_halted( db, core_id ) );
   BOOST_CHECK( stealth_tripwire_fire_block( db ) > 0 );

   // While shadow-ahead, honest blind ops of the asset reject fail-closed.
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 100 );
      ttb.from = dan.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_secret( "g1b-shadow-ahead-b" );
      auto N = T_secret( "g1b-shadow-ahead-n" );
      o.commitment = fc::ecc::blind( B, 100 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 100 );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      try
      {
         PUSH_TX( db, trx );
         BOOST_FAIL( "shadow-ahead diverged-asset blind op must reject" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "halted" ) != std::string::npos,
                              e.to_detail_string() );
      }
      trx.clear();
   }

   // Heal: shadow back to live, reconcile drops the asset, ops proceed.
   db.modify( *db.get_index_type<stealth_status_index>().indices().begin(),
              []( stealth_status_object& s ) {
         auto itr = s.blinded_supply_shadow.find( asset_id_type() );
         BOOST_REQUIRE( itr != s.blinded_supply_shadow.end() );
         itr->second -= 1000;
      } );
   stealth_reconcile_supplies( db );
   BOOST_CHECK( !stealth_asset_halted( db, core_id ) );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK( st.diverged_assets.empty() );
   }
} FC_CAPTURE_AND_RETHROW() }

// Task 6 (SUP-07): per-asset halt scope end to end — a diverged UIA halts
// while CORE blind ops proceed; the committee resume quorum is refused while
// the diverged set is non-empty and clears after healing.
BOOST_AUTO_TEST_CASE( per_asset_halt_scope )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (alice)(bob)(carol)(dan) );
   upgrade_to_lifetime_member( alice ); upgrade_to_lifetime_member( bob );
   upgrade_to_lifetime_member( carol ); upgrade_to_lifetime_member( dan );
   create_committee_member( alice ); create_committee_member( bob );
   create_committee_member( carol ); create_committee_member( dan );
   generate_block();
   const asset_object& core = asset_id_type()(db);
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()(db), dan, core.amount( 400000000 ) );
   const asset_object& uia = create_user_issued_asset( "HALTUIA" );
   const asset_id_type uia_id = uia.get_id();
   issue_uia( dan, uia.amount( 100000000 ) );
   generate_block();
   // Baseline: both assets unhalted.
   BOOST_CHECK( !stealth_asset_halted( db, core_id ) );
   BOOST_CHECK( !stealth_asset_halted( db, uia_id ) );
   BOOST_CHECK( !stealth_blind_halted( db ) );
   // Diverge the UIA only (bump its blind counter with no backing output).
   // Test-harness note: the fixture verifies liquid+confidential==current
   // after every push, so current_supply is bumped alongside — the tripwire
   // input under test is shadow-vs-confidential only (current is irrelevant
   // to reconciliation); both bumps are repaired on healing below.
   // Re-fetch by id (Task 7 note): block production resets the pending undo
   // session, destroying pending-created objects and recreating them at new
   // addresses — a db.get const-ref captured before a generate_block may
   // dangle after it. IDs stay valid; refs do not.
   db.modify( uia_id( db ).dynamic_asset_data_id( db ), []( asset_dynamic_data_object& d ) {
      d.confidential_supply += 500;
      d.current_supply += 500;
   } );
   stealth_reconcile_supplies( db );
   BOOST_CHECK( stealth_asset_halted( db, uia_id ) );
   BOOST_CHECK( !stealth_asset_halted( db, core_id ) );
   BOOST_CHECK( !stealth_blind_halted( db ) ); // no global flap
   // The diverged asset's blind ops reject at the asset gate...
   // (uia re-fetched by id — see the pending-session note above).
   {
      transfer_to_blind_operation ttb;
      ttb.amount = uia_id( db ).amount( 100 );
      ttb.from = dan.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_secret( "t6-halt-uia-b" );
      auto N = T_secret( "t6-halt-uia-n" );
      o.commitment = fc::ecc::blind( B, 100 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 100 );
      ttb.blinding_factor = B;
      ttb.fee = uia_id( db ).amount( 2000000 ); // generous: the asset gate fires first
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
      trx.clear_signatures(); trx.operations.clear();
   }
   // ...while the healthy asset's blind ops proceed (per-asset scope).
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 100 );
      ttb.from = dan.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_secret( "t6-halt-core-b" );
      auto N = T_secret( "t6-halt-core-n" );
      o.commitment = fc::ecc::blind( B, 100 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 100 );
      ttb.blinding_factor = B;
      ttb.fee = core.amount( 1000000 ); // cost path
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
      trx.clear_signatures(); trx.operations.clear();
      generate_block();
   }
   // A full 3-member resume quorum is REFUSED while the set is non-empty:
   // the test engages the global halt first (freeze quorum), then resumes.
   auto cast_freeze = [&]( const account_object& who, const private_key_type& key, bool freeze ) {
      freeze_blind_operation fz;
      fz.voter = who.id; fz.freeze = freeze; fz.reason = "scope test";
      signed_transaction tx; tx.operations.push_back( fz );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      sign( tx, key );
      PUSH_TX( db, tx );
   };
   cast_freeze( alice, alice_private_key, true );
   cast_freeze( bob, bob_private_key, true );
   cast_freeze( carol, carol_private_key, true );
   BOOST_REQUIRE( stealth_blind_halted( db ) );
   cast_freeze( alice, alice_private_key, false );
   cast_freeze( bob, bob_private_key, false );
   cast_freeze( carol, carol_private_key, false );
   BOOST_CHECK( stealth_blind_halted( db ) ); // refused: UIA still diverged
   // Heal the UIA: repair both bumps + reconcile drops it from the set.
   // Ordering law (fixture undo sessions): no generate_block may intervene
   // between a direct db.modify and the quorum re-evaluation below — block
   // production resets the pending undo session and would roll the heal back
   // while replaying only pushed transactions. Same-block pushes re-evaluate
   // immediately, so the fresh fourth member (dan never voted: no duplicate
   // hazard) re-triggers the quorum on the healed state directly.
   // (uia re-fetched by id — see the pending-session note above.)
   db.modify( uia_id( db ).dynamic_asset_data_id( db ), []( asset_dynamic_data_object& d ) {
      d.confidential_supply -= 500;
      d.current_supply -= 500;
   } );
   stealth_reconcile_supplies( db );
   BOOST_CHECK( !stealth_asset_halted( db, uia_id ) );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK( st.diverged_assets.empty() );
   }
   // The same quorum that was refused while diverged now clears the halt.
   cast_freeze( dan, dan_private_key, false );
   BOOST_CHECK( !stealth_blind_halted( db ) );
   verify_asset_supplies( db );
   generate_block();
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( freeze_blind_committee_backup )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_FREEZE_VOTES_REQUIRED, 3u );
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_FREEZE_VOTE_EXPIRY_SEC, 86400u );
   ACTORS( (alice)(bob)(carol)(dan) );
   upgrade_to_lifetime_member( alice ); upgrade_to_lifetime_member( bob );
   upgrade_to_lifetime_member( carol );
   create_committee_member( alice ); create_committee_member( bob );
   create_committee_member( carol );
   generate_block();
   BOOST_CHECK( !stealth_blind_halted( db ) );
   auto cast_vote = [&]( const account_object& who, const private_key_type& key, bool freeze ) {
      freeze_blind_operation fz;
      fz.voter = who.id; fz.freeze = freeze; fz.reason = "quorum test";
      signed_transaction tx; tx.operations.push_back( fz );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      sign( tx, key );
      PUSH_TX( db, tx );
   };
   // One vote is not enough.
   cast_vote( alice, alice_private_key, true );
   BOOST_CHECK( !stealth_blind_halted( db ) );
   // Two votes are not enough either (Task 6: 2-vote freeze now refused —
   // any two colluding members could halt alone under the old quorum).
   cast_vote( bob, bob_private_key, true );
   BOOST_CHECK( !stealth_blind_halted( db ) );
   // Third distinct member vote engages the halt.
   cast_vote( carol, carol_private_key, true );
   BOOST_CHECK( stealth_blind_halted( db ) );
   // Non-member votes never count.
   {
      freeze_blind_operation fz;
      fz.voter = dan.id;
      fz.freeze = true;
      fz.reason = "grief";
      signed_transaction tx; tx.operations.push_back( fz );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      sign( tx, dan_private_key );
      BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
   }
   // Three resume votes lift the halt (one or two are not enough).
   cast_vote( alice, alice_private_key, false );
   BOOST_CHECK( stealth_blind_halted( db ) );
   cast_vote( bob, bob_private_key, false );
   BOOST_CHECK( stealth_blind_halted( db ) );
   cast_vote( carol, carol_private_key, false );
   BOOST_CHECK( !stealth_blind_halted( db ) );
   // Vote freshness boundary (pure function): 24h fresh, 24h+1 stale.
   {
      auto now = db.head_block_time();
      BOOST_CHECK( stealth_vote_fresh( now, now ) );
      BOOST_CHECK( stealth_vote_fresh( now, now - GRAPHENE_STEALTH_FREEZE_VOTE_EXPIRY_SEC ) );
      BOOST_CHECK( !stealth_vote_fresh( now, now - GRAPHENE_STEALTH_FREEZE_VOTE_EXPIRY_SEC - 1 ) );
   }
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( turnstile_migration )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   // V1 sunset is dated at activation (turnstile G2): activation + lifetime.
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_V1_LIFETIME_SEC, 31536000u );
   BOOST_CHECK( stealth_v1_sunset_time( db ) ==
                HARDFORK_STEALTH_TIME + GRAPHENE_STEALTH_V1_LIFETIME_SEC );
   BOOST_CHECK( stealth_turnstile_g2_time( db ) == stealth_v1_sunset_time( db ) );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), dan, core.amount( 400000000 ) );
   // G1c parity economics (BSIP-2 §2): 11 deposits (1M gap each) + the
   // turnstile migration (1M gap, fee-10 conservation-bound) run subsidized.
   // Sealed first (see the seal-then-modify note in negative_mint_rejected).
   generate_block();
   g1c_seed_pool( db, dan_id, core, 15000000 );
   // Fund V1 blind balances pre-sunset (11 for the pool floor).
   auto k = fc::ecc::private_key::generate();
   authority own( 1, public_key_type( k.get_public_key() ), 1 );
   blinded_balance_id_type target;
   fc::ecc::commitment_type target_c;
   for( int i = 0; i < 11; ++i )
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 100 );
      ttb.from = dan.id;
      blind_output o;
      o.owner = own;
      auto B = T_blind_secret( "g1b-turn-b|" + std::to_string( i ) );
      auto N = T_secret( "g1b-turn-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, 100 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 100 );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      generate_block();
      if( i == 0 )
      {
         const auto& idx = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
         auto itr = idx.find( o.commitment );
         BOOST_REQUIRE( itr != idx.end() );
         target = itr->get_id();
         target_c = o.commitment;
         // Task 3: the legacy-spend rejection below must fire at the V1
         // sunset gate, not the legacy-leg created_block gate — the turnstile
         // migration after it exercises the same balance on the R15 path.
         T_grandfather( db, core.get_id(), o.commitment );
      }
   }
   // Pass the V1 sunset.
   generate_blocks( stealth_v1_sunset_time( db ) + 10 );
   generate_block();
   set_expiration( db, trx );
   // G1c parity economics (BSIP-2 §2): the ~1-year jump lapses the 6-month
   // parity review, so subsidies float to cost by rule. A two-member
   // committee review (Task 6 quorum) re-arms the pool-funded path the
   // migration below exercises (missed quarterly reports halt funding only
   // — the pre-seeded pool keeps paying). The legacy-spend rejection above
   // needs no subsidy: the sunset gate throws before any fee logic.
   ACTORS( (alice)(bob) );
   upgrade_to_lifetime_member( alice ); upgrade_to_lifetime_member( bob );
   create_committee_member( alice ); create_committee_member( bob );
   generate_block();
   for( auto voter : { std::make_pair( alice.id, alice_private_key ),
                       std::make_pair( bob.id, bob_private_key ) } )
   {
      parity_review_operation r;
      r.voter = voter.first;
      r.kind = GRAPHENE_STEALTH_REVIEW_PARITY;
      r.note = "parity review ahead of turnstile migration window";
      signed_transaction tx; tx.operations.push_back( r );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      sign( tx, voter.second );
      PUSH_TX( db, tx );
   }
   set_expiration( db, trx );
   // Legacy V1 spend past sunset is spend-only-via-turnstile.
   {
      transfer_from_blind_operation x;
      x.to = dan.id;
      x.amount = core.amount( 90 );
      x.fee = core.amount( 10 );
      blind_input bi; bi.commitment = target_c; bi.owner = own;
      x.inputs = { bi };
      // The TRUE input blind: conservation passes validate, so the V1
      // sunset gate (not conservation) is what rejects this spend.
      x.blinding_factor = T_blind_secret( "g1b-turn-b|0" );
      trx.operations = { x };
      sign( trx, k );
      BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
      trx.clear_signatures(); trx.operations.clear();
   }
   // Turnstile re-proof migrates the balance to V2 (fee 10 explicit).
   {
      turnstile_reproof_operation t;
      t.asset_id = core.get_id();
      t.old_commitment = target_c;
      t.owner = own;
      t.new_proof_version = GRAPHENE_STEALTH_PROOF_V2;
      stealth_blind_output no;
      auto Bn = T_blind_secret( "g1b-turn-bn" );
      // new output commits to 90; excess: b_old - b_new revealed for the
      // conservation check (migration leg is transparent by design).
      {
         BIGNUM* bnn = T_bn( Bn );
         no.commitment = T_commitment( T_commit( bnn, 90 ) );
         BN_free( bnn );
      }
      no.range_proof = T_bp_prove( no.commitment, Bn, 90 );
      no.owner = own;
      t.new_output = no;
      t.fee = core.amount( 10 );
      t.old_blind = T_blind_secret( "g1b-turn-b|0" );
      t.new_blind = Bn;
      // Task 4: the R15 extension is mandatory on every path — attach the
      // true recovery proof over the migrated opening (blind "g1b-turn-b|0",
      // value 100) so the migration succeeds under the always-prove rule.
      {
         fc::ecc::commitment_type I1, I2; std::vector<char> proof;
         BIGNUM* bb = T_bn( T_blind_secret( "g1b-turn-b|0" ) );
         std::vector<unsigned char> Cvec( target_c.begin(), target_c.end() );
         T_prove_recovery( Cvec, bb, 100, core.get_id(), I1, I2, proof );
         BN_free( bb );
         T_set_recovery_v2( t, I1, I2, proof );
      }
      trx.operations = { t };
      sign( trx, k );
      BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
      trx.clear_signatures(); trx.operations.clear();
   }
   // The migrated V2 output exists as a fresh blinded balance.
   // NOTE (corrected G1b-2): look up by the saved commitment bytes, not via
   // target(db) — the turnstile consumed (removed) the old balance, so
   // dereferencing its id throws "Unable to find Object".
   {
      const auto& idx = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
      BOOST_CHECK( idx.find( target_c ) == idx.end() ); // old consumed
   }
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( bp_plus_vectors_and_budget )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   // BP+ prove/verify round-trip (m=1, 64-bit) through the consensus verifier.
   std::string err;
   fc::ecc::commitment_type Cc;
   std::vector<char> proof;
   {
      auto B = T_secret( "g1b-bp-b" );
      BIGNUM* bb = T_bn( B );
      auto Cv = T_commit( bb, 424242 );
      BN_free( bb );
      std::copy( Cv.begin(), Cv.end(), Cc.begin() );
      proof = T_bp_prove( Cc, B, 424242 );
      BOOST_REQUIRE_MESSAGE( !proof.empty(), "test prover must produce a blob" );
      // Size anchor: the kept G1 wire format is exact (no padded encodings):
      // m || A || A1 || B || r1 || s1 || d1 || 6x(L||R) = 592 bytes for m=1.
      // (G1b-1's "~0.7kB / 600..900" estimate predated the kept verifier's
      // exact-size rule; corrected G1b-2 P3 to stealth_bp_proof_size(1).)
      BOOST_CHECK_MESSAGE( proof.size() == stealth_bp_proof_size( 1 ),
                           "BP+ 1-output blob size " << proof.size()
                           << " != consensus " << stealth_bp_proof_size( 1 ) );
      BOOST_CHECK_MESSAGE( stealth_verify_bp_plus( 1, proof, { Cc }, err ),
                           "BP+ golden proof must verify: " << err );
      for( size_t off : { (size_t)0, proof.size()/2, proof.size()-1 } )
      {
         std::vector<char> bad = proof;
         bad[off] ^= 0x01;
         BOOST_CHECK_MESSAGE( !stealth_verify_bp_plus( 1, bad, { Cc }, err ),
                              "BP+ tampered proof (off " << off << ") must reject" );
      }
      fc::ecc::commitment_type other = Cc; other[5] ^= 0x02;
      BOOST_CHECK_MESSAGE( !stealth_verify_bp_plus( 1, proof, { other }, err ),
                           "BP+ proof against wrong commitment must reject" );
      // Wrong value (same blind, different amount) must reject.
      BIGNUM* bw = T_bn( B );
      auto Cwv = T_commit( bw, 424243 );
      BN_free( bw );
      fc::ecc::commitment_type Cw; std::copy( Cwv.begin(), Cwv.end(), Cw.begin() );
      BOOST_CHECK_MESSAGE( !stealth_verify_bp_plus( 1, proof, { Cw }, err ),
                           "BP+ proof for wrong value must reject" );
   }
    // F-01 remediation (R9B): the two 100x 1-in/1-out loops that stood here
    // modeled a shape consensus never bounds (inputs<=8, outputs<=8,
    // ring<=32, single-version) and understated the permitted worst case
    // ~23x (space-bunny REVIEW §F-01). DELETED, not annotated: the model was
    // the artefact that hid the finding for four rounds. The ring-11 loop
    // went with it (11 is a verifier bound only; the consensus floor is 16,
    // so a ring-11 "worst case" is doubly misleading). The binding
    // constraint is now the per-block verification-WORK budget
    // (GRAPHENE_STEALTH_MAX_BLIND_WORK_US_PER_BLOCK, enforced by
    // stealth_check_blind_work_gate and pinned arithmetically by
    // r9b_work_budget_arithmetic); this leg measures the single-op
    // consensus worst case the budget admits — 8 inputs x ring-32 x DUAL
    // verify + 8 BP+ outputs + kernel — and hard-gates it under the
    // 750000us envelope (best of 9 passes over 2 unmeasured warmup
    // iterations, scheduling-noise robust — container hardware varies pass
    // to pass by tens of percent; R10A hardening, gate value unchanged).
    // Witness validation is serial (db_block.cpp "TODO - parallelize"), so
    // one pass here is one block's worth of the offender shape.
    {
       const size_t NK = 8, RK = 32;
       std::string ms( (const char*)T_secret( "r9bW-msg" ).data(), 32 );
       std::string msa( (const char*)T_secret( "r9bW-msg-alt" ).data(), 32 );
       std::vector<stealth_ring_input> rins, alts;
       std::vector<fc::ecc::commitment_type> pins, outs;
       std::vector<std::vector<char>> bproofs;
       std::vector<BIGNUM*> bprimes, gammas;
       for( size_t k = 0; k < NK; ++k )
       {
          std::vector<std::vector<unsigned char>> Qk;
          size_t sk = k;
          BIGNUM* bsk = T_scalar( "r9bW-bs|" + std::to_string( k ) );
          BIGNUM* bpk = T_scalar( "r9bW-bp|" + std::to_string( k ) );
          for( size_t j = 0; j < RK; ++j )
          {
             if( j == sk )
                Qk.push_back( T_commit( bsk, 1000 ) );
             else
                Qk.push_back( T_commit(
                   T_scalar( "r9bW-d|" + std::to_string( k ) + "|" + std::to_string( j ) ),
                   500 + j ) );
          }
          stealth_ring_input rin = T_make_dual_ring_input( GRAPHENE_STEALTH_PROOF_V2,
             GRAPHENE_STEALTH_PROOF_V1, Qk, sk, bsk, 1000, bpk, ms, msa );
          BOOST_REQUIRE_MESSAGE( stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V2, rin, ms, err ),
                                 "worst-case setup V2 leg must verify: " << err );
          pins.push_back( rin.pseudo_output );
          // Evaluator-style alt-leg rebuild (same ring/pseudo, alt image+sig).
          stealth_ring_input alt;
          alt.ring = rin.ring;
          alt.key_image = rin.alt_key_image;
          alt.ring_sig = rin.alt_ring_sig;
          alt.pseudo_output = rin.pseudo_output;
          BOOST_REQUIRE_MESSAGE( stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V1, alt, msa, err ),
                                 "worst-case setup V1 alt leg must verify: " << err );
          rins.push_back( rin );
          alts.push_back( alt );
          bprimes.push_back( bpk );
          BN_free( bsk );
       }
       // 8 outputs of 990 + fee 80 balance the 8x1000 pseudo-inputs.
       for( size_t j = 0; j < NK; ++j )
       {
          auto Gj = T_blind_secret( "r9bW-g|" + std::to_string( j ) );
          fc::ecc::commitment_type Cj = fc::ecc::blind( Gj, 990 );
          std::vector<char> pj = T_bp_prove( Cj, Gj, 990 );
          BOOST_REQUIRE_MESSAGE( !pj.empty(), "worst-case BP+ prove must produce a blob" );
          BOOST_REQUIRE_MESSAGE( stealth_verify_bp_plus( 1, pj, { Cj }, err ),
                                 "worst-case BP+ setup must verify: " << err );
          outs.push_back( Cj );
          bproofs.push_back( pj );
          gammas.push_back( T_bn( Gj ) );
       }
       BIGNUM* be = BN_new();
       BN_copy( be, bprimes[0] );
       for( size_t k = 1; k < NK; ++k )
          BN_mod_add( be, be, bprimes[k], T_order(), T_ctx() );
       for( auto g : gammas )
          BN_mod_sub( be, be, g, T_order(), T_ctx() );
       unsigned char beb[32]; BN_bn2binpad( be, beb, 32 );
       fc::sha256 bex; std::copy( beb, beb + 32, (char*)bex.data() );
       BOOST_REQUIRE_MESSAGE( stealth_verify_excess( pins, outs, 80, bex, err ),
                              "worst-case kernel setup must verify: " << err );
        // R10A deterministic model pins (no wall-clock, never flake): the
        // per-component unit costs behind the budgeted model, pinned as hard
        // integer arithmetic. The wall-clock below corroborates the model;
        // THIS arithmetic is the deterministic gate.
        {
           const uint64_t WORK_US_PER_RING32_DUAL =
              (uint64_t)2 * 32 * GRAPHENE_STEALTH_WORK_US_PER_RING_MEMBER;
           BOOST_REQUIRE_EQUAL( WORK_US_PER_RING32_DUAL, 77440ull );
           const uint64_t WORK_US_PER_RANGE_PROOF =
              (uint64_t)GRAPHENE_STEALTH_WORK_US_PER_RANGE_PROOF;
           BOOST_REQUIRE_EQUAL( WORK_US_PER_RANGE_PROOF, 6322ull );
           const uint64_t WORK_US_PER_EXCESS =
              (uint64_t)GRAPHENE_STEALTH_WORK_US_PER_KERNEL;
           BOOST_REQUIRE_EQUAL( WORK_US_PER_EXCESS, 2048ull );
           const uint64_t model_worst_case =
              (uint64_t)8 * WORK_US_PER_RING32_DUAL
              + (uint64_t)8 * WORK_US_PER_RANGE_PROOF
              + WORK_US_PER_EXCESS;
           BOOST_REQUIRE_EQUAL( model_worst_case, 672144ull );
           BOOST_REQUIRE_MESSAGE( model_worst_case
                                  <= GRAPHENE_STEALTH_MAX_BLIND_WORK_US_PER_BLOCK,
              "model worst case " << model_worst_case << "us exceeds 750000us budget" );
           // Cross-check: the consensus calculator agrees with the hand model.
           stealth_transfer_operation model_op;
           for( int i = 0; i < 8; ++i )
           {
              stealth_ring_input in;
              in.ring.resize( 32 );
              model_op.inputs.push_back( in );
           }
           model_op.outputs.resize( 8 );
           BOOST_REQUIRE_EQUAL( stealth_work_for_stealth_transfer( model_op ), 672144u );
           BOOST_REQUIRE_MESSAGE(
              stealth_work_for_stealth_transfer( model_op )
              <= GRAPHENE_STEALTH_MAX_BLIND_WORK_US_PER_BLOCK,
              "consensus model worst case exceeds 750000us budget" );
        }
        // R10A warmup (unmeasured): 2 full passes of the offender shape to
        // shake out page-cache/allocator cold start before the measured set.
        for( int warm = 0; warm < 2; ++warm )
        {
           for( size_t k = 0; k < NK; ++k )
           {
              BOOST_REQUIRE( stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V2, rins[k], ms, err ) );
              BOOST_REQUIRE( stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V1, alts[k], msa, err ) );
              BOOST_REQUIRE( stealth_verify_bp_plus( 1, bproofs[k], { outs[k] }, err ) );
           }
           BOOST_REQUIRE( stealth_verify_excess( pins, outs, 80, bex, err ) );
        }
        long long best = -1;
        std::vector<long long> samples;
        samples.reserve( 9 );
        for( int pass = 0; pass < 9; ++pass )
       {
          fc::time_point start = fc::time_point::now();
          for( size_t k = 0; k < NK; ++k )
          {
             BOOST_REQUIRE( stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V2, rins[k], ms, err ) );
             BOOST_REQUIRE( stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V1, alts[k], msa, err ) );
             BOOST_REQUIRE( stealth_verify_bp_plus( 1, bproofs[k], { outs[k] }, err ) );
          }
          BOOST_REQUIRE( stealth_verify_excess( pins, outs, 80, bex, err ) );
           long long us = ( fc::time_point::now() - start ).count();
           BOOST_TEST_MESSAGE( "consensus worst-case pass " << pass << ": " << us << "us" );
           samples.push_back( us );
           if( best < 0 || us < best ) best = us;
        }
        {
           std::ostringstream dist;
           dist << "CONSENSUS WORST-CASE DISTRIBUTION (us): [";
           for( size_t i = 0; i < samples.size(); ++i )
              dist << ( i ? ", " : "" ) << samples[i];
           dist << "] best=" << best;
           BOOST_TEST_MESSAGE( dist.str() );
        }
        BOOST_TEST_MESSAGE( "CONSENSUS WORST CASE " << best
                            << "us (8-in/ring-32/dual + 8 BP+ + kernel, best-of-9 + 2 warmup)" );
       BOOST_REQUIRE_MESSAGE( best <= 750000,
          "CONSENSUS WORST CASE " << best << "us > 750000us" );
       BN_free( be );
       for( auto b : bprimes ) BN_free( b );
       for( auto g : gammas ) BN_free( g );
     }
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( bp_plus_m2_rejected_only_m1_wired )
{ try {
   // R9A safe batch (F-02/F-06): only m=1 is wired to consensus. A
   // well-formed 658-byte m=2 blob (exact size, matching m tag, valid
   // on-curve points, canonical nonzero scalars) over 2 commitments must be
   // rejected cleanly with the wiring error — never accepted, never an OOB
   // read. m in {1,2} stays valid on the wire (size helper untouched).
   BOOST_REQUIRE_EQUAL( stealth_bp_proof_size( 1 ), 592u );
   BOOST_REQUIRE_EQUAL( stealth_bp_proof_size( 2 ), 658u );
   std::vector<unsigned char> G33 = stealth_G_point();
   BOOST_REQUIRE_EQUAL( G33.size(), 33u );
   std::vector<char> blob;
   blob.reserve( 658 );
   blob.push_back( (char)2 ); // m tag matches m=2
   auto push_point = [&]( const std::vector<unsigned char>& p )
      { for( auto b : p ) blob.push_back( (char)b ); };
   push_point( G33 ); // A
   push_point( G33 ); // A1
   push_point( G33 ); // B
   for( int k = 0; k < 3; ++k ) // r1, s1, d1: canonical nonzero scalars
   {
      for( int i = 0; i < 31; ++i ) blob.push_back( (char)0 );
      blob.push_back( (char)1 );
   }
   for( int k = 0; k < 14; ++k ) push_point( G33 ); // 7x (L, R)
   BOOST_REQUIRE_EQUAL( blob.size(), 658u );
   BIGNUM* b1 = T_bn( T_blind_secret( "r9a-m2-b|0" ) );
   BIGNUM* b2 = T_bn( T_blind_secret( "r9a-m2-b|1" ) );
   fc::ecc::commitment_type c1 = T_commitment( T_commit( b1, 100 ) );
   fc::ecc::commitment_type c2 = T_commitment( T_commit( b2, 200 ) );
   BN_free( b1 ); BN_free( b2 );
   std::string err;
   BOOST_CHECK_MESSAGE( !stealth_verify_bp_plus( 2, blob, { c1, c2 }, err ),
                        "m=2 blob must not verify (only m=1 is wired)" );
   BOOST_CHECK_EQUAL( err, "only m=1 is wired" );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( v1_range_claims_observed )
{ try {
   // R9A (F-05): the V1 claimed range is observed, never ignored. Small
   // values prove narrow ranges by construction (min_bits=0 -> mantissa =
   // value bits), so consensus pins min_value==0 fail-closed and documents
   // the operative ceiling [0,2^50) instead of flooring max_value — a floor
   // would reject legitimate small-value proofs (see evaluator call sites).
   for( uint64_t v : { (uint64_t)1000, (uint64_t)GRAPHENE_MAX_SHARE_SUPPLY } )
   {
      auto B = T_blind_secret( "r9a-v1rng|" + std::to_string( v ) );
      auto N = T_secret( "r9a-v1nonce|" + std::to_string( v ) );
      fc::ecc::commitment_type C = fc::ecc::blind( B, v );
      fc::ecc::range_proof_type pr = fc::ecc::range_proof_sign( 0, C, B, N, 0, 0, v );
      BOOST_REQUIRE_MESSAGE( !pr.empty(), "must sign a V1 proof for v=" << v );
      BOOST_CHECK_MESSAGE( pr.size() <= 4096, "V1 proof for v=" << v
         << " must fit the consensus cap, got " << pr.size() << "B" );
      uint64_t min_v = 0, max_v = 0;
      std::vector<char> proof( pr.begin(), pr.end() );
      BOOST_REQUIRE_MESSAGE( stealth_verify_range_v1( C, proof, min_v, max_v ),
         "V1 proof for v=" << v << " must verify" );
      BOOST_CHECK_EQUAL( min_v, 0u );
      BOOST_CHECK_MESSAGE( max_v >= v, "claimed max " << max_v
         << " must cover the proven value " << v );
   }
   // Exact pins: 1000 needs 10 bits -> [0,1023]; max supply needs 50 bits
   // -> [0,2^50), the last range admissible under the 4096-byte cap.
   {
      auto B = T_blind_secret( "r9a-v1rng|pin" );
      auto N = T_secret( "r9a-v1nonce|pin" );
      fc::ecc::commitment_type C = fc::ecc::blind( B, 1000 );
      fc::ecc::range_proof_type pr = fc::ecc::range_proof_sign( 0, C, B, N, 0, 0, 1000 );
      uint64_t min_v = 0, max_v = 0;
      std::vector<char> proof( pr.begin(), pr.end() );
      BOOST_REQUIRE( stealth_verify_range_v1( C, proof, min_v, max_v ) );
      BOOST_CHECK_EQUAL( min_v, 0u );
      BOOST_CHECK_EQUAL( max_v, 1023u );
   }
   {
      auto B = T_blind_secret( "r9a-v1rng|pin50" );
      auto N = T_secret( "r9a-v1nonce|pin50" );
      fc::ecc::commitment_type C = fc::ecc::blind( B, GRAPHENE_MAX_SHARE_SUPPLY );
      fc::ecc::range_proof_type pr = fc::ecc::range_proof_sign(
         0, C, B, N, 0, 0, GRAPHENE_MAX_SHARE_SUPPLY );
      uint64_t min_v = 0, max_v = 0;
      std::vector<char> proof( pr.begin(), pr.end() );
      BOOST_REQUIRE_MESSAGE( stealth_verify_range_v1( C, proof, min_v, max_v ),
         "max-supply proof must fit the cap and verify" );
      BOOST_CHECK_EQUAL( min_v, 0u );
      BOOST_CHECK_EQUAL( max_v, ( (uint64_t)1 << 50 ) - 1 );
   }
} FC_CAPTURE_AND_RETHROW() }

// R9B negative vectors (space-bunny §7 Groups A/B + C1/C2 + E7/E8, F-01
// companion): each asserts the NAMED verifier error string, fail-closed.
// The ring/BP+ verifiers are fail-closed here already (no consensus change
// in this batch for them); these vectors pin the exact strings op-level
// rejections wrap, so a future refactor cannot soften a check silently.
BOOST_AUTO_TEST_CASE( r9b_ring_scalar_canonicality_vectors )
{ try {
   // Group A: c0 / per-member (rb, rv, rd) at (n) or above (n+1) the curve
   // order must reject as non-canonical (S1 is_reduced discipline).
   std::string err;
   const size_t n = 16;
   std::vector<std::vector<unsigned char>> Q;
   for( size_t i = 0; i < n; ++i )
      Q.push_back( T_commit( T_scalar( "r9bA-b|" + std::to_string( i ) ), 500 + i ) );
   BIGNUM* bs = T_scalar( "r9bA-b|7" );
   BIGNUM* bprime = T_scalar( "r9bA-bp" );
   std::string ms( (const char*)T_secret( "r9bA-msg" ).data(), 32 );
   stealth_ring_input good = T_make_ring_input( GRAPHENE_STEALTH_PROOF_V2,
      Q, 7, bs, 507, bprime, ms );
   BOOST_REQUIRE_MESSAGE( stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V2, good, ms, err ),
                          "control must verify: " << err );
   unsigned char nbytes[32], n1bytes[32];
   BN_bn2binpad( T_order(), nbytes, 32 );
   BIGNUM* n1 = BN_new(); BN_copy( n1, T_order() ); BN_add_word( n1, 1 );
   BN_bn2binpad( n1, n1bytes, 32 );
   auto expect_ring_reject = [&]( stealth_ring_input bad, const std::string& why ) {
      err.clear();
      BOOST_CHECK_MESSAGE( !stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V2, bad, ms, err ),
                           why << ": non-canonical scalar must reject" );
      BOOST_CHECK_EQUAL( err, why );
   };
   { stealth_ring_input bad = good; // A1: c0 == n
     std::copy( nbytes, nbytes + 32, bad.ring_sig.begin() );
     expect_ring_reject( bad, "c0 not canonical" ); }
   { stealth_ring_input bad = good; // A2: c0 == n+1
     std::copy( n1bytes, n1bytes + 32, bad.ring_sig.begin() );
     expect_ring_reject( bad, "c0 not canonical" ); }
   { stealth_ring_input bad = good; // A3: rb_0 == n
     std::copy( nbytes, nbytes + 32, bad.ring_sig.begin() + 32 );
     expect_ring_reject( bad, "responses not canonical" ); }
   { stealth_ring_input bad = good; // A4: rv_0 == n
     std::copy( nbytes, nbytes + 32, bad.ring_sig.begin() + 64 );
     expect_ring_reject( bad, "responses not canonical" ); }
   { stealth_ring_input bad = good; // A5: rd_0 == n
     std::copy( nbytes, nbytes + 32, bad.ring_sig.begin() + 96 );
     expect_ring_reject( bad, "responses not canonical" ); }
   { stealth_ring_input bad = good; // A3-last: rb_{n-1} == n (per-member)
     std::copy( nbytes, nbytes + 32, bad.ring_sig.begin() + 32 + 96 * ( n - 1 ) );
     expect_ring_reject( bad, "responses not canonical" ); }
   BN_free( n1 ); BN_free( bs ); BN_free( bprime );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( r9b_point_encoding_vectors )
{ try {
   // Group B: every 33-byte point field on the ring/BP+ path is strictly
   // parsed (prefix + oct2point + on-curve + non-identity). Infinity has no
   // compressed encoding, so an identity smuggle must arrive as an invalid
   // encoding — pinned with a bad-prefix vector alongside the off-curve
   // (x >= p) vector for each field.
   std::string err;
   const size_t n = 16;
   std::vector<std::vector<unsigned char>> Q;
   for( size_t i = 0; i < n; ++i )
      Q.push_back( T_commit( T_scalar( "r9bB-b|" + std::to_string( i ) ), 500 + i ) );
   BIGNUM* bs = T_scalar( "r9bB-b|7" );
   BIGNUM* bprime = T_scalar( "r9bB-bp" );
   std::string ms( (const char*)T_secret( "r9bB-msg" ).data(), 32 );
   stealth_ring_input good = T_make_ring_input( GRAPHENE_STEALTH_PROOF_V2,
      Q, 7, bs, 507, bprime, ms );
   BOOST_REQUIRE_MESSAGE( stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V2, good, ms, err ),
                          "control must verify: " << err );
   std::vector<char> img_prefix( 33, 0 ); img_prefix[0] = 0x04;
   std::vector<char> img_curve( 33, (char)0xFF ); img_curve[0] = 0x02;
   std::vector<unsigned char> pt_prefix( 33, 0x00 ); pt_prefix[0] = 0x04;
   std::vector<unsigned char> pt_curve( 33, 0xFF ); pt_curve[0] = 0x02;
   auto to_commit = []( const std::vector<unsigned char>& v ) {
      fc::ecc::commitment_type c;
      BOOST_REQUIRE( v.size() == 33 );
      std::copy( v.begin(), v.end(), c.begin() );
      return c;
   };
   auto expect_ring_reject = [&]( stealth_ring_input bad, const std::string& why ) {
      err.clear();
      BOOST_CHECK_MESSAGE( !stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V2, bad, ms, err ),
                           why << ": bad point encoding must reject" );
      BOOST_CHECK_EQUAL( err, why );
   };
   { stealth_ring_input bad = good; // B1: image, bad prefix
     bad.key_image = img_prefix;
     expect_ring_reject( bad, "bad image point" ); }
   { stealth_ring_input bad = good; // B2/B3: image, off-curve x
     bad.key_image = img_curve;
     expect_ring_reject( bad, "bad image point" ); }
   { stealth_ring_input bad = good; // B4-prefix: ring member, bad prefix
     bad.ring[3] = to_commit( pt_prefix );
     expect_ring_reject( bad, "bad ring point" ); }
   { stealth_ring_input bad = good; // B4-curve: ring member, off-curve x
     bad.ring[3] = to_commit( pt_curve );
     expect_ring_reject( bad, "bad ring point" ); }
   { stealth_ring_input bad = good; // B5-prefix: pseudo-output, bad prefix
     bad.pseudo_output = to_commit( pt_prefix );
     expect_ring_reject( bad, "bad pseudo point" ); }
   { stealth_ring_input bad = good; // B5-curve: pseudo-output, off-curve x
     bad.pseudo_output = to_commit( pt_curve );
     expect_ring_reject( bad, "bad pseudo point" ); }
   // BP+ points A / A1 / B / L0 (wire offsets m=1: A@1 A1@34 B@67 L0@196).
   fc::ecc::commitment_type Cc;
   std::vector<char> proof;
   {
      auto B = T_blind_secret( "r9bB-bpb" );
      BIGNUM* bb = T_bn( B );
      auto Cv = T_commit( bb, 424242 );
      BN_free( bb );
      std::copy( Cv.begin(), Cv.end(), Cc.begin() );
      proof = T_bp_prove( Cc, B, 424242 );
      BOOST_REQUIRE_MESSAGE( !proof.empty(), "test prover must produce a blob" );
      BOOST_REQUIRE_MESSAGE( stealth_verify_bp_plus( 1, proof, { Cc }, err ),
                             "control BP+ must verify: " << err );
   }
   auto expect_bp_reject = [&]( std::vector<char> bad, const std::string& why ) {
      err.clear();
      BOOST_CHECK_MESSAGE( !stealth_verify_bp_plus( 1, bad, { Cc }, err ),
                           why << ": bad BP+ point must reject" );
      BOOST_CHECK_EQUAL( err, why );
   };
   { std::vector<char> bad = proof; // B6a: A, bad prefix
     std::copy( pt_prefix.begin(), pt_prefix.end(), bad.begin() + 1 );
     expect_bp_reject( bad, "bad A" ); }
   { std::vector<char> bad = proof; // B6a-curve: A, off-curve x
     std::copy( pt_curve.begin(), pt_curve.end(), bad.begin() + 1 );
     expect_bp_reject( bad, "bad A" ); }
   { std::vector<char> bad = proof; // B6b: A1, bad prefix
     std::copy( pt_prefix.begin(), pt_prefix.end(), bad.begin() + 34 );
     expect_bp_reject( bad, "bad A1" ); }
   { std::vector<char> bad = proof; // B6b-curve: A1, off-curve x
     std::copy( pt_curve.begin(), pt_curve.end(), bad.begin() + 34 );
     expect_bp_reject( bad, "bad A1" ); }
   { std::vector<char> bad = proof; // B6c: B, bad prefix
     std::copy( pt_prefix.begin(), pt_prefix.end(), bad.begin() + 67 );
     expect_bp_reject( bad, "bad B" ); }
   { std::vector<char> bad = proof; // B6c-curve: B, off-curve x
     std::copy( pt_curve.begin(), pt_curve.end(), bad.begin() + 67 );
     expect_bp_reject( bad, "bad B" ); }
   { std::vector<char> bad = proof; // B7: L0, bad prefix
     std::copy( pt_prefix.begin(), pt_prefix.end(), bad.begin() + 196 );
     expect_bp_reject( bad, "bad L" ); }
   BN_free( bs ); BN_free( bprime );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( r9b_bp_shape_scalar_transcript_vectors )
{ try {
   // Groups C1/C2 (blob shape), A6-A8 (BP+ scalars), E7 (transcript pin).
   std::string err;
   fc::ecc::commitment_type Cc;
   std::vector<char> proof;
   {
      auto B = T_blind_secret( "r9bC-bpb" );
      BIGNUM* bb = T_bn( B );
      auto Cv = T_commit( bb, 424242 );
      BN_free( bb );
      std::copy( Cv.begin(), Cv.end(), Cc.begin() );
      proof = T_bp_prove( Cc, B, 424242 );
      BOOST_REQUIRE_MESSAGE( !proof.empty(), "test prover must produce a blob" );
      BOOST_REQUIRE_EQUAL( proof.size(), 592u );
      BOOST_REQUIRE_MESSAGE( stealth_verify_bp_plus( 1, proof, { Cc }, err ),
                             "control BP+ must verify: " << err );
   }
   unsigned char nbytes[32];
   BN_bn2binpad( T_order(), nbytes, 32 );
   unsigned char zbytes[32] = { 0 };
   auto expect_bp_reject = [&]( std::vector<char> bad, const std::string& why ) {
      err.clear();
      BOOST_CHECK_MESSAGE( !stealth_verify_bp_plus( 1, bad, { Cc }, err ),
                           why << ": malformed BP+ blob must reject" );
      BOOST_CHECK_EQUAL( err, why );
   };
   { std::vector<char> bad( proof.begin(), proof.end() - 1 ); // C1: 591 B
     expect_bp_reject( bad, "blob size" ); }
   { std::vector<char> bad = proof; bad.push_back( (char)0 ); // C2: 593 B
     BOOST_REQUIRE_EQUAL( bad.size(), 593u );
     expect_bp_reject( bad, "blob size" ); }
   // Wire offsets m=1: r1@100 s1@132 d1@164 (32 B each, strict-canonical nonzero).
   { std::vector<char> bad = proof; // A6: r1 == n
     std::copy( nbytes, nbytes + 32, bad.begin() + 100 );
     expect_bp_reject( bad, "bad r1" ); }
   { std::vector<char> bad = proof; // A7: r1 == 0 (canonical but zero)
     std::copy( zbytes, zbytes + 32, bad.begin() + 100 );
     expect_bp_reject( bad, "bad r1" ); }
   { std::vector<char> bad = proof; // A6: s1 == n
     std::copy( nbytes, nbytes + 32, bad.begin() + 132 );
     expect_bp_reject( bad, "bad s1" ); }
   { std::vector<char> bad = proof; // A8: s1 == 0
     std::copy( zbytes, zbytes + 32, bad.begin() + 132 );
     expect_bp_reject( bad, "bad s1" ); }
   { std::vector<char> bad = proof; // A6: d1 == n
     std::copy( nbytes, nbytes + 32, bad.begin() + 164 );
     expect_bp_reject( bad, "bad d1" ); }
   { std::vector<char> bad = proof; // A8: d1 == 0
     std::copy( zbytes, zbytes + 32, bad.begin() + 164 );
     expect_bp_reject( bad, "bad d1" ); }
    // E7: valid proof with A1/B replaced by the round-0 L/R pair in the `e`
    // transcript. All four points are valid on-curve, so parsing succeeds;
    // the equation must still fail (R9C: round challenges use "G1BPr" and
    // the final challenge its own label "G1BPf", so role collision is gone
    // by construction — and separately the multiexp binds A1/B directly,
    // so transplanting L0/R0 cannot close it).
   { std::vector<char> bad = proof;
     std::copy( bad.begin() + 196, bad.begin() + 229, bad.begin() + 34 ); // A1 <- L0
     std::copy( bad.begin() + 229, bad.begin() + 262, bad.begin() + 67 ); // B <- R0
     err.clear();
     BOOST_CHECK_MESSAGE( !stealth_verify_bp_plus( 1, bad, { Cc }, err ),
                          "A1/B-swapped transcript must reject: " << err );
     BOOST_CHECK_EQUAL( err, "multiexp != identity" ); }
} FC_CAPTURE_AND_RETHROW() }

// R9C transcript hardening (mimo F-01, fledge F1/F2, space-bunny F-10):
// the Fiat-Shamir transcript is chained S1-style (state_0 = z, then
// e_j = H("G1BPr" || state_{j-1} || L_j || R_j), e = H("G1BPf" ||
// state_last || A1 || B)) with partitioned stage labels. y = H(V||A) and
// z = H(y) are unchanged; m=1-only (R9A gate stays).
BOOST_AUTO_TEST_CASE( r9c_chained_transcript_verifies )
{ try {
   // The in-tree prover speaks the chained transcript; consensus must
   // accept. TDD RED-1: fails while the verifier is still flat (the
   // chained challenges match nothing the flat verifier recomputes).
   std::string err;
   fc::ecc::commitment_type Cc;
   std::vector<char> proof;
   {
      auto B = T_blind_secret( "r9c-chain-bpb" );
      BIGNUM* bb = T_bn( B );
      auto Cv = T_commit( bb, 424242 );
      BN_free( bb );
      std::copy( Cv.begin(), Cv.end(), Cc.begin() );
      proof = T_bp_prove( Cc, B, 424242 );
      BOOST_REQUIRE_MESSAGE( !proof.empty(), "chained prover must produce a blob" );
      BOOST_REQUIRE_EQUAL( proof.size(), 592u );
   }
   BOOST_CHECK_MESSAGE( stealth_verify_bp_plus( 1, proof, { Cc }, err ),
                        "chained proof must verify: " << err );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( r9c_flat_transcript_rejects )
{ try {
   // Pre-R9C flat transcript (every challenge H("G1BPe"||points), no
   // chaining) is a different protocol: the frozen reference prover's
   // output MUST reject under the chained verifier. TDD RED-1: fails
   // while the verifier is still flat (flat proofs verify there).
   // Non-vacuity: the same fixture's chained proof verifies (r9c case
   // above), and flat bytes differ from chained bytes below.
   std::string err;
   fc::ecc::commitment_type Cc;
   std::vector<char> flat, chained;
   {
      auto B = T_blind_secret( "r9c-flat-bpb" );
      BIGNUM* bb = T_bn( B );
      auto Cv = T_commit( bb, 424242 );
      BN_free( bb );
      std::copy( Cv.begin(), Cv.end(), Cc.begin() );
      flat = T_bp_prove_flat( Cc, B, 424242 );
      chained = T_bp_prove( Cc, B, 424242 );
      BOOST_REQUIRE_MESSAGE( !flat.empty() && !chained.empty(),
                             "both provers must produce blobs" );
   }
   BOOST_CHECK_MESSAGE( flat != chained,
                        "flat and chained transcripts must diverge" );
   // Non-vacuity, asserted rather than asserted-in-a-comment: the SAME
   // fixture's chained proof must verify, so the rejection below is
   // attributable to the transcript and not to a broken fixture.
   err.clear();
   BOOST_REQUIRE_MESSAGE( stealth_verify_bp_plus( 1, chained, { Cc }, err ),
                          "chained control must verify: " << err );
   err.clear();
   BOOST_CHECK_MESSAGE( !stealth_verify_bp_plus( 1, flat, { Cc }, err ),
                        "flat-transcript proof must reject post-R9C" );
   // Pin WHY it rejects. Without this the test would still pass if the flat
   // blob were refused for an unrelated reason (blob size, bad point
   // encoding), which would make the protocol-break pin vacuous. The chained
   // verifier must fail the equation itself, because the flat challenges are
   // not functions of the threaded state.
   BOOST_CHECK_EQUAL( err, "multiexp != identity" );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( r9c_transcript_dependency_mutation )
{ try {
   // Chaining pin: corrupting any round's L input breaks its challenge
   // AND every downstream challenge (state threads forward), so the
   // equation cannot close. Flip the parity byte of L_0 and L_2 (wire
   // offsets m=1: L_j at 196+66j; ^0x01 keeps 0x02/0x03 valid, negating
   // y — encodings stay parseable, the equation must fail). Passes
   // pre- and post-R9C (RED N/A — the flat transcript rejects these
   // too); it pins rejection, the r9c pair above pins the break.
   std::string err;
   fc::ecc::commitment_type Cc;
   std::vector<char> proof;
   {
      auto B = T_blind_secret( "r9c-mut-bpb" );
      BIGNUM* bb = T_bn( B );
      auto Cv = T_commit( bb, 424242 );
      BN_free( bb );
      std::copy( Cv.begin(), Cv.end(), Cc.begin() );
      proof = T_bp_prove( Cc, B, 424242 );
      BOOST_REQUIRE_MESSAGE( !proof.empty(), "test prover must produce a blob" );
      BOOST_REQUIRE_MESSAGE( stealth_verify_bp_plus( 1, proof, { Cc }, err ),
                             "control proof must verify: " << err );
   }
   for( size_t off : { (size_t)196, (size_t)( 196 + 2 * 66 ) } )
   {
      std::vector<char> bad = proof;
      bad[off] ^= 0x01;
      err.clear();
      BOOST_CHECK_MESSAGE( !stealth_verify_bp_plus( 1, bad, { Cc }, err ),
                           "L-mutated proof (off " << off << ") must reject" );
      BOOST_CHECK_EQUAL( err, "multiexp != identity" );
   }
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( r9b_b8_parity_negated_y_vectors )
{ try {
   // R9B Important-3 / space-bunny B8: the same-x opposite-parity prefix
   // (y negated) is a DIFFERENT on-curve point — parse accepts it, the
   // ring equation rejects it. Recorded: accept-at-parse ("ring did not
   // close", not "bad ring point") — the malleability argument is won
   // here: negation never smuggles a second valid authorization for the
   // same member, it just fails the closure check.
   std::string err;
   const size_t n = 16;
   std::vector<std::vector<unsigned char>> Q;
   for( size_t i = 0; i < n; ++i )
      Q.push_back( T_commit( T_scalar( "r9bB8-b|" + std::to_string( i ) ), 500 + i ) );
   BIGNUM* bs = T_scalar( "r9bB8-b|7" );
   BIGNUM* bprime = T_scalar( "r9bB8-bp" );
   std::string ms( (const char*)T_secret( "r9bB8-msg" ).data(), 32 );
   stealth_ring_input good = T_make_ring_input( GRAPHENE_STEALTH_PROOF_V2,
      Q, 7, bs, 507, bprime, ms );
   BOOST_REQUIRE_MESSAGE( stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V2, good, ms, err ),
                          "control must verify: " << err );
   stealth_ring_input bad = good; // B8: member 3, same x, negated y
   bad.ring[3][0] ^= 0x01;
   err.clear();
   BOOST_CHECK_MESSAGE( !stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V2, bad, ms, err ),
                        "parity-negated member must reject" );
   BOOST_CHECK_EQUAL( err, "ring did not close" );
   BN_free( bs ); BN_free( bprime );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( r9c_v1_verify_cost_pin )
{ try {
   // R9B Important-1: replace the "believed cheaper" comment on
   // WORK_US_PER_RANGE_PROOF with a measurement. Times ONE V1 Borromean
   // verify over the consensus path (stealth_verify_range_v1 on a real
   // 1000-value proof), best of 21. Printed, not gated: the budget keeps
   // charging the BP+ rate per V1 output (fail-closed over-count); this
   // pins the number the over-count is measured against.
   auto B = T_blind_secret( "r9c-v1cost-b" );
   auto N = T_secret( "r9c-v1cost-n" );
   fc::ecc::commitment_type C = fc::ecc::blind( B, 1000 );
   fc::ecc::range_proof_type pr = fc::ecc::range_proof_sign( 0, C, B, N, 0, 0, 1000 );
   BOOST_REQUIRE_MESSAGE( !pr.empty(), "must sign a V1 proof" );
   std::vector<char> proof( pr.begin(), pr.end() );
   long long best = -1;
   for( int i = 0; i < 21; ++i )
   {
      uint64_t mn = 0, mx = 0;
      fc::time_point start = fc::time_point::now();
      BOOST_REQUIRE( stealth_verify_range_v1( C, proof, mn, mx ) );
      long long us = ( fc::time_point::now() - start ).count();
      if( best < 0 || us < best ) best = us;
   }
   BOOST_TEST_MESSAGE( "V1 BORROMEAN VERIFY " << best << "us (1 proof, best of 21)" );
} FC_CAPTURE_AND_RETHROW() }

// R9C F-08 disclosure pin (mimo-2.6 F-08 HIGH), Task 3 update: the
// whole-ring spent flag is RETIRED, so decoys stay live — the decoy owner's
// op108 spend succeeds (pinned by
// g1_decoyed_output_remains_spendable_after_flag_retirement). What this case
// still pins: the LEGACY op41 leg refuses her post-fork output (created_block
// gate), routing her to op108.
BOOST_AUTO_TEST_CASE( r9c_decoy_owner_explicit_spend_refused )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r9c-f08", 16, true );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 16u );
   // Honest V1 spend of output #5 (1000 -> 600 + 390 + fee 10). V1 keeps
   // this pin orthogonal to the transcript change (fc backend, no BP+).
   const size_t s = 5, decoy = 7; // decoy != real input
   stealth_transfer_operation stop = t5_build_spend( core, p, s,
      GRAPHENE_STEALTH_PROOF_V1, "r9c-f08-sp", 600, 390, 10 );
   trx.operations = { stop };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   const int64_t live = t5_supply( db, core );
   // The decoy owner spends her OWN output explicitly (owner-signed,
   // conservation-exact: 990 + 10 == 1000 under the true blind) — and
   // is refused on the legacy leg: post-fork outputs spend only via op108
   // (Task 3; the F-08 "output died as someone else's decoy" rationale is
   // retired — the output is live, and its op108 spend is pinned by
   // g1_decoyed_output_remains_spendable_after_flag_retirement).
   transfer_from_blind_operation x;
   x.to = dan.id;
   x.amount = core.amount( 990 );
   x.fee = core.amount( 10 );
   blind_input bi; bi.commitment = p.commits[decoy]; bi.owner = p.owners[decoy];
   x.inputs = { bi };
   x.blinding_factor = p.blinds[decoy];
   BOOST_CHECK_NO_THROW( x.validate() ); // relay shape is fine...
   set_expiration( db, trx );
   trx.operations = { x };
   sign( trx, p.keys[decoy] );
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "decoy-owner legacy explicit spend must refuse (post-fork routes to op108)" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "stealth_explicit_spend" ) != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live ); // refused spend moved nothing
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( r9b_version_binding_e8 )
{ try {
   // E8 (sharpest proof-bound test): a valid authorization under one proof
   // version never verifies under the other. Verifier leg pins the
   // J-domain separation (same bytes, same message, other version rejects);
   // op legs pin the consensus binding end to end.
   std::string err;
   const size_t n = 16;
   std::vector<std::vector<unsigned char>> Q;
   for( size_t i = 0; i < n; ++i )
      Q.push_back( T_commit( T_scalar( "r9bE-b|" + std::to_string( i ) ), 500 + i ) );
   BIGNUM* bs = T_scalar( "r9bE-b|7" );
   BIGNUM* bprime = T_scalar( "r9bE-bp" );
   std::string ms( (const char*)T_secret( "r9bE-msg" ).data(), 32 );
   stealth_ring_input v1in = T_make_ring_input( GRAPHENE_STEALTH_PROOF_V1,
      Q, 7, bs, 507, bprime, ms );
   stealth_ring_input v2in = T_make_ring_input( GRAPHENE_STEALTH_PROOF_V2,
      Q, 7, bs, 507, bprime, ms );
   BOOST_REQUIRE_MESSAGE( stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V1, v1in, ms, err ),
                          "V1 control must verify: " << err );
   BOOST_REQUIRE_MESSAGE( stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V2, v2in, ms, err ),
                          "V2 control must verify: " << err );
   err.clear();
   BOOST_CHECK_MESSAGE( !stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V2, v1in, ms, err ),
                        "V1 authorization under V2 must reject" );
   BOOST_CHECK_EQUAL( err, "ring did not close" );
   err.clear();
   BOOST_CHECK_MESSAGE( !stealth_verify_ring( GRAPHENE_STEALTH_PROOF_V1, v2in, ms, err ),
                        "V2 authorization under V1 must reject" );
   BOOST_CHECK_EQUAL( err, "ring did not close" );
   BN_free( bs ); BN_free( bprime );
   // Op legs: one funded pool, three fail-closed mutations (all reject in
   // do_evaluate, so no nullifier/pool state moves between them).
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r9b-e8", 16, true );
   { // (a) version flip: V1 bytes presented as a V2 op. The V1 Borromean
     // blobs cannot parse as BP+ (validate would also refuse at relay, so
     // dispatch past it to pin the CONSENSUS gate specifically).
     stealth_transfer_operation stop = t5_build_spend( core, p, 5,
        GRAPHENE_STEALTH_PROOF_V1, "r9b-e8-a", 600, 390, 10 );
     stop.proof_version = GRAPHENE_STEALTH_PROOF_V2;
     transaction_evaluation_state es( &db );
     try
     {
        db.apply_operation( es, operation( stop ) );
        BOOST_FAIL( "version-flipped op must fail closed in do_evaluate" );
     }
     catch( const fc::exception& e )
     {
        BOOST_CHECK_MESSAGE( e.to_detail_string().find(
           "Stealth output V2 range proof does not verify" ) != std::string::npos,
           e.to_detail_string() );
     }
   }
   { // (b) sharp leg: the VALID V2 alternate signature presented as the V1
     // main leg (images stay distinct, so the duplicate-image tripwire is
     // not what fires — the version binding itself rejects).
     stealth_transfer_operation stop = t5_build_spend( core, p, 5,
        GRAPHENE_STEALTH_PROOF_V1, "r9b-e8-b", 600, 390, 10 );
     stop.inputs[0].ring_sig = stop.inputs[0].alt_ring_sig;
     trx.operations = { stop };
     try
     {
        PUSH_TX( db, trx );
        BOOST_FAIL( "cross-version main leg must reject" );
     }
     catch( const fc::exception& e )
     {
        BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Ring signature does not verify" )
                             != std::string::npos, e.to_detail_string() );
     }
     trx.clear();
   }
   { // (c) E2 companion: altered fee rebinds the ring message (fee rides
     // stealth_ring_message), so the proven authorization no longer matches.
     stealth_transfer_operation stop = t5_build_spend( core, p, 5,
        GRAPHENE_STEALTH_PROOF_V1, "r9b-e8-c", 600, 390, 10 );
     stop.fee = core.amount( 11 );
     trx.operations = { stop };
     try
     {
        PUSH_TX( db, trx );
        BOOST_FAIL( "altered-fee op must reject on the message binding" );
     }
     catch( const fc::exception& e )
     {
        BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Ring signature does not verify" )
                             != std::string::npos, e.to_detail_string() );
     }
     trx.clear();
   }
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( r9b_work_budget_rejects_overwork_block )
{ try {
   // F-01 work gate (RED first: no work budget exists yet, so the final
   // spend is wrongly ACCEPTED). Bulk legacy work (56 x 2-output deposits)
   // plus one honest ring spend exceeds 750000us of verifier work while
   // staying under the 100-op count gate (57 ops isolates the work gate).
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r9b-w", 16, true );
   // Pool seeding above costs 20x the seeded need from dan; top up for the
   // 56 cost-path deposits below (56 x (200 + 1500000) ~= 84M).
   transfer( account_id_type()(db), dan, core.amount( 500000000 ) );
   // 56 two-output deposits on the G1c cost path (pinned anchor n=2, no
   // pool touch, no subsidy-cap units) in ONE pending block.
   for( int i = 0; i < 56; ++i )
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 200 );
      ttb.from = dan.id;
      auto k1 = fc::ecc::private_key::generate();
      auto k2 = fc::ecc::private_key::generate();
      blind_output o1, o2;
      o1.owner = authority( 1, public_key_type( k1.get_public_key() ), 1 );
      o2.owner = authority( 1, public_key_type( k2.get_public_key() ), 1 );
      auto B1 = T_blind_secret( "r9b-w-b1|" + std::to_string( i ) );
      auto B2 = T_blind_secret( "r9b-w-b2|" + std::to_string( i ) );
      auto N1 = T_secret( "r9b-w-n1|" + std::to_string( i ) );
      auto N2 = T_secret( "r9b-w-n2|" + std::to_string( i ) );
      o1.commitment = fc::ecc::blind( B1, 100 );
      o1.range_proof = fc::ecc::range_proof_sign( 0, o1.commitment, B1, N1, 0, 0, 100 );
      o2.commitment = fc::ecc::blind( B2, 100 );
      o2.range_proof = fc::ecc::range_proof_sign( 0, o2.commitment, B2, N2, 0, 0, 100 );
      { // wallet convention: the deposit blind is the sum of output blinds
        BIGNUM* b1 = T_bn( B1 ); BIGNUM* b2 = T_bn( B2 ); BIGNUM* e = BN_new();
        BN_mod_add( e, b1, b2, T_order(), T_ctx() );
        unsigned char eb[32]; BN_bn2binpad( e, eb, 32 );
        fc::sha256 h; std::copy( eb, eb + 32, (char*)h.data() );
        ttb.blinding_factor = h;
        BN_free( b1 ); BN_free( b2 ); BN_free( e );
      }
      ttb.fee = core.amount( 1500000 ); // pinned cost anchor, n=2: 5+2*5 CORE
      // Consensus requires blind outputs sorted by commitment id
      // (confidential.cpp validate); order is cosmetic here (no kernel).
      if( o2.commitment < o1.commitment )
         ttb.outputs = { o2, o1 };
      else
         ttb.outputs = { o1, o2 };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
   }
   // One honest ring spend on top must trip the work gate (not the count gate).
   stealth_transfer_operation stop = t5_build_spend( core, p, 5,
      GRAPHENE_STEALTH_PROOF_V1, "r9b-w-sp", 600, 390, 10 );
   trx.operations = { stop };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "over-work block must fail closed on the verification-work budget" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "verification-work budget" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear();
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( r13e_ring_message_partition_is_unambiguous )
{ try {
   // F-03 (mimo-2.6): the G1RM ring-message preimage concatenated
   //   ring[33n] || pseudo[33] || outputs[33m] || fee
   // with NO canonical count for n or m, so two different partitions of the
   // same byte string hashed identically. This is the structural ambiguity,
   // stated as a property test rather than a captured collision:
   //
   //   A: ring={c0,c1},  pseudo=c2, outputs={c3}    (n=2, m=1)
   //   B: ring={c0,c1,c2}, pseudo=c3, outputs={}    (n=3, m=0)
   //
   // Both preimages are the flat byte run c0|c1|c2|c3 followed by the fee.
   // The fix prepends fixed-width LE64 counts n and m, so the counts are part
   // of what is hashed and A != B. Before the fix these two hashes are equal —
   // which is exactly the defect, so this assertion FAILS until it is fixed.
   std::vector<std::vector<unsigned char>> pt;
   for( int i = 0; i < 4; ++i )
      pt.push_back( T_commit( T_scalar( "r13e-part|" + std::to_string( i ) ), 900 + i ) );

   const uint8_t ver = GRAPHENE_STEALTH_PROOF_V2;
   const asset_id_type a_self  = asset_id_type();
   const asset_id_type a_other = asset_id_type( 1 );
   std::vector<char> img( 33 );
   std::copy( pt[0].begin(), pt[0].end(), img.begin() );
   fc::ecc::commitment_type c0 = T_commitment( pt[0] );
   fc::ecc::commitment_type c1 = T_commitment( pt[1] );
   fc::ecc::commitment_type c2 = T_commitment( pt[2] );
   fc::ecc::commitment_type c3 = T_commitment( pt[3] );
   const share_type fee( 4242 );

   // A: (n=2, m=1)
   fc::sha256 ha = stealth_ring_message( ver, a_self, img,
      { c0, c1 }, c2, { c3 }, fee );
   // B: (n=3, m=0) — identical flat byte run c0|c1|c2|c3
   fc::sha256 hb = stealth_ring_message( ver, a_self, img,
      { c0, c1, c2 }, c3, {}, fee );
   BOOST_REQUIRE_MESSAGE( ha != hb,
      "F-03: (n=2,m=1) and (n=3,m=0) must not share a G1RM preimage; equal "
      "hashes mean the ring/output counts are not bound into the message" );

   // Second case, chosen to be F-03-DISCRIMINATING (the first pair above is
   // the primary RED witness; this one would ALSO have collided pre-fix, so
   // it fails if the counts are unbound, and would NOT have separated them
   // merely because the commitment runs differ in length):
   //   C: ring={c0,c1},  pseudo=c2, outputs={c2}    (n=2, m=1)  -> c0|c1|c2|c2
   //   D: ring={c0,c1,c2}, pseudo=c2, outputs={}    (n=3, m=0)  -> c0|c1|c2|c2
   fc::sha256 hc = stealth_ring_message( ver, a_self, img,
      { c0, c1 }, c2, { c2 }, fee );
   fc::sha256 hd = stealth_ring_message( ver, a_self, img,
      { c0, c1, c2 }, c2, {}, fee );
   BOOST_REQUIRE_MESSAGE( hc != hd,
      "F-03: a commitment repeated as pseudo-output and as output must still "
      "separate from the same commitment placed at the end of the ring" );

   // Pin WHY these two cases discriminate, so they cannot silently stop being
   // F-03 witnesses: reconstruct the PRE-FIX preimage (no counts) and show it
   // genuinely collided. If this ever stops holding, the cases above are no
   // longer testing the defect they claim to test.
   {
      auto old_preimage = [&]( const std::vector<fc::ecc::commitment_type>& r,
                               const fc::ecc::commitment_type& p,
                               const std::vector<fc::ecc::commitment_type>& outs ) {
         std::string pre = "G1RM";
         pre.push_back( (char)ver );
         auto av = fc::raw::pack( a_self );
         pre.append( av.data(), av.size() );
         pre.append( img.data(), img.size() );
         for( const auto& c : r ) pre.append( (const char*)c.data(), 33 );
         pre.append( (const char*)p.data(), 33 );
         for( const auto& c : outs ) pre.append( (const char*)c.data(), 33 );
         auto fv = fc::raw::pack( fee );
         pre.append( fv.data(), fv.size() );
         return fc::sha256::hash( pre.data(), pre.size() );
      };
      BOOST_REQUIRE_EQUAL( old_preimage( { c0, c1 }, c2, { c2 } ),
                           old_preimage( { c0, c1, c2 }, c2, {} ) );
      BOOST_REQUIRE( old_preimage( { c0, c1 }, c2, { c3 } )
                      == old_preimage( { c0, c1, c2 }, c3, {} ) );
   }

   // Sanity: identical partitions still agree (the fix must not disturb the
   // normal path), and the existing version/asset/fee bindings still hold.
   fc::sha256 h1 = stealth_ring_message( ver, a_self, img,
      { c0, c1 }, c2, { c3 }, fee );
   fc::sha256 h3 = stealth_ring_message( ver, a_self, img,
      { c0, c1 }, c2, { c3 }, fee );
   BOOST_REQUIRE_EQUAL( h1, h3 );
   BOOST_REQUIRE( stealth_ring_message( GRAPHENE_STEALTH_PROOF_V1, a_self, img,
                  { c0, c1 }, c2, { c3 }, fee ) != h1 );
   BOOST_REQUIRE( stealth_ring_message( ver, a_other, img,
                  { c0, c1 }, c2, { c3 }, fee ) != h1 );
   BOOST_REQUIRE( stealth_ring_message( ver, a_self, img,
                  { c0, c1 }, c2, { c3 }, share_type( 4243 ) ) != h1 );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( r9b_work_budget_arithmetic )
{ try {
   // F-01 work-budget model pins (pure arithmetic, no chain, no timing):
   // unit costs, the offender shape, the legacy full-block fit, and the
   // exact charges the overwork test above relies on.
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_MAX_BLIND_WORK_US_PER_BLOCK, 750000u );
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_WORK_US_PER_RING_MEMBER, 1210u );
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_WORK_US_PER_RANGE_PROOF, 6322u );
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_WORK_US_PER_KERNEL, 2048u );
   // Consensus worst case (8-in / ring-32 / dual + 8 BP+ + kernel) fits, so
   // ANY single consensus-valid op is admissible...
   stealth_transfer_operation worst;
   for( int i = 0; i < 8; ++i )
   {
      stealth_ring_input in;
      in.ring.resize( 32 );
      worst.inputs.push_back( in );
   }
   worst.outputs.resize( 8 );
   BOOST_REQUIRE_EQUAL( stealth_work_for_stealth_transfer( worst ), 672144u );
   BOOST_CHECK( stealth_work_for_stealth_transfer( worst )
                <= GRAPHENE_STEALTH_MAX_BLIND_WORK_US_PER_BLOCK );
   // ...while a block of worst cases cannot (2x offender > budget).
   BOOST_CHECK( 2u * stealth_work_for_stealth_transfer( worst )
                > GRAPHENE_STEALTH_MAX_BLIND_WORK_US_PER_BLOCK );
   // Minimal G1 spend (1-in / ring-16 / dual + 2 outputs + kernel).
   stealth_transfer_operation small;
   small.inputs.resize( 1 ); small.inputs[0].ring.resize( 16 );
   small.outputs.resize( 2 );
   BOOST_REQUIRE_EQUAL( stealth_work_for_stealth_transfer( small ), 53412u );
   // Legacy full block (100 x 1-output deposits) still fits (tightening-only).
   BOOST_REQUIRE_EQUAL( stealth_work_for_range_proofs( 1 ), 6322u );
   BOOST_CHECK( 100u * stealth_work_for_range_proofs( 1 )
                <= GRAPHENE_STEALTH_MAX_BLIND_WORK_US_PER_BLOCK );
   // Overwork-test charges: 56 x 2-output deposits fit, plus one minimal
   // spend trips.
   BOOST_REQUIRE_EQUAL( stealth_work_for_range_proofs( 2 ), 12644u );
   BOOST_CHECK( 56u * stealth_work_for_range_proofs( 2 )
                <= GRAPHENE_STEALTH_MAX_BLIND_WORK_US_PER_BLOCK );
   BOOST_CHECK( 56u * stealth_work_for_range_proofs( 2 )
                + stealth_work_for_stealth_transfer( small )
                > GRAPHENE_STEALTH_MAX_BLIND_WORK_US_PER_BLOCK );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( parity_pool_routing_and_float )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()(db), dan, core.amount( 40000000 ) );
   // Seal-then-modify (see negative_mint_rejected): the routing legs below
   // are direct db modifications and must survive block-production replay.
   generate_block();
   // Task 7 legacy gate: this case funds CORE's pool through the real
   // routing leg, so opt CORE in first (production path pinned separately).
   g1c_opt_in_parity( db, core_id );

   // --- fee-share routing through the single choke point (market + ---
   // --- settlement fees both land in database::pay_market_fees)      ---
   {
      share_type acc0 = core.dynamic_asset_data_id( db ).accumulated_fees;
      // Mirror the skimmed-proceeds leg so supply verification still
      // balances: only the FEE leaves dan's balance (pay_market_fees never
      // moves the nominal — the caller pays the seller separately).
      db.adjust_balance( dan_id, core.amount( -1000000 ) );
      asset got = db.pay_market_fees( nullptr, core, core.amount( 10000000 ),
                                      true, core.amount( 1000000 ) );
      BOOST_CHECK_EQUAL( got.amount.value, 1000000 );
      // 5% of the 1M fee routes to the pool; the remainder accumulates.
      BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_PARITY_FEE_SHARE_BPS, 500u );
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      auto pitr = st.parity_pool.find( core_id );
      BOOST_REQUIRE( pitr != st.parity_pool.end() );
      BOOST_CHECK_EQUAL( pitr->second.value, 50000 );
      BOOST_CHECK_EQUAL( core.dynamic_asset_data_id( db ).accumulated_fees.value,
                         ( acc0 + 950000 ).value );
      auto ritr = st.interval_routed.find( core_id );
      BOOST_REQUIRE( ritr != st.interval_routed.end() );
      BOOST_CHECK_EQUAL( ritr->second.value, 50000 );
   }
   verify_asset_supplies( db );

   // --- cost-anchor math (test genesis zeroes fees: pinned governs) ---
   {
      BOOST_CHECK_EQUAL( stealth_cost_anchor_core( db, 0 ).value,
                         (int64_t)( 5 * GRAPHENE_BLOCKCHAIN_PRECISION ) );
      BOOST_CHECK_EQUAL( stealth_cost_anchor_core( db, 1 ).value,
                         (int64_t)( 10 * GRAPHENE_BLOCKCHAIN_PRECISION ) );
      BOOST_CHECK_EQUAL( stealth_parity_gap_core( db, 0, share_type( 0 ), 0 ).value,
                         stealth_cost_anchor_core( db, 0 ).value );
      BOOST_CHECK_EQUAL(
         stealth_parity_gap_core( db, 0, stealth_cost_anchor_core( db, 0 ), 0 ).value, 0 );
   }

   // --- deposits (cost path: pool is short by design, so the pinned ---
   // --- anchor is paid and the pool assertions below stay exact)      ---
   auto k = fc::ecc::private_key::generate();
   authority own( 1, public_key_type( k.get_public_key() ), 1 );
   // Returns the commitment AND its blinding factor: transfer_from_blind
   // conservation is checked at validate time as
   //   sum(inputs) - blind(blinding_factor, amount+fee) == 0,
   // so a withdrawal must present the INPUT's blind (not a fresh one).
   auto deposit = [&]( const std::string& tag, int64_t amt )
      -> std::pair<fc::ecc::commitment_type, fc::sha256> {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( amt );
      ttb.from = dan.id;
      blind_output o;
      o.owner = own;
      // G1c cost path: the pool (50k) cannot cover the 1M gap, so deposits
      // pay the pinned anchor (n=1) from transparent funds — pool untouched.
      ttb.fee = core.amount( 1000000 );
      auto B = T_blind_secret( "g1c-float-b|" + tag );
      auto N = T_secret( "g1c-float-n|" + tag );
      o.commitment = fc::ecc::blind( B, amt );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, amt );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      return { o.commitment, B };
   };
   // transfer_from_blind conservation is exact at validate time (input
   // commitment == amount + fee), so each leg below funds the precise input
   // its withdrawal spends: A covers amount+cost (500900), B and C cover
   // amount+parity (900). That keeps conservation green so the FEE rule —
   // not conservation — decides every leg.
   auto cA = deposit( "a", 500900 );
   auto cB = deposit( "b", 900 );
   auto cC = deposit( "c", 900 );
   generate_block(); // seal BEFORE grandfathering (see T_grandfather note)
   // Task 3: every deposit above is withdrawn via the legacy op41 leg below
   // — grandfather each sealed balance so the fee rule (not the
   // created_block gate) decides every leg.
   T_grandfather( db, core.get_id(), cA.first );
   T_grandfather( db, core.get_id(), cB.first );
   T_grandfather( db, core.get_id(), cC.first );

   // Withdrawals carry no blind outputs (n = 0): gap is the full anchor
   // (500000) against the zeroed schedule. The pool holds 50000 — short.
   auto withdraw = [&]( const std::pair<fc::ecc::commitment_type, fc::sha256>& in,
                        int64_t amt, int64_t fee, bool expect_ok ) {
      transfer_from_blind_operation x;
      x.to = dan.id;
      x.amount = core.amount( amt );
      x.fee = core.amount( fee );
      blind_input bi; bi.commitment = in.first; bi.owner = own;
      x.inputs = { bi };
      x.blinding_factor = in.second;
      set_expiration( db, trx );
      trx.operations = { x };
      sign( trx, k );
      if( expect_ok )
      {
         db.push_transaction( precomputable_transaction( trx ), database::skip_nothing );
         verify_asset_supplies( db );
      }
      else
         BOOST_CHECK_THROW(
            db.push_transaction( precomputable_transaction( trx ), database::skip_nothing ),
            fc::exception );
      trx.clear_signatures(); trx.operations.clear();
   };
   // Pool-empty floats to cost by rule: the parity-level fee (0) rejects...
   withdraw( cB, 900, 0, false );
   // ...while the cost-anchor fee clears (cost path consumes nothing).
   withdraw( cA, 900, 500000, true );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      auto pitr = st.parity_pool.find( core_id );
      BOOST_REQUIRE( pitr != st.parity_pool.end() );
      BOOST_CHECK_EQUAL( pitr->second.value, 50000 ); // cost path: pool untouched
   }
   // Fund exact coverage (pool 550000), then the parity fee clears and the
   // pool debits exactly the gap. Sealed first: the cost withdrawal above is
   // still pending, and the routing legs below are direct (see
   // seal-then-modify note) — they must survive block-production replay so
   // the parity withdrawal replays against the funded pool.
   generate_block();
   db.adjust_balance( dan_id, core.amount( -10000000 ) );
   db.pay_market_fees( nullptr, core, core.amount( 10000000 ),
                       true, core.amount( 10000000 ) );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_REQUIRE_EQUAL( st.parity_pool.find( core_id )->second.value, 550000 );
   }
   withdraw( cC, 900, 0, true );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.parity_pool.find( core_id )->second.value, 50000 );
      auto gitr = st.interval_granted.find( core_id );
      BOOST_REQUIRE( gitr != st.interval_granted.end() );
      BOOST_CHECK_EQUAL( gitr->second.value, 500000 );
      BOOST_CHECK_EQUAL( st.parity_subsidized_count, 1u );
   }
   generate_block();
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( parity_per_block_subsidy_cap_and_reserve )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_PARITY_MAX_SUBSIDIZED_PER_BLOCK, 50u );
   ACTORS( (dan)(alice) );
   const asset_object& core = asset_id_type()(db);
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()(db), dan, core.amount( 300000000 ) );
   // Seal-then-modify (see negative_mint_rejected): fee-schedule and pool
   // writes below are direct and must survive block-production replay.
   generate_block();
   // Price parity just under the pinned anchor: gap 1000 per withdrawal.
   // Test genesis zeroes the fee scale (calculate_fee would map every
   // schedule to 0), so pin scale at 100% for the schedule levels below to
   // mean what they say — production default; the zeroed genesis is why
   // the pre-parity cases above price everything at the pinned anchor.
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      auto& fees = p.parameters.get_mutable_fees();
      fees.scale = GRAPHENE_100_PERCENT;
      auto& fee_params = fees.parameters;
      auto itr = fee_params.find( transfer_from_blind_operation::fee_params_t() );
      itr->get<transfer_from_blind_operation::fee_params_t>().fee = 499000;
   } );
   BOOST_CHECK_EQUAL( stealth_parity_gap_core( db, 0, share_type( 499000 ), 0 ).value, 1000 );
   // Task 7 legacy gate: opt CORE in so the seeding below routes.
   g1c_opt_in_parity( db, core_id );
   // Seed exactly 50 subsidies: route 1M nominal (5% = 50000).
   db.adjust_balance( dan_id, core.amount( -1000000 ) );
   db.pay_market_fees( nullptr, core, core.amount( 1000000 ), true, core.amount( 1000000 ) );

   // 52 deposits (cost path, sealed in one block): 51 inputs worth
   // amount+parity (499900) for the subsidized legs, one worth amount+cost
   // (500900) for the cost leg. Conservation is exact at validate time, so
   // the CAP rule — not conservation — decides the 51st withdrawal.
   auto k = fc::ecc::private_key::generate();
   authority own( 1, public_key_type( k.get_public_key() ), 1 );
   vector<fc::ecc::commitment_type> cs;
   vector<fc::sha256> bs; // input blinding factors (from_blind needs them)
   for( int i = 0; i < 52; ++i )
   {
      transfer_to_blind_operation ttb;
      int64_t dep = ( i == 51 ) ? 500900 : 499900;
      ttb.amount = core.amount( dep );
      ttb.from = dan.id;
      blind_output o; o.owner = own;
      // G1c cost path (BSIP-2 §2): deposits pay the pinned anchor (n=1, 1M)
      // from transparent funds — the 50k pool is reserved for the withdrawal
      // subsidies under test, and cost-path ops consume no cap units.
      ttb.fee = core.amount( 1000000 );
      auto B = T_blind_secret( "g1c-cap-b|" + std::to_string( i ) );
      auto N = T_secret( "g1c-cap-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, dep );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, dep );
      ttb.blinding_factor = B; ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      cs.push_back( o.commitment );
      bs.push_back( B );
   }
   generate_block(); // seal BEFORE grandfathering (see T_grandfather note)
   // Task 3: all 52 are withdrawn via the legacy op41 leg below —
   // grandfather each sealed balance so the CAP rule (not the created_block
   // gate) decides.
   for( const auto& c : cs )
      T_grandfather( db, core.get_id(), c );

   // 50 subsidized withdrawals in one pending block (fee = parity 499000).
   for( int i = 0; i < 50; ++i )
   {
      transfer_from_blind_operation x;
      x.to = dan.id; x.amount = core.amount( 900 ); x.fee = core.amount( 499000 );
      blind_input bi; bi.commitment = cs[i]; bi.owner = own;
      x.inputs = { bi };
      x.blinding_factor = bs[i];
      set_expiration( db, trx );
      trx.operations = { x };
      sign( trx, k );
      db.push_transaction( precomputable_transaction( trx ), database::skip_nothing );
      trx.clear_signatures(); trx.operations.clear();
   }
   verify_asset_supplies( db );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      // Exact drain: zero entries are removed, not left at zero.
      BOOST_CHECK( st.parity_pool.find( core_id ) == st.parity_pool.end() );
      BOOST_CHECK_EQUAL( st.parity_subsidized_count, 50u );
      auto gitr = st.interval_granted.find( core_id );
      BOOST_REQUIRE( gitr != st.interval_granted.end() );
      BOOST_CHECK_EQUAL( gitr->second.value, 50000 );
   }
   // 51st withdrawal: subsidy cap exhausted floats it to cost...
   auto last = [&]( size_t ci, int64_t fee, bool expect_ok ) {
      transfer_from_blind_operation x;
      x.to = dan.id; x.amount = core.amount( 900 ); x.fee = core.amount( fee );
      blind_input bi; bi.commitment = cs[ci]; bi.owner = own;
      x.inputs = { bi };
      x.blinding_factor = bs[ci];
      set_expiration( db, trx );
      trx.operations = { x };
      sign( trx, k );
      if( expect_ok )
         db.push_transaction( precomputable_transaction( trx ), database::skip_nothing );
      else
         BOOST_CHECK_THROW(
            db.push_transaction( precomputable_transaction( trx ), database::skip_nothing ),
            fc::exception );
      trx.clear_signatures(); trx.operations.clear();
   };
   last( 50, 499000, false );
   last( 51, 500000, true ); // cost level clears even with an empty pool
   verify_asset_supplies( db );

   // Reserved transparent space: top this block's blind budget up to 100.
   {
      uint32_t have = stealth_blind_count_this_block( db );
      BOOST_REQUIRE_LE( have, 100u );
      for( uint32_t i = have; i < 100; ++i )
      {
         transfer_to_blind_operation ttb;
         ttb.amount = core.amount( 100 );
         ttb.from = dan.id;
         auto kk = fc::ecc::private_key::generate();
         blind_output o;
         o.owner = authority( 1, public_key_type( kk.get_public_key() ), 1 );
         ttb.fee = core.amount( 1000000 ); // G1c cost path: pool is drained
         auto B = T_secret( "g1c-rsv-b|" + std::to_string( i ) );
         auto N = T_secret( "g1c-rsv-n|" + std::to_string( i ) );
         o.commitment = fc::ecc::blind( B, 100 );
         o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 100 );
         ttb.blinding_factor = B; ttb.outputs = { o };
         set_expiration( db, trx );
         trx.operations = { ttb };
         sign( trx, dan_private_key );
         PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      }
      BOOST_CHECK_EQUAL( stealth_blind_count_this_block( db ), 100u );
      // 101st blind op trips the budget...
      transfer_to_blind_operation over;
      over.amount = core.amount( 100 );
      over.from = dan.id;
      auto kk = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( kk.get_public_key() ), 1 );
      auto B = T_secret( "g1c-rsv-b|over" );
      auto N = T_secret( "g1c-rsv-n|over" );
      o.commitment = fc::ecc::blind( B, 100 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 100 );
      over.blinding_factor = B;
      over.fee = core.amount( 1000000 ); // G1c cost path: budget (not float) rejects
      over.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { over };
      sign( trx, dan_private_key );
      BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
      trx.clear_signatures(); trx.operations.clear();
      // ...while transparent transfers still clear (reserved space rides
      // outside the blind budget: the gate only counts blind ops).
      // (dan→dan self-transfers never validate; a second actor receives.)
      transfer_operation t;
      t.from = dan.id; t.to = alice.id; t.amount = core.amount( 1 );
      trx.operations = { t };
      db.current_fee_schedule().set_fee( trx.operations.back() );
      sign( trx, dan_private_key );
      BOOST_CHECK_NO_THROW(
         db.push_transaction( precomputable_transaction( trx ), database::skip_nothing ) );
      trx.clear_signatures(); trx.operations.clear();
   }
   generate_block();
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( parity_missed_review_defaults )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_PARITY_REVIEW_INTERVAL_SEC, 15552000u );
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_PARITY_REPORT_INTERVAL_SEC, 7776000u );
   ACTORS( (alice)(bob)(dan) );
   upgrade_to_lifetime_member( alice ); upgrade_to_lifetime_member( bob );
   create_committee_member( alice ); create_committee_member( bob );
   generate_block();
   const asset_object& core = asset_id_type()(db);
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()(db), dan, core.amount( 40000000 ) );
   // Seal-then-modify (see negative_mint_rejected).
   generate_block();
   // Gap 10000 per withdrawal (parity 490000 vs 500000 anchor). Pin scale
   // at 100% (see the cap test note): test genesis zeroes it, which would
   // map the 490000 schedule to a 0 parity and a 500000 gap.
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      auto& fees = p.parameters.get_mutable_fees();
      fees.scale = GRAPHENE_100_PERCENT;
      auto& fee_params = fees.parameters;
      auto itr = fee_params.find( transfer_from_blind_operation::fee_params_t() );
      itr->get<transfer_from_blind_operation::fee_params_t>().fee = 490000;
   } );
   // Seed the pool BEFORE the clock jumps (funding works while current).
   // Task 7 legacy gate: opt CORE in so the seeding below routes.
   g1c_opt_in_parity( db, core_id );
   db.adjust_balance( dan_id, core.amount( -1000000 ) );
   db.pay_market_fees( nullptr, core, core.amount( 1000000 ), true, core.amount( 1000000 ) );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_REQUIRE_EQUAL( st.parity_pool.find( core_id )->second.value, 50000 );
   }

   auto k = fc::ecc::private_key::generate();
   authority own( 1, public_key_type( k.get_public_key() ), 1 );
   vector<fc::ecc::commitment_type> cs;
   vector<fc::sha256> bs; // input blinding factors (from_blind needs them)
   // Exact-conservation deposits (see routing test): cs[0] covers
   // amount+parity (490900) for the float-reject leg, cs[1] covers
   // amount+cost (500900) for the cost leg, cs[2] covers amount+parity for
   // the post-review subsidy leg.
   const int64_t rev_deps[3] = { 490900, 500900, 490900 };
   for( int i = 0; i < 3; ++i )
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( rev_deps[i] );
      ttb.from = dan.id;
      blind_output o; o.owner = own;
      // G1c cost path: the 50k pool is reserved for the withdrawal subsidies
      // under test, so deposits pay the pinned anchor (n=1, 1M).
      ttb.fee = core.amount( 1000000 );
      auto B = T_blind_secret( "g1c-rev-b|" + std::to_string( i ) );
      auto N = T_secret( "g1c-rev-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, rev_deps[i] );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, rev_deps[i] );
      ttb.blinding_factor = B; ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      cs.push_back( o.commitment );
      bs.push_back( B );
   }
   generate_block(); // seal BEFORE grandfathering (see T_grandfather note)
   // Task 3: all three are withdrawn via the legacy op41 leg below —
   // grandfather each sealed balance so the review/funding gates (not the
   // created_block gate) decide every leg.
   for( const auto& c : cs )
      T_grandfather( db, core.get_id(), c );
   BOOST_CHECK( stealth_parity_available( db, core_id, share_type( 10000 ) ) );

   // Jump 7 months: 1 missed 6-month review + 2 missed quarterly reports.
   generate_blocks( HARDFORK_STEALTH_TIME + 7 * 30 * 86400 );
   generate_block();
   set_expiration( db, trx );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.missed_parity_reviews, 1u );
      BOOST_CHECK_EQUAL( st.missed_set_reports, 2u );
      BOOST_CHECK( st.parity_funding_halted );
   }
   auto withdraw = [&]( size_t ci, int64_t fee, bool expect_ok ) {
      transfer_from_blind_operation x;
      x.to = dan.id; x.amount = core.amount( 900 ); x.fee = core.amount( fee );
      blind_input bi; bi.commitment = cs[ci]; bi.owner = own;
      x.inputs = { bi };
      x.blinding_factor = bs[ci];
      set_expiration( db, trx );
      trx.operations = { x };
      sign( trx, k );
      if( expect_ok )
      {
         db.push_transaction( precomputable_transaction( trx ), database::skip_nothing );
         verify_asset_supplies( db );
      }
      else
         BOOST_CHECK_THROW(
            db.push_transaction( precomputable_transaction( trx ), database::skip_nothing ),
            fc::exception );
      trx.clear_signatures(); trx.operations.clear();
   };
   // Cost-mode with a FUNDED pool: the missed review alone floats to cost.
   withdraw( 0, 490000, false );
   withdraw( 1, 500000, true );
   // Task 6 quorum: one member's review is recorded as PENDING only and
   // moves no clock (single-member parity reset refused).
   auto cast_review = [&]( const account_object& who, const private_key_type& key, uint8_t kind ) {
      parity_review_operation r;
      r.voter = who.id;
      r.kind = kind;
      r.note = "quorum test attestation";
      signed_transaction tx; tx.operations.push_back( r );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      sign( tx, key );
      PUSH_TX( db, tx );
   };
   cast_review( alice, alice_private_key, GRAPHENE_STEALTH_REVIEW_PARITY );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.missed_parity_reviews, 1u ); // lone vote: pending only
      BOOST_CHECK_EQUAL( st.pending_parity_votes.size(), 1u );
   }
   withdraw( 0, 490000, false ); // still cost-mode: no quorum yet
   // Second DISTINCT member for the same kind reaches quorum: the clock moves.
   cast_review( bob, bob_private_key, GRAPHENE_STEALTH_REVIEW_PARITY );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.missed_parity_reviews, 0u );
      BOOST_CHECK( st.pending_parity_votes.empty() ); // quorum spends its pendings
   }
   withdraw( 2, 490000, true );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.parity_pool.find( core_id )->second.value, 40000 );
   }
   // Funding still halted (reports still missed): routing books zero.
   {
      share_type acc0 = core.dynamic_asset_data_id( db ).accumulated_fees;
      db.adjust_balance( dan_id, core.amount( -100000 ) );
      db.pay_market_fees( nullptr, core, core.amount( 1000000 ), true, core.amount( 100000 ) );
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.parity_pool.find( core_id )->second.value, 40000 );
      BOOST_CHECK_EQUAL( core.dynamic_asset_data_id( db ).accumulated_fees.value,
                         ( acc0 + 100000 ).value );
   }
   verify_asset_supplies( db );
   // Record the set report: a lone report is pending-only...
   cast_review( bob, bob_private_key, GRAPHENE_STEALTH_REVIEW_SET_REPORT );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK( st.parity_funding_halted ); // still halted: no quorum yet
      BOOST_CHECK_EQUAL( st.missed_set_reports, 2u );
   }
   // ...the second distinct member resumes funding.
   cast_review( alice, alice_private_key, GRAPHENE_STEALTH_REVIEW_SET_REPORT );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK( !st.parity_funding_halted );
      BOOST_CHECK_EQUAL( st.missed_set_reports, 0u );
   }
   {
      db.adjust_balance( dan_id, core.amount( -100000 ) );
      db.pay_market_fees( nullptr, core, core.amount( 1000000 ), true, core.amount( 100000 ) );
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.parity_pool.find( core_id )->second.value, 45000 );
   }
   verify_asset_supplies( db );
   // Non-member attestations never count; bad kinds reject at validate AND
   // at create time (G4-02: the do_evaluate kind gate fails fast at
   // mempool/proposal-create instead of a late block failure — the direct
   // dispatch below bypasses relay-side validate to pin the consensus gate).
   {
      parity_review_operation r;
      r.voter = dan.id; r.kind = GRAPHENE_STEALTH_REVIEW_PARITY;
      signed_transaction tx; tx.operations.push_back( r );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      sign( tx, dan_private_key );
      BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
      trx.clear();
      parity_review_operation bad;
      bad.voter = alice.id; bad.kind = 7;
      BOOST_CHECK_THROW( bad.validate(), fc::exception );
      // Create-time refusal: a committee member's bad-kind review never
      // reaches a block (fails at push, not at apply).
      {
         signed_transaction btx; btx.operations.push_back( bad );
         db.current_fee_schedule().set_fee( btx.operations.back() );
         set_expiration( db, btx );
         sign( btx, alice_private_key );
         BOOST_CHECK_THROW( PUSH_TX( db, btx ), fc::exception );
      }
      // Consensus gate (validate bypassed): do_evaluate itself rejects the
      // kind with the consensus message, so a block-producer smuggling a
      // non-validated bad-kind op fails closed at evaluation, not late.
      {
         transaction_evaluation_state es( &db );
         try
         {
            db.apply_operation( es, operation( bad ) );
            BOOST_FAIL( "bad-kind review must fail closed in do_evaluate" );
         }
         catch( const fc::exception& e )
         {
            BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Unknown parity review kind" )
                                 != std::string::npos, e.to_detail_string() );
         }
      }
      // The valid-kind control still dispatches past the kind gate to the
      // committee gate (non-member dan): proves the gate above is kind-only
      // and registration dispatches op 107 to this evaluator.
      {
         parity_review_operation good;
         good.voter = dan.id; good.kind = GRAPHENE_STEALTH_REVIEW_PARITY;
         transaction_evaluation_state es( &db );
         try
         {
            db.apply_operation( es, operation( good ) );
            BOOST_FAIL( "non-member review must reject at the committee gate" );
         }
         catch( const fc::exception& e )
         {
            BOOST_CHECK_MESSAGE( e.to_detail_string().find( "committee member" )
                                 != std::string::npos, e.to_detail_string() );
         }
      }
   }
   generate_block();
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( parity_alarms_computed_and_queryable )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   ACTORS( (alice)(dan) );
   upgrade_to_lifetime_member( alice );
   create_committee_member( alice );
   generate_block();
   const asset_object& core = asset_id_type()(db);
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()(db), dan, core.amount( 40000000 ) );

   auto k = fc::ecc::private_key::generate();
   authority own( 1, public_key_type( k.get_public_key() ), 1 );
   vector<fc::ecc::commitment_type> cs;
   vector<fc::sha256> bs; // input blinding factors (from_blind needs them)
   // Exact-conservation deposits (see routing test): withdrawals spend
   // amount+fee = 900+0, so each input commits to exactly 900.
   for( int i = 0; i < 3; ++i )
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 900 );
      ttb.from = dan.id;
      blind_output o; o.owner = own;
      // G1c cost path: deposits pay the pinned anchor (n=1, 1M) so the
      // routed pool funds only the withdrawal subsidies the alarms measure.
      ttb.fee = core.amount( 1000000 );
      auto B = T_blind_secret( "g1c-alm-b|" + std::to_string( i ) );
      auto N = T_secret( "g1c-alm-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, 900 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 900 );
      ttb.blinding_factor = B; ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      cs.push_back( o.commitment );
      bs.push_back( B );
   }
   generate_block(); // seal BEFORE grandfathering (see T_grandfather note)
   // Task 3: the two withdrawn below (cs[0], cs[1]) go through the legacy
   // op41 leg — grandfather the sealed balances so the subsidy gates (not
   // the created_block gate) decide. cs[2] stays post-fork (counted), so the
   // effective-set pin keeps measuring a live member.
   T_grandfather( db, core.get_id(), cs[0] );
   T_grandfather( db, core.get_id(), cs[1] );
   auto withdraw = [&]( size_t ci ) {
      transfer_from_blind_operation x;
      x.to = dan.id; x.amount = core.amount( 900 ); x.fee = core.amount( 0 );
      blind_input bi; bi.commitment = cs[ci]; bi.owner = own;
      x.inputs = { bi };
      x.blinding_factor = bs[ci];
      set_expiration( db, trx );
      trx.operations = { x };
      sign( trx, k );
      db.push_transaction( precomputable_transaction( trx ), database::skip_nothing );
      trx.clear_signatures(); trx.operations.clear();
   };
   // Route 20M nominal (pool +1M), grant one 500000 subsidy (zeroed schedule).
   // Task 7 legacy gate: opt CORE in so the seeding below routes.
   g1c_opt_in_parity( db, core_id );
   db.adjust_balance( dan_id, core.amount( -20000000 ) );
   db.pay_market_fees( nullptr, core, core.amount( 20000000 ), true, core.amount( 20000000 ) );
   withdraw( 0 );
   verify_asset_supplies( db );
   stealth_parity_maintenance( db );
   {
      // Queryable through the status object (the same object get_object serves).
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      auto eitr = st.alarms.effective_set.find( core_id );
      BOOST_REQUIRE( eitr != st.alarms.effective_set.end() );
      BOOST_CHECK_EQUAL( eitr->second, 1u ); // 3 created - 2 grandfathered (never counted)
      BOOST_CHECK_EQUAL( st.alarms.burn_rate_pct, 50u ); // 500000/1000000
      BOOST_CHECK( st.alarms.burn_warn );
      BOOST_CHECK( !st.alarms.burn_critical );
      BOOST_CHECK( st.alarms.decoy_skew_warn ); // young chain: pool is all-new
      BOOST_CHECK( !st.alarms.mass_exit_warn );
      BOOST_CHECK( !st.alarms.joint_cap_breach );
      BOOST_CHECK( st.interval_routed.empty() );
      BOOST_CHECK( st.interval_granted.empty() );
   }
   // Grants with no routed inflow burn 100%: critical fires.
   withdraw( 1 );
   verify_asset_supplies( db );
   stealth_parity_maintenance( db );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.alarms.burn_rate_pct, 100u );
      BOOST_CHECK( st.alarms.burn_warn );
      BOOST_CHECK( st.alarms.burn_critical );
   }
   // Inflow with no grants burns 0%: both clear.
   db.adjust_balance( dan_id, core.amount( -1000000 ) );
   db.pay_market_fees( nullptr, core, core.amount( 1000000 ), true, core.amount( 1000000 ) );
   verify_asset_supplies( db );
   stealth_parity_maintenance( db );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.alarms.burn_rate_pct, 0u );
      BOOST_CHECK( !st.alarms.burn_warn );
      BOOST_CHECK( !st.alarms.burn_critical );
   }
   // A live freeze vote (below quorum) arms the mass-exit warning.
   {
      freeze_blind_operation fz;
      fz.voter = alice.id; fz.freeze = true; fz.reason = "drill";
      signed_transaction tx; tx.operations.push_back( fz );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      sign( tx, alice_private_key );
      PUSH_TX( db, tx );
   }
   stealth_parity_maintenance( db );
   BOOST_CHECK( stealth_current_alarms( db ).mass_exit_warn );
   // Stale votes (48h expiry) stop warning.
   generate_blocks( db.head_block_time() + 3 * 86400 );
   generate_block();
   set_expiration( db, trx );
   stealth_parity_maintenance( db );
   BOOST_CHECK( !stealth_current_alarms( db ).mass_exit_warn );
   // Age the pool past the 100-block window: skew clears (block numbers,
   // not time, advance the window — 150 real blocks).
   for( int i = 0; i < 150; ++i ) generate_block();
   stealth_parity_maintenance( db );
   BOOST_CHECK( !stealth_current_alarms( db ).decoy_skew_warn );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( parity_joint_cap_with_h2 )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), dan, core.amount( 1000000 ) );
   // Pure accounting (BSIP-1 §7b: <=70% shared denominator, proposals).
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_JOINT_FEE_CAP_BPS, 7000u );
   BOOST_CHECK( stealth_joint_fee_within_cap( GRAPHENE_STEALTH_PARITY_FEE_SHARE_BPS, 0 ) );
   BOOST_CHECK( stealth_joint_fee_within_cap( 500, 2000 ) ); // H2 diverts 20%
   BOOST_CHECK( stealth_joint_fee_within_cap( 500, 6500 ) ); // boundary holds
   BOOST_CHECK( !stealth_joint_fee_within_cap( 500, 6501 ) ); // breach
   BOOST_CHECK( !stealth_joint_fee_within_cap( 500, 7000 ) );
   // Recorded H2 diversion surfaces as an alarm, never as a market-fee throw.
   auto set_h2 = [&]( uint32_t bps ) {
      db.modify( *db.get_index_type<stealth_status_index>().indices().begin(),
                 [&]( stealth_status_object& s ) { s.h2_diversion_bps = bps; } );
   };
   set_h2( 6500 );
   stealth_parity_maintenance( db );
   BOOST_CHECK( !stealth_current_alarms( db ).joint_cap_breach );
   set_h2( 6501 );
   stealth_parity_maintenance( db );
   BOOST_CHECK( stealth_current_alarms( db ).joint_cap_breach );
   {
      // Routing still books while breached (signal, not halt): mirror the
      // pay_market_fees legs exactly (offset + accumulate the remainder).
      // Task 7 legacy gate: opt CORE in so the routing below books.
      g1c_opt_in_parity( db, core.get_id() );
      db.adjust_balance( dan_id, core.amount( -100000 ) );
      share_type inc = 100000;
      share_type routed = stealth_parity_route_fee( db, core.get_id(), inc );
      BOOST_CHECK_EQUAL( routed.value, 5000 );
      BOOST_CHECK_EQUAL( inc.value, 95000 );
      db.modify( core.dynamic_asset_data_id( db ), [&]( asset_dynamic_data_object& d ) {
         d.accumulated_fees += inc;
      } );
   }
   verify_asset_supplies( db );
   set_h2( 0 );
   stealth_parity_maintenance( db );
   BOOST_CHECK( !stealth_current_alarms( db ).joint_cap_breach );
} FC_CAPTURE_AND_RETHROW() }

/// MUSE-R11 G1 side, coincident both-legs breach: the joint ceiling is a SUM
/// over one denominator (stealth_evaluator.cpp stealth_joint_fee_within_cap),
/// never a per-leg check. Pure pins first (3500+3500 breaches while NEITHER
/// leg alone exceeds the cap — RED if rewritten per-leg), then the production
/// alarm path: H2 diversion 6800 with the 500bps parity share breaches at
/// 7300 joint with both legs individually under 7000 (the atomic door+debt
/// counterpart to the H2-side coincident test: both legs over the JOINT cap
/// raises joint_cap_breach).
BOOST_AUTO_TEST_CASE( parity_joint_cap_both_legs_over_cap )
{ try {
   // Pure joint semantics: the sum binds, not the legs.
   BOOST_CHECK( stealth_joint_fee_within_cap( 0, 0 ) );
   BOOST_CHECK( stealth_joint_fee_within_cap( 7000, 0 ) ); // boundary holds
   BOOST_CHECK( stealth_joint_fee_within_cap( 0, 7000 ) ); // boundary holds
   BOOST_CHECK( !stealth_joint_fee_within_cap( 7001, 0 ) );
   BOOST_CHECK( !stealth_joint_fee_within_cap( 0, 7001 ) );
   BOOST_CHECK( !stealth_joint_fee_within_cap( 3500, 3501 ) ); // both under, joint over
   BOOST_CHECK( !stealth_joint_fee_within_cap( 500, 6800 ) ); // production shape
   BOOST_CHECK( stealth_joint_fee_within_cap( 500, 6500 ) ); // production holds

   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), dan, core.amount( 1000000 ) );

   auto set_h2 = [&]( uint32_t bps ) {
      db.modify( *db.get_index_type<stealth_status_index>().indices().begin(),
                 [&]( stealth_status_object& s ) { s.h2_diversion_bps = bps; } );
   };
   // Both legs individually under the 7000 cap (500, 6800): joint 7300
   // breaches through the maintenance alarm path.
   set_h2( 6800 );
   stealth_parity_maintenance( db );
   BOOST_CHECK( stealth_current_alarms( db ).joint_cap_breach );
   // Back under joint (500 + 6500 = 7000): clears.
   set_h2( 6500 );
   stealth_parity_maintenance( db );
   BOOST_CHECK( !stealth_current_alarms( db ).joint_cap_breach );
   verify_asset_supplies( db );
   set_h2( 0 );
   stealth_parity_maintenance( db );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( thin_pool_decoy_tightening )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_THIN_POOL_DEPTH, 64u );
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_THIN_SKEW_MAX_PCT, 25u );
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_RING_TARGET, 16u );

    auto now = db.head_block_time();
    std::string err;
    // Deep pool (>= 64): the TARGET-16 floor binds here too (Task 6, R7
    // C-01): an 11-ring is below the floor even with a perfect age spread.
    // MIN-11 is reserved for a future governance-opened thin-pool emergency,
    // never the normal path — so spread-compliant 11-rings throw deep.
    {
       std::vector<uint32_t> h = { 1, 150, 300, 450, 600, 750, 900, 1050, 1200, 1350, 1500 };
       std::vector<fc::time_point_sec> t( 11, now - 90000 );
       BOOST_CHECK_MESSAGE( !stealth_check_decoy_policy( h, t, now, 2000, err, 64 ),
                            "deep 11-ring must reject (floor is target-16)" );
       BOOST_CHECK_MESSAGE( err.find( "target size" ) != std::string::npos, err );
       BOOST_CHECK_MESSAGE( !stealth_check_decoy_policy( h, t, now, 2000, err, 1000000 ),
                            "deep 11-ring must reject at any depth >= 64" );
    }
    // Deep pool (>= 64): a 16-ring with a 40%-compliant spread passes.
    {
       std::vector<uint32_t> h;
       for( uint32_t w : { 10u, 20u, 30u, 40u } )
          for( uint32_t k = 0; k < 4; ++k )
             h.push_back( w * 100 + k );
       std::vector<fc::time_point_sec> t( 16, now - 90000 );
       BOOST_CHECK_MESSAGE( stealth_check_decoy_policy( h, t, now, 5000, err, 64 ), err );
       BOOST_CHECK_MESSAGE( stealth_check_decoy_policy( h, t, now, 5000, err, 1000000 ), err );
    }
   // Thin pool (< 64): the same spread-compliant 11-ring now rejects —
   // it is below the target size (availability yields to privacy).
   {
      std::vector<uint32_t> h = { 1, 150, 300, 450, 600, 750, 900, 1050, 1200, 1350, 1500 };
      std::vector<fc::time_point_sec> t( 11, now - 90000 );
      BOOST_CHECK_MESSAGE( !stealth_check_decoy_policy( h, t, now, 2000, err, 63 ),
                           "thin 11-ring must reject" );
      BOOST_CHECK_MESSAGE( !stealth_check_decoy_policy( h, t, now, 2000, err, 0 ),
                           "thin 11-ring must reject at depth 0" );
      BOOST_CHECK_MESSAGE( err.find( "thin-pool" ) != std::string::npos, err );
   }
   // Thin pool: a 16-ring at exactly 25% per window passes (boundary
   // inclusive, same convention as the 40% rule: exactly-at-cap passes).
   {
      std::vector<uint32_t> h;
      for( uint32_t w : { 10u, 20u, 30u, 40u } )
         for( uint32_t k = 0; k < 4; ++k )
            h.push_back( w * 100 + k );
      std::vector<fc::time_point_sec> t( 16, now - 90000 );
      BOOST_CHECK_MESSAGE( stealth_check_decoy_policy( h, t, now, 5000, err, 16 ), err );
   }
   // Thin pool: 5 of 16 in one window (31.25% > 25%) rejects — while the
   // identical ring passes deep (31.25% < 40%). The tightening binds.
   {
      std::vector<uint32_t> h = { 1000, 1001, 1002, 1003, 1004,
                                  2000, 2100, 2200, 2300, 2400, 2500,
                                  2600, 2700, 2800, 2900, 3000 };
      std::vector<fc::time_point_sec> t( 16, now - 90000 );
      BOOST_CHECK_MESSAGE( !stealth_check_decoy_policy( h, t, now, 5000, err, 16 ),
                           "thin 31%-skewed ring must reject" );
      BOOST_CHECK_MESSAGE( stealth_check_decoy_policy( h, t, now, 5000, err, 64 ), err );
   }

   // Op level: an 11-member spend over real aged outputs at depth 11
   // rejects on the thin rule — the pool FLOOR (11 >= 11) passes first, so
   // the decoy gate is what fires. Fake image/sig are fine: policy runs
   // before signature verification (same shape as the floor test above).
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), dan, core.amount( 300000000 ) );
   generate_block();
   g1c_seed_pool( db, dan_id, core, 12000000 ); // 11 deposits + this attempt
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      p.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   auto k = fc::ecc::private_key::generate();
   authority own( 1, public_key_type( k.get_public_key() ), 1 );
   std::vector<fc::ecc::commitment_type> cs;
   for( int i = 0; i < 11; ++i )
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 1000 );
      ttb.from = dan.id;
      blind_output o; o.owner = own;
      // Cost path (fee 1M = the n=1 anchor): deposits grant nothing, so the
      // aging-jump maintenance below sees no interval flow and the pool
      // stays whole for the attempt — isolating the decoy gate as the
      // rejector. (Parity-path deposits would grant 11M against a 12M seed
      // = 91% burn = critical at the jump.)
      ttb.fee = core.amount( 1000000 );
      auto B = T_blind_secret( "g1c-thin11-b|" + std::to_string( i ) );
      auto N = T_secret( "g1c-thin11-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, 1000 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 1000 );
      ttb.blinding_factor = B; ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      cs.push_back( o.commitment );
   }
   generate_blocks( db.head_block_time() + 90000 ); // +25h: all decoys old
   generate_block();
   set_expiration( db, trx );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 11u );
   // One real V1 output (so output checks pass) over the 11 real inputs.
   auto Bo = T_blind_secret( "g1c-thin11-out" );
   auto No = T_secret( "g1c-thin11-nout" );
   stealth_transfer_operation thin11;
   thin11.asset_id = core.get_id();
   thin11.proof_version = GRAPHENE_STEALTH_PROOF_V1;
   thin11.fee = core.amount( 0 );
   {
      stealth_ring_input rin;
      for( const auto& c : cs )
         rin.ring.push_back( c );
      rin.key_image = std::vector<char>( 33, 0x03 );
      rin.pseudo_output = cs[0];
      rin.ring_sig = std::vector<char>( 32 + 96 * 11, 0x01 );
      // Dummy alt linkage (rejected at the decoy gate, never verified).
      rin.alt_key_image = std::vector<char>( 33, 0x04 );
      rin.alt_ring_sig = std::vector<char>( 32 + 96 * 11, 0x01 );
      thin11.inputs = { rin };
      stealth_blind_output so;
      so.commitment = fc::ecc::blind( Bo, 990 );
      so.range_proof = fc::ecc::range_proof_sign( 0, so.commitment, Bo, No, 0, 0, 990 );
      so.owner = own;
      thin11.outputs = { so };
   }
   BOOST_CHECK_NO_THROW( thin11.validate() );
   trx.operations = { thin11 };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "thin-pool 11-ring spend must reject" );
   }
   catch( const fc::exception& e )
   {
      // what() carries only "Assert Exception"; the format lives in the
      // detail string.
      std::string w = e.to_detail_string();
      BOOST_CHECK_MESSAGE( w.find( "thin-pool" ) != std::string::npos, w );
   }
   trx.clear();
   // The thin-pool-16 ACCEPT case at op level is stealth_transfer_happy_path
   // (depth 16 < 64, target-size ring, 4x4 windows at exactly 25%).
} FC_CAPTURE_AND_RETHROW() }

// Task 3 (nullifier migration): the retired spent-membership exclusion is
// now enforced by the nullifier set. A ring reusing a REALLY-spent output
// (same opening: same images, already nullified) still refuses — at the
// nullifier gate, with the images pinned — while mere decoys stay reusable
// (pinned by g1_decoyed_output_remains_spendable_after_flag_retirement).
BOOST_AUTO_TEST_CASE( spent_ring_member_excluded )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "t6-spent", 16, true );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 16u );
   // Honest spend grows the live set (Task 3: 16 - 0 + 2).
   stealth_transfer_operation first = t5_build_spend( core, p, 5,
      GRAPHENE_STEALTH_PROOF_V1, "t6-spent-1", 600, 390, 10 );
   trx.operations = { first };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 18u );
   // Top the pool back over the floor with fresh cost-path deposits (fee 1M
   // = the n=1 anchor: no subsidy involvement either way). No time jump:
   // the nullifier gate fires before any age/policy math, and jumping
   // would cross a maintenance that recomputes burn-critical from the
   // spend's interval flow and block the attempt at the fee gate instead.
   for( int i = 0; i < 16; ++i )
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 1000 );
      ttb.from = dan.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_blind_secret( "t6-spent-top-b|" + std::to_string( i ) );
      auto N = T_secret( "t6-spent-top-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, 1000 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 1000 );
      ttb.blinding_factor = B;
      ttb.fee = core.amount( 1000000 ); // cost path: keep the parity pool whole
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      generate_block();
   }
   set_expiration( db, trx );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 34u );
   // Re-arm the subsidy path deterministically (direct pool top-up: no blocks,
   // no maintenance, no burn recompute) so the attempt below reaches the
   // nullifier gate instead of the fee gate.
   g1c_seed_pool( db, dan_id, core, 5000000 );
   // Second spend reusing the same real opening (first in the ring, so the
   // per-input loop meets its nullified images before any policy math) must
   // refuse there.
   stealth_transfer_operation second = t5_build_spend( core, p, 5,
      GRAPHENE_STEALTH_PROOF_V1, "t6-spent-2", 600, 390, 10 );
   trx.operations = { second };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "ring reusing a really-spent opening must reject" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Key image already spent" ) != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear();
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// Task 6: pool-depth < 22 raises a WARNING alarm (flags only — never a market
// or blind-path assert), and the effective set is queryable via database_api.
BOOST_AUTO_TEST_CASE( thin_pool_warn_flag_and_effective_set_api )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()(db), dan, core.amount( 100000000 ) );
   generate_block();
   auto deposit_one = [&]( int i ) {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 1000 );
      ttb.from = dan.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_blind_secret( "t6-warn-b|" + std::to_string( i ) );
      auto N = T_secret( "t6-warn-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, 1000 );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, 1000 );
      ttb.blinding_factor = B;
      ttb.fee = core.amount( 1000000 ); // cost path: no subsidy involvement
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
   };
   for( int i = 0; i < 16; ++i ) deposit_one( i );
   generate_block();
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core_id ), 16u );
   stealth_parity_maintenance( db );
   // 16 < 22: the warning alarm is set, but nothing halts on it.
   BOOST_CHECK( stealth_current_alarms( db ).thin_pool_warn );
   // Flags only: deposits (which grow the pool) still clear while warned.
   BOOST_CHECK_NO_THROW( deposit_one( 100 ) );
   generate_block();
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core_id ), 17u );
   // The effective set is exposed to wallets/UIs through database_api.
   {
      graphene::app::database_api db_api( db );
      flat_map<asset_id_type, uint32_t> eff = db_api.get_stealth_effective_set();
      auto eitr = eff.find( core_id );
      BOOST_REQUIRE( eitr != eff.end() );
      BOOST_CHECK_EQUAL( eitr->second, 17u );
   }
   // At/above 22 the warning clears.
   for( int i = 0; i < 8; ++i ) deposit_one( 200 + i );
   generate_block();
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core_id ), 25u );
   stealth_parity_maintenance( db );
   BOOST_CHECK( !stealth_current_alarms( db ).thin_pool_warn );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// Task 5 (nullifier migration): pool-floor regression under live-set semantics.
// Under the retired flag the counter shrank on every ring spend, so heavy ring
// activity alone could drive the pool to the floor and halt spends. Under
// live-set semantics a ring spend removes nothing and creates outputs, so the
// counter only falls on genuine exits: the floor still halts a genuinely thin
// pool (a) but never a pool "drained" by ring activity (b) — the behaviour
// change users will notice.
BOOST_AUTO_TEST_CASE( pool_floor_halts_thin_pool_not_ring_activity )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   // Re-derived Task 5 tripwire pins: halt below one minimum ring (11),
   // alarm below two (22, one ring of headroom). See stealth.hpp.
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_BLIND_POOL_FLOOR, 11u );
   BOOST_REQUIRE_EQUAL( GRAPHENE_STEALTH_POOL_WARN_DEPTH, 22u );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   transfer( account_id_type()(db), dan, core.amount( 500000000 ) );
   generate_block();
   // Ring ops exceed the 2048B default transaction ceiling by design
   // (11-member dual rings alone are ~2.2kB). Production enables them via
   // committee-set maximum_transaction_size; the test mirrors that
   // governance action directly (precedent: db.modify on global properties
   // in authority_tests/block_tests). Needed up front: the size gate runs
   // before evaluation, so without it the dummy spends below would reject
   // at the size gate instead of the gate under test.
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      p.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   // Seed the parity pool so fee-0 dummy spends below reach the pool FLOOR
   // (not the float rule): the floor — never the subsidy — must decide them
   // (same seeding trick as decoy_rules_enforced).
   g1c_seed_pool( db, dan_id, core, 24000000 );
   // Wire-valid dummy ring (shape passes validate(); members are fake, so a
   // pool that clears the floor rejects it downstream — the floor message
   // pin below distinguishes the two rejections).
   auto make_dummy_ring = [&]( const authority& owner ) {
      stealth_transfer_operation thin;
      thin.asset_id = core.get_id();
      thin.proof_version = GRAPHENE_STEALTH_PROOF_V1;
      thin.fee = core.amount( 0 );
      stealth_ring_input frin;
      for( int i = 0; i < 11; ++i )
      {
         fc::ecc::commitment_type fc_;
         fc_.data()[0] = (char)( 0x02 + ( i & 1 ) );
         fc_.data()[1] = (char)i; fc_.data()[2] = (char)0x77;
         frin.ring.push_back( fc_ );
      }
      frin.key_image = std::vector<char>( 33, 0x03 );
      frin.pseudo_output = frin.ring[0];
      frin.ring_sig = std::vector<char>( 32 + 96 * 11, 0x01 );
      frin.alt_key_image = std::vector<char>( 33, 0x04 );
      frin.alt_ring_sig = std::vector<char>( 32 + 96 * 11, 0x01 );
      thin.inputs = { frin };
      stealth_blind_output fout;
      fout.commitment = frin.ring[1];
      fout.range_proof = std::vector<char>( 1, 0x02 );
      fout.owner = owner;
      thin.outputs = { fout };
      return thin;
   };
   auto dan_owner = authority( 1, dan_id, 1 );
   // (a) Genuinely thin pool (depth 0 < 11): the floor gate halts HERE —
   // pin the message so a future gate reorder is caught, not papered over.
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 0u );
   {
      stealth_transfer_operation thin = make_dummy_ring( dan_owner );
      BOOST_CHECK_NO_THROW( thin.validate() ); // wire shape is fine...
      trx.operations = { thin };
      try { PUSH_TX( db, trx ); BOOST_FAIL( "thin pool must halt at the floor" ); }
      catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "below floor" ) != std::string::npos,
                              e.to_detail_string() );
      }
      trx.clear();
   }
   // (b) Fund 16 post-fork outputs (4/4/4/4) spread over four 100-block
   // windows so the thin-pool 25%-skew rule (R-04: depth 16 < 64) is
   // satisfiable at the target ring size 16; then age them 25h in one jump.
   // Mirrors stealth_transfer_happy_path (same subsidy math: 16 x 1M gap +
   // one 1.5M spend against the 24M seed).
   std::vector<fc::sha256> blinds;
   std::vector<fc::ecc::commitment_type> commits;
   auto fund_one = [&]( int i, uint64_t v ) {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( v );
      ttb.from = dan.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_blind_secret( "t5-floor-b|" + std::to_string( i ) );
      auto N = T_secret( "t5-floor-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, v );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, v );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      blinds.push_back( B );
      commits.push_back( o.commitment );
   };
   for( int i = 0; i < 4; ++i ) { fund_one( i, 1000 ); generate_block(); }
   generate_blocks( 110 );
   for( int i = 4; i < 8; ++i ) { fund_one( i, 1000 ); generate_block(); }
   generate_blocks( 110 );
   for( int i = 8; i < 12; ++i ) { fund_one( i, 1000 ); generate_block(); }
   generate_blocks( 110 );
   for( int i = 12; i < 16; ++i ) { fund_one( i, 1000 ); generate_block(); }
   generate_blocks( db.head_block_time() + 90000 ); // +25h: all decoys old
   generate_block();
   set_expiration( db, trx );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 16u );
   // One genuine ring spend: output #5 (value 1000) into two V1 outputs
   // (600 + 390, fee 10). Same kernel construction as the happy path.
   size_t s = 5;
   BIGNUM* bs = T_bn( blinds[s] );
   BIGNUM* bprime = T_bn( T_blind_secret( "t5-floor-pseudo" ) );
   auto Bk1 = T_blind_secret( "t5-floor-out1" );
   auto Bk2 = T_blind_secret( "t5-floor-out2" );
   auto Nk1 = T_secret( "t5-floor-nout1" );
   auto Nk2 = T_secret( "t5-floor-nout2" );
   auto rk1 = fc::ecc::private_key::generate();
   auto rk2 = fc::ecc::private_key::generate();
   stealth_blind_output so1, so2;
   so1.commitment = fc::ecc::blind( Bk1, 600 );
   so1.range_proof = fc::ecc::range_proof_sign( 0, so1.commitment, Bk1, Nk1, 0, 0, 600 );
   so1.owner = authority( 1, public_key_type( rk1.get_public_key() ), 1 );
   so2.commitment = fc::ecc::blind( Bk2, 390 );
   so2.range_proof = fc::ecc::range_proof_sign( 0, so2.commitment, Bk2, Nk2, 0, 0, 390 );
   so2.owner = authority( 1, public_key_type( rk2.get_public_key() ), 1 );
   stealth_transfer_operation stop;
   stop.asset_id = core.get_id();
   stop.proof_version = GRAPHENE_STEALTH_PROOF_V1;
   stop.fee = core.amount( 10 );
   stop.outputs = { so1, so2 };
   {
      BIGNUM* e = BN_new();
      BIGNUM* t = BN_new();
      BIGNUM* b1 = T_bn( Bk1 );
      BIGNUM* b2 = T_bn( Bk2 );
      BN_copy( e, bprime );
      BN_mod_sub( e, e, b1, T_order(), T_ctx() );
      BN_mod_sub( e, e, b2, T_order(), T_ctx() );
      unsigned char eb[32]; BN_bn2binpad( e, eb, 32 );
      std::copy( eb, eb + 32, (char*)stop.excess.data() );
      BN_free( e ); BN_free( t ); BN_free( b1 ); BN_free( b2 );
   }
   std::vector<std::vector<unsigned char>> Q;
   for( const auto& c : commits )
      Q.push_back( std::vector<unsigned char>( c.begin(), c.end() ) );
   std::vector<fc::ecc::commitment_type> out_cs = { so1.commitment, so2.commitment };
   auto Pv = T_commit( bprime, 1000 );
   fc::ecc::commitment_type pseudo_c = T_commitment( Pv );
   std::vector<unsigned char> img0, pseudo0; std::vector<char> sig0;
   {
      std::string m0( 32, '\0' );
      T_prove_ring( GRAPHENE_STEALTH_PROOF_V1, Q, s, bs, 1000, bprime,
                    m0, img0, pseudo0, sig0 );
   }
   BOOST_REQUIRE( pseudo0 == Pv );
   std::vector<unsigned char> img2, pseudo2; std::vector<char> sig2;
   {
      std::string m0( 32, '\0' );
      T_prove_ring( GRAPHENE_STEALTH_PROOF_V2, Q, s, bs, 1000, bprime,
                    m0, img2, pseudo2, sig2 );
   }
   BOOST_REQUIRE( pseudo2 == Pv );
   std::vector<char> img0c( img0.begin(), img0.end() );
   std::vector<char> img2c( img2.begin(), img2.end() );
   fc::sha256 m = stealth_ring_message( stop.proof_version, stop.asset_id,
      img0c, commits, pseudo_c, out_cs, stop.fee.amount );
   fc::sha256 m_alt = stealth_ring_message( GRAPHENE_STEALTH_PROOF_V2, stop.asset_id,
      img2c, commits, pseudo_c, out_cs, stop.fee.amount );
   std::string ms( (const char*)m.data(), 32 );
   std::string ms_alt( (const char*)m_alt.data(), 32 );
   stealth_ring_input rin = T_make_dual_ring_input( GRAPHENE_STEALTH_PROOF_V1,
      GRAPHENE_STEALTH_PROOF_V2, Q, s, bs, 1000, bprime, ms, ms_alt );
   stop.inputs = { rin };
   BOOST_CHECK_NO_THROW( stop.validate() );
   trx.operations = { stop };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   // Live-set counter: 16 funded, the ring removes nothing, 2 outputs
   // created -> 18. Ring activity GREW the pool; under the retired flag
   // this same spend would have left it at 15, draining toward the floor.
   // Task 6: REQUIRE, not CHECK — phase (b2) below must never run on a
   // failed precondition (a silent 15/16 here would flip the (b2) verdict
   // from "not floor-halted" to a false RED at the floor).
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 18u );
   // ...and a follow-up spend is NOT floor-halted: the dummy clears the
   // floor (18 >= 11) and rejects downstream instead. If a future refactor
   // re-shrinks the counter on ring spends, this goes RED at the floor.
   {
      stealth_transfer_operation thin2 = make_dummy_ring( dan_owner );
      trx.operations = { thin2 };
      try { PUSH_TX( db, trx ); BOOST_FAIL( "dummy ring must reject downstream, not halt" ); }
      catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "below floor" ) == std::string::npos,
                              e.to_detail_string() );
      }
      trx.clear();
   }
   BN_free( bs ); BN_free( bprime );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }
// The test-side sampler implements the documented normative rule verbatim:
// uniform-without-replacement over eligible (aged) candidates, TARGET-16
// size, the depth-appropriate skew cap, bounded retries. Compliant samples
// must ACCEPT against consensus policy; rule violations (clustered windows,
// young members) must REJECT — proving the documented rule and the
// consensus gate agree.
BOOST_AUTO_TEST_CASE( ring_sampler_rule_conformance )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   auto now = db.head_block_time();
   // Synthetic eligible pool: 100 candidates, 10 per 100-block window over
   // 10 windows, all older than 24h (metadata-bearing by construction here;
   // the metadata/nullifier gates are op-level, pinned by their own tests).
   std::vector<uint32_t> pool_h;
   for( uint32_t w = 0; w < 10; ++w )
      for( uint32_t k = 0; k < 10; ++k )
         pool_h.push_back( 1000 + w * 100 + k );
   std::vector<fc::time_point_sec> pool_t( pool_h.size(), now - 90000 );
   // Sampler: uniform without replacement (deterministic seed: the rule, not
   // the entropy, is under test), TARGET-16 size, skew cap checked per draw
   // with bounded retries (never ship a skewed ring silently).
   auto sample_compliant = [&]( uint32_t depth, uint32_t seed ) {
      std::vector<uint32_t> h;
      std::vector<fc::time_point_sec> t;
      std::mt19937 rng( seed );
      for( int attempt = 0; attempt < 50 && h.size() < 16; ++attempt )
      {
         std::vector<size_t> idx( pool_h.size() );
         for( size_t i = 0; i < idx.size(); ++i ) idx[i] = i;
         std::shuffle( idx.begin(), idx.end(), rng );
         std::vector<uint32_t> cand_h;
         for( size_t i = 0; i < 16; ++i ) cand_h.push_back( pool_h[ idx[i] ] );
         // skew pre-check mirrors the consensus caps (40% deep / 25% thin).
         const bool thin = ( depth < GRAPHENE_STEALTH_THIN_POOL_DEPTH );
         bool skewed = false;
         for( size_t i = 0; i < cand_h.size() && !skewed; ++i )
         {
            uint32_t w = cand_h[i] / GRAPHENE_STEALTH_DECOY_SKEW_WINDOW_BLOCKS;
            size_t count = 0;
            for( size_t j = 0; j < cand_h.size(); ++j )
               if( cand_h[j] / GRAPHENE_STEALTH_DECOY_SKEW_WINDOW_BLOCKS == w )
                  ++count;
            skewed = thin ? ( count * 4 > 16 ) : ( count * 5 > 2 * 16 );
         }
         if( skewed )
            continue; // resample: never ship a skewed ring silently
         h = cand_h;
         t.assign( 16, now - 90000 );
      }
      return std::make_pair( h, t );
   };
   std::string err;
   // Deep pool: three independently seeded compliant samples all accept.
   for( uint32_t s = 1; s <= 3; ++s )
   {
      auto pr = sample_compliant( 1000, s );
      BOOST_REQUIRE_EQUAL( pr.first.size(), 16u );
      BOOST_CHECK_MESSAGE( stealth_check_decoy_policy( pr.first, pr.second,
         now, 3000, err, 1000 ), "compliant deep sample " << s << ": " << err );
   }
   // Thin pool (16): the same rule with the 25% cap accepts.
   {
      auto pr = sample_compliant( 16, 7 );
      BOOST_REQUIRE_EQUAL( pr.first.size(), 16u );
      BOOST_CHECK_MESSAGE( stealth_check_decoy_policy( pr.first, pr.second,
         now, 3000, err, 16 ), err );
   }
   // Violations reject: 7 of 16 in one window (43.75% > 40% deep)...
   {
      std::vector<uint32_t> h = { 1000, 1001, 1002, 1003, 1004, 1005, 1006,
                                  2000, 2100, 2200, 2300, 2400, 2500,
                                  2600, 2700, 2800 };
      std::vector<fc::time_point_sec> t( 16, now - 90000 );
      BOOST_CHECK_MESSAGE( !stealth_check_decoy_policy( h, t, now, 3000, err, 1000 ),
                           "clustered ring must reject" );
   }
   // ...and one young member rejects even in a compliant spread.
   {
      auto pr = sample_compliant( 1000, 11 );
      BOOST_REQUIRE_EQUAL( pr.first.size(), 16u );
      pr.second[3] = now - 3600;
      BOOST_CHECK_MESSAGE( !stealth_check_decoy_policy( pr.first, pr.second,
         now, 3000, err, 1000 ), "young member must reject" );
   }
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( parity_burn_critical_halts_new_subsidies )
{ try {
   // G3-03: the R-05 halt is maintenance-lagged but real — while
   // burn_critical is set, new subsidies refuse (parity path rejects, the
   // cost-anchor path still clears); the next maintenance auto-clears with
   // fresh routed/granted flow and subsidies resume.
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()(db), dan, core.amount( 100000000 ) );
   generate_block(); // seal-then-modify: schedule + pool writes are direct
   // Gap 10000 per withdrawal (parity 490000 vs 500000 pinned anchor, n=0).
   // Pin scale at 100% (see the cap test note): test genesis zeroes it.
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      auto& fees = p.parameters.get_mutable_fees();
      fees.scale = GRAPHENE_100_PERCENT;
      auto& fee_params = fees.parameters;
      auto itr = fee_params.find( transfer_from_blind_operation::fee_params_t() );
      itr->get<transfer_from_blind_operation::fee_params_t>().fee = 490000;
   } );
   BOOST_REQUIRE_EQUAL( stealth_parity_gap_core( db, 0, share_type( 490000 ), 0 ).value, 10000 );
   // Seed the pool (5% of 1M = 50000) BEFORE forcing the halt.
   // Task 7 legacy gate: opt CORE in so the seeding below routes.
   g1c_opt_in_parity( db, core_id );
   db.adjust_balance( dan_id, core.amount( -1000000 ) );
   db.pay_market_fees( nullptr, core, core.amount( 1000000 ), true, core.amount( 1000000 ) );
   BOOST_REQUIRE_EQUAL(
      db.get_index_type<stealth_status_index>().indices().begin()->parity_pool.find( core_id )->second.value,
      50000 );

   auto k = fc::ecc::private_key::generate();
   authority own( 1, public_key_type( k.get_public_key() ), 1 );
   auto deposit = [&]( const std::string& tag, int64_t dep ) -> std::pair<fc::ecc::commitment_type, fc::sha256> {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( dep );
      ttb.from = dan.id;
      blind_output o; o.owner = own;
      ttb.fee = core.amount( 1000000 ); // cost path: pool reserved for the legs under test
      auto B = T_blind_secret( "g1c-halt-b|" + tag );
      auto N = T_secret( "g1c-halt-n|" + tag );
      o.commitment = fc::ecc::blind( B, dep );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, dep );
      ttb.blinding_factor = B; ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      return { o.commitment, B };
   };
   // Exact-conservation inputs: parity leg spends 900 + 490000, cost leg
   // spends 900 + 500000, post-clear leg spends 900 + 490000.
   auto cP = deposit( "parity", 490900 );
   auto cC = deposit( "cost", 500900 );
   auto cR = deposit( "resume", 490900 );
   generate_block(); // seal BEFORE grandfathering (see T_grandfather note).
   // (The halt flag below is also a direct modify, but on the sealed status
   // object — no pending tx recreates it, so it persists.)
   // Task 3: every deposit above is withdrawn via the legacy op41 leg below
   // — grandfather each sealed balance so the halt/cost gates (not the
   // created_block gate) decide every leg.
   T_grandfather( db, core.get_id(), cP.first );
   T_grandfather( db, core.get_id(), cC.first );
   T_grandfather( db, core.get_id(), cR.first );
   auto withdraw = [&]( const std::pair<fc::ecc::commitment_type, fc::sha256>& in,
                        int64_t fee, bool expect_ok ) {
      transfer_from_blind_operation x;
      x.to = dan.id; x.amount = core.amount( 900 ); x.fee = core.amount( fee );
      blind_input bi; bi.commitment = in.first; bi.owner = own;
      x.inputs = { bi };
      x.blinding_factor = in.second;
      set_expiration( db, trx );
      trx.operations = { x };
      sign( trx, k );
      if( expect_ok )
      {
         db.push_transaction( precomputable_transaction( trx ), database::skip_nothing );
         verify_asset_supplies( db );
      }
      else
         BOOST_CHECK_THROW(
            db.push_transaction( precomputable_transaction( trx ), database::skip_nothing ),
            fc::exception );
      trx.clear_signatures(); trx.operations.clear();
   };
   // Force the alarm with a funded pool (maintenance would set it from
   // flow; direct-set isolates the halt from the ratio math).
   db.modify( *db.get_index_type<stealth_status_index>().indices().begin(),
              []( stealth_status_object& s ) { s.alarms.burn_critical = true; } );
   // Parity path refuses while critical...
   withdraw( cP, 490000, false );
   // ...the cost-anchor path still clears (halt never bricks traffic)...
   withdraw( cC, 500000, true );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.parity_pool.find( core_id )->second.value, 50000 ); // untouched
   }
   // Next maintenance auto-clears (this interval routed 50000, granted 0:
   // worst 0%) and fresh flow resumes subsidies.
   stealth_parity_maintenance( db );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK( !st.alarms.burn_critical );
      BOOST_CHECK_EQUAL( st.alarms.burn_rate_pct, 0u );
   }
   db.adjust_balance( dan_id, core.amount( -1000000 ) );
   db.pay_market_fees( nullptr, core, core.amount( 1000000 ), true, core.amount( 1000000 ) );
   withdraw( cR, 490000, true );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.parity_pool.find( core_id )->second.value, 90000 );
      BOOST_REQUIRE( st.interval_granted.find( core_id ) != st.interval_granted.end() );
      BOOST_CHECK_EQUAL( st.interval_granted.find( core_id )->second.value, 10000 );
   }
   stealth_parity_maintenance( db );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.alarms.burn_rate_pct, 20u ); // 10000/50000 this interval
      BOOST_CHECK( !st.alarms.burn_warn );
      BOOST_CHECK( !st.alarms.burn_critical );
   }
   verify_asset_supplies( db );
   generate_block();
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( parity_uia_cer_gap_bound )
{ try {
   // G3-01 + G3-06: non-CORE CER gap conversion rounds UP (pool-favoring)
   // with a ceil-vs-floor difference bounded by 1 unit. A 3:2 CER makes
   // every odd gap expose the rounding leg.
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()(db), dan, core.amount( 10000000 ) );
   const asset_object& uia = create_user_issued_asset( "TESTUIA" );
   const asset_id_type uia_id = uia.get_id();
   issue_uia( dan, uia.amount( 1000000 ) );
   generate_block(); // seal-then-modify: CER + pool writes below are direct
   // Non-dividing CER: 2 TESTUIA cost 3 CORE units (tiny units, exact math).
   db.modify( uia, [&]( asset_object& a ) {
      a.options.core_exchange_rate = price( core.amount( 3 ), asset( 2, uia_id ) );
   } );
   // CORE identity + zero fast paths.
   BOOST_CHECK_EQUAL( stealth_gap_to_asset( db, core_id, share_type( 1001 ) ).value, 1001 );
   BOOST_CHECK_EQUAL( stealth_gap_to_asset( db, uia_id, share_type( 0 ) ).value, 0 );
   // Odd gap: ceil(1001*3/2) = 1502 vs floor 1501 — the 1-unit bound.
   BOOST_CHECK_EQUAL( stealth_gap_to_asset( db, uia_id, share_type( 1001 ) ).value, 1502 );
   // Even gap: exact division, no rounding leg.
   BOOST_CHECK_EQUAL( stealth_gap_to_asset( db, uia_id, share_type( 1000 ) ).value, 1500 );
   // Sweep: converted - floor(exact) is always 0 or 1, never negative.
   for( int64_t g = 0; g <= 64; ++g )
   {
      int64_t conv = stealth_gap_to_asset( db, uia_id, share_type( g ) ).value;
      int64_t floor_v = ( g * 3 ) / 2;
      BOOST_CHECK_GE( conv, floor_v );
      BOOST_CHECK_LE( conv - floor_v, 1 );
      BOOST_CHECK_GE( conv * 2, g * 3 ); // never under-debits the pool
   }
   // Availability honors the ceil: fund the pool with exactly 1502 TESTUIA
   // through the real routing leg (supply-neutral: dan debited, pool +
   // accumulated credited — direct pool writes would break
   // verify_asset_supplies, which counts the pool). 1502 covers gap 1001
   // exactly; gap 1002 needs ceil(1002*3/2) = 1503 and is short.
   // Task 7 legacy gate: opt the UIA in so the seeding below routes.
   // (Re-fetched by id — see the pending-session note in per_asset_halt_scope.)
   g1c_opt_in_parity( db, uia_id );
   db.adjust_balance( dan_id, uia_id( db ).amount( -30040 ) );
   db.pay_market_fees( nullptr, uia_id( db ), uia_id( db ).amount( 30040 ), true, uia_id( db ).amount( 30040 ) );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_REQUIRE_EQUAL( st.parity_pool.find( uia_id )->second.value, 1502 );
   }
   BOOST_CHECK( stealth_parity_available( db, uia_id, share_type( 1001 ) ) );
   BOOST_CHECK( !stealth_parity_available( db, uia_id, share_type( 1002 ) ) );
   verify_asset_supplies( db );
   generate_block();
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( gap_cer_edge_guards )
{ try {
   // G4-01: the CER + gap guards in stealth_gap_to_asset fail closed.
   // price::validate pins both CER legs at issue/update time, but consensus
   // must not trust stored state (direct db.modify bypasses validate — the
   // same way a replayed/corrupt CER would arrive). Zero base without the
   // fix converts every gap to 0 (free subsidy: pool never debited); a
   // negative gap without the fix passes the CORE fast path ungated while
   // the UIA path wraps to uint64 and trips overflow. Both pinned with
   // exact-message asserts; the CER is restored after each leg so
   // verify_asset_supplies still balances (CER is not supply state).
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()(db), dan, core.amount( 10000000 ) );
   const asset_object& uia = create_user_issued_asset( "TESTUIA" );
   const asset_id_type uia_id = uia.get_id();
   issue_uia( dan, uia.amount( 1000000 ) );
   generate_block(); // seal-then-modify: CER writes below are direct
   db.modify( uia, [&]( asset_object& a ) {
      a.options.core_exchange_rate = price( core.amount( 3 ), asset( 2, uia_id ) );
   } );
   // Sanity: the 3:2 CER still converts (ceil(1001*3/2) = 1502).
   BOOST_CHECK_EQUAL( stealth_gap_to_asset( db, uia_id, share_type( 1001 ) ).value, 1502 );
   // Zero gap fast path (both legs): 0 in, 0 out, no throw.
   BOOST_CHECK_EQUAL( stealth_gap_to_asset( db, core_id, share_type( 0 ) ).value, 0 );
   BOOST_CHECK_EQUAL( stealth_gap_to_asset( db, uia_id, share_type( 0 ) ).value, 0 );
   // Negative gap fails closed on BOTH legs with the consensus message.
   for( auto aid : { core_id, uia_id } )
   {
      try
      {
         stealth_gap_to_asset( db, aid, share_type( -1 ) );
         BOOST_FAIL( "negative gap must fail closed" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "non-negative gap" )
                              != std::string::npos, e.to_detail_string() );
      }
      try
      {
         stealth_gap_to_asset( db, aid, share_type( -1000000 ) );
         BOOST_FAIL( "negative gap must fail closed" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "non-negative gap" )
                              != std::string::npos, e.to_detail_string() );
      }
   }
   // Zero CER base fails closed (would otherwise convert every gap to 0).
   db.modify( uia, [&]( asset_object& a ) {
      a.options.core_exchange_rate = price( core.amount( 0 ), asset( 2, uia_id ) );
   } );
   try
   {
      stealth_gap_to_asset( db, uia_id, share_type( 100 ) );
      BOOST_FAIL( "zero CER base must fail closed" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "valid CER" )
                           != std::string::npos, e.to_detail_string() );
   }
   // Zero CER quote still fails closed (pre-existing gate, pinned here).
   db.modify( uia, [&]( asset_object& a ) {
      a.options.core_exchange_rate = price( core.amount( 3 ), asset( 0, uia_id ) );
   } );
   try
   {
      stealth_gap_to_asset( db, uia_id, share_type( 100 ) );
      BOOST_FAIL( "zero CER quote must fail closed" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "valid CER" )
                           != std::string::npos, e.to_detail_string() );
   }
   // Overflow CER fails closed: gap 1000 at base 1e15 / quote 1 needs
   // 1000*1e15 = 1e18 units > GRAPHENE_MAX_SHARE_SUPPLY (1e15).
   db.modify( uia, [&]( asset_object& a ) {
      a.options.core_exchange_rate = price( core.amount( GRAPHENE_MAX_SHARE_SUPPLY ),
                                            asset( 1, uia_id ) );
   } );
   try
   {
      stealth_gap_to_asset( db, uia_id, share_type( 1000 ) );
      BOOST_FAIL( "overflowing CER conversion must fail closed" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "overflow" )
                           != std::string::npos, e.to_detail_string() );
   }
   // Restore the valid CER: conversion + availability work again.
   db.modify( uia, [&]( asset_object& a ) {
      a.options.core_exchange_rate = price( core.amount( 3 ), asset( 2, uia_id ) );
   } );
   BOOST_CHECK_EQUAL( stealth_gap_to_asset( db, uia_id, share_type( 1000 ) ).value, 1500 );
   verify_asset_supplies( db );
   generate_block();
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( parity_dust_and_scale )
{ try {
   // G3-06 + G3-01: (a) dust routing returns zero and dirties no state;
   // (b) the fee-schedule scale factor moves the cost anchor's current leg
   // exactly as it moves parity_core (both through calculate_fee), so a
   // committee repricing cannot open a windfall subsidy gap.
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx ); // H1 pattern (oracle_tests): ACTORS/trx go stale across the jump
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()(db), dan, core.amount( 10000000 ) );
   generate_block(); // seal: routing + fee writes below are direct

   // --- dust: 1 and 19 route zero at 500bps (never a partial unit) ---
   // Supply-neutral mirroring (G3-07): every routed increment is funded by
   // a balance debit, the remainder credited to accumulated_fees — the same
   // legs pay_market_fees runs, so verify_asset_supplies holds.
   // Task 7 legacy gate: opt CORE in — the dust boundary math below
   // applies to opted-in assets (dust still routes zero by rule).
   g1c_opt_in_parity( db, core_id );
   {
      const auto& st0 = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK( st0.parity_pool.find( core_id ) == st0.parity_pool.end() );
      BOOST_CHECK( st0.interval_routed.find( core_id ) == st0.interval_routed.end() );
      for( int64_t dust : { 1, 19 } )
      {
         db.adjust_balance( dan_id, core.amount( -dust ) );
         share_type inc = dust;
         share_type routed = stealth_parity_route_fee( db, core_id, inc );
         BOOST_CHECK_EQUAL( routed.value, 0 );
         BOOST_CHECK_EQUAL( inc.value, dust ); // remainder untouched
         db.modify( core.dynamic_asset_data_id( db ), [&]( asset_dynamic_data_object& d ) {
            d.accumulated_fees += inc;
         } );
      }
      // 20 routes exactly one unit (20*500/10000 = 1): the dust boundary.
      // Routed into the pool with the remainder credited back, supply-neutral.
      {
         db.adjust_balance( dan_id, core.amount( -20 ) );
         share_type inc = 20;
         share_type routed = stealth_parity_route_fee( db, core_id, inc );
         BOOST_CHECK_EQUAL( routed.value, 1 );
         BOOST_CHECK_EQUAL( inc.value, 19 );
         db.modify( core.dynamic_asset_data_id( db ), [&]( asset_dynamic_data_object& d ) {
            d.accumulated_fees += inc;
         } );
      }
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.parity_pool.find( core_id )->second.value, 1 );
      verify_asset_supplies( db );
   }

   // --- scale: anchor current leg tracks parity_core through repricing ---
   // Live schedule: transfer_to_blind 600000 (+0 ppo), transfer_from_blind
   // 500000. Pinned n=0 floor is 500000; activation snapshot is 0 (zeroed
   // test genesis), so the current leg governs at both scales. Note test
   // genesis also zeroes the scale itself (fees.scale == 0 maps every
   // schedule to 0) — the pre-parity cases above rely on that; here scale
   // is set explicitly per leg via parity_at().
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      auto& fees = p.parameters.get_mutable_fees();
      auto& params = fees.parameters;
      params.find( transfer_to_blind_operation::fee_params_t() )
         ->get<transfer_to_blind_operation::fee_params_t>().fee = 600000;
      auto& params2 = p.parameters.get_mutable_fees().parameters;
      params2.find( transfer_from_blind_operation::fee_params_t() )
         ->get<transfer_from_blind_operation::fee_params_t>().fee = 500000;
   } );
   transfer_from_blind_operation probe;
   const auto parity_at = [&]( uint32_t scale ) -> share_type {
      db.modify( db.get_global_properties(), [&]( global_property_object& p ) {
         p.parameters.get_mutable_fees().scale = scale;
      } );
      return db.current_fee_schedule().calculate_fee( operation( probe ) ).amount;
   };
   // Scale 100%: parity 500000, anchor max(600000, pinned 500000) = 600000.
   BOOST_CHECK_EQUAL( parity_at( GRAPHENE_100_PERCENT ).value, 500000 );
   BOOST_CHECK_EQUAL( stealth_cost_anchor_core( db, 0 ).value, 600000 );
   BOOST_CHECK_EQUAL( stealth_parity_gap_core( db, 0, share_type( 500000 ), 0 ).value, 100000 );
   // Scale 200%: BOTH legs double — anchor 1200000 (not the raw 600000 a
   // scale-blind read would pin), parity 1000000, gap 200000. G3-01 pin:
   // without the fix the anchor would sit at 600000 while parity cleared
   // at 1000000, a 400000 windfall subsidy per op.
   BOOST_CHECK_EQUAL( parity_at( 2 * GRAPHENE_100_PERCENT ).value, 1000000 );
   BOOST_CHECK_EQUAL( stealth_cost_anchor_core( db, 0 ).value, 1200000 );
   BOOST_CHECK_NE( stealth_cost_anchor_core( db, 0 ).value, 600000 );
   BOOST_CHECK_EQUAL( stealth_parity_gap_core( db, 0, share_type( 1000000 ), 0 ).value, 200000 );
   verify_asset_supplies( db );
   generate_block();
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( g1_genesis_evaluator_registration )
{ try {
   // G3-04/E-07 genesis coverage: every new G1 op (104-107) has a registered
   // evaluator, every evaluator-touched index is registered from genesis,
   // and replay-from-genesis (pre-hardfork push) refuses op 107.
   ACTORS( (dan) );
   // (a) indexes exist before any block (genesis state, no fork needed).
   BOOST_CHECK_NO_THROW( db.get_index_type<stealth_status_index>() );
   BOOST_CHECK_NO_THROW( db.get_index_type<stealth_nullifier_index>() );
   BOOST_CHECK_NO_THROW( db.get_index_type<blinded_balance_index>() );
   // (b) the consensus kind gate fires without any fork or committee: the
   // record helper rejects unknown kinds even pre-STEALTH (validate() is a
   // relay-side check, not the consensus boundary for proposal-embedded
   // ops — see parity_review_evaluator::do_apply). The kind gate fires
   // before any voter/quorum logic, so the voter here is arbitrary.
   BOOST_CHECK_THROW( stealth_record_parity_review( db, 7, account_id_type() ), fc::exception );
   try
   {
      stealth_record_parity_review( db, 7, account_id_type() );
      BOOST_FAIL( "unknown review kind must fail closed" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Unknown parity review kind" )
                           != std::string::npos, e.to_detail_string() );
   }
    // (c) pre-hardfork replay refuses op 107 (like its siblings in
   // stealth_ops_are_refused_before_the_hardfork): a well-formed review
   // never reaches the committee gate before activation.
   {
      parity_review_operation r;
      r.voter = dan.id;
      r.kind = GRAPHENE_STEALTH_REVIEW_PARITY;
      r.note = "genesis replay must refuse";
      BOOST_CHECK_NO_THROW( r.validate() );
      signed_transaction tx;
      tx.operations.push_back( r );
      set_expiration( db, tx );
      sign( tx, dan_private_key );
      BOOST_CHECK_THROW( PUSH_TX( db, tx ), fc::exception );
   }
    // (e) G4-06 direct evaluator-registration asserts: dispatch each new op
    // 104-107 straight to database::apply_operation, bypassing PUSH_TX fee /
   // authority layers AND relay-side validate(). Pre-fork every one must
   // reach its evaluator's hardfork gate — "No registered evaluator" would
   // prove a db_init wiring miss; the hardfork refusal proves the evaluator
   // exists and gates. (The inferred PUSH_TX pins in (d) cannot prove this:
   // a missing evaluator and a hardfork refusal both throw at push.)
   // (C++14: tag<X>::value is constexpr-static; bind it to a local first —
   // passing it straight into BOOST_CHECK_EQUAL odr-uses it via const-ref
   // and fails to link. Copy-init is a constant-expression use, no odr-use.)
    const int tag104 = operation::tag<stealth_transfer_operation>::value;
    const int tag105 = operation::tag<freeze_blind_operation>::value;
    const int tag106 = operation::tag<turnstile_reproof_operation>::value;
    const int tag107 = operation::tag<parity_review_operation>::value;
    BOOST_CHECK_EQUAL( tag104, 104 );
    BOOST_CHECK_EQUAL( tag105, 105 );
    BOOST_CHECK_EQUAL( tag106, 106 );
    BOOST_CHECK_EQUAL( tag107, 107 );
   {
      auto expect_hardfork_refusal = [&]( const operation& op, const char* what )
      {
         transaction_evaluation_state es( &db );
         try
         {
            db.apply_operation( es, op );
            BOOST_FAIL( what << ": unregistered evaluator or missing hardfork gate" );
         }
         catch( const fc::exception& e )
         {
            std::string w = e.to_detail_string();
            BOOST_CHECK_MESSAGE( w.find( "No registered evaluator" ) == std::string::npos, w );
            BOOST_CHECK_MESSAGE( w.find( "hardfork" ) != std::string::npos, w );
         }
      };
       stealth_transfer_operation t104;
       expect_hardfork_refusal( operation( t104 ), "op 104 stealth_transfer" );
       freeze_blind_operation f105;
       f105.voter = dan.id;
       expect_hardfork_refusal( operation( f105 ), "op 105 freeze_blind" );
       turnstile_reproof_operation t106;
       expect_hardfork_refusal( operation( t106 ), "op 106 turnstile_reproof" );
       parity_review_operation r107;
       r107.voter = dan.id; r107.kind = GRAPHENE_STEALTH_REVIEW_PARITY;
       expect_hardfork_refusal( operation( r107 ), "op 107 parity_review" );
   }
   // (f) G4-06 old-DB lazy path: an old database replaying without the
   // genesis-created singleton (db_genesis.cpp:596) must read as
   // pre-activation defaults and lazily create on the first post-STEALTH
   // maintenance — never assert on a missing index entry.
   {
      const auto& idx = db.get_index_type<stealth_status_index>().indices();
      BOOST_REQUIRE_EQUAL( idx.size(), 1u ); // genesis created it
      db.remove( *idx.begin() ); // simulate an old DB: singleton absent
      BOOST_CHECK( db.get_index_type<stealth_status_index>().indices().empty() );
      // Read paths treat a missing singleton as pre-activation defaults.
      BOOST_CHECK( !stealth_blind_halted( db ) );
      BOOST_CHECK_EQUAL( stealth_tripwire_fire_block( db ), 0u );
      BOOST_CHECK_EQUAL( stealth_blind_count_this_block( db ), 0u );
      BOOST_CHECK_EQUAL( stealth_pool_depth( db, asset_id_type() ), 0u );
      BOOST_CHECK( stealth_current_alarms( db ).effective_set.empty() );
      BOOST_CHECK( stealth_v1_sunset_time( db ) == fc::time_point_sec() );
      // Pre-fork maintenance is a no-op: it must NOT create the singleton
      // (creation happens only on post-STEALTH maintenance/apply paths).
      stealth_parity_maintenance( db );
      stealth_maybe_record_activation( db );
      BOOST_CHECK( db.get_index_type<stealth_status_index>().indices().empty() );
   }
    // (d) post-fork every evaluator is wired: each op reaches its own gate
    // (committee-membership for 105/107, cost path for a fee-less 106) instead
    // of "no evaluator". Op 104 is covered by stealth_transfer_happy_path
   // (success) + the pre-fork refusal above.
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   // (f2) the first post-STEALTH maintenance path lazily creates the
   // singleton the old DB was missing, with activation recorded
   // deterministically at the scheduled hardfork time (idempotent: a
   // maintenance during the jump may have created it already).
   stealth_maybe_record_activation( db );
   {
      const auto& idx = db.get_index_type<stealth_status_index>().indices();
      BOOST_REQUIRE_EQUAL( idx.size(), 1u ); // lazily created, not genesis
      BOOST_CHECK( idx.begin()->stealth_activated_time == HARDFORK_STEALTH_TIME );
      BOOST_CHECK( idx.begin()->v1_sunset_time != fc::time_point_sec() );
   }
   stealth_parity_maintenance( db ); // idempotent on the fresh singleton
   BOOST_CHECK_EQUAL( db.get_index_type<stealth_status_index>().indices().size(), 1u );
   {
      freeze_blind_operation fz;
      fz.voter = dan_id; fz.freeze = true; fz.reason = "evaluator pin";
      signed_transaction tx; tx.operations.push_back( fz );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      sign( tx, dan_private_key );
      try { PUSH_TX( db, tx ); BOOST_FAIL( "non-member freeze must reject" ); }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "committee member" )
                              != std::string::npos, e.to_detail_string() );
      }
      trx.clear();
   }
   {
      // Fee-less with a shaped (but unresolvable) leg: validate passes, the
       // evaluator's cost path rejects — proving op 106 is wired, not absent.
      // Owner-signed (dan) so the authority gate passes first.
      turnstile_reproof_operation tp;
      tp.new_output.range_proof = std::vector<char>( 64, 0 );
      tp.new_output.owner = authority( 1, dan_id, 1 );
      tp.owner = authority( 1, dan_id, 1 );
      signed_transaction tx; tx.operations.push_back( tp );
      set_expiration( db, tx );
      BOOST_CHECK_NO_THROW( tp.validate() );
      sign( tx, dan_private_key );
      try { PUSH_TX( db, tx ); BOOST_FAIL( "fee-less turnstile must reject" ); }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "cost" ) != std::string::npos,
                              e.to_detail_string() );
      }
      trx.clear();
   }
   {
      parity_review_operation r;
      r.voter = dan_id; r.kind = GRAPHENE_STEALTH_REVIEW_PARITY;
      signed_transaction tx; tx.operations.push_back( r );
      db.current_fee_schedule().set_fee( tx.operations.back() );
      set_expiration( db, tx );
      sign( tx, dan_private_key );
      try { PUSH_TX( db, tx ); BOOST_FAIL( "non-member review must reject" ); }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "committee member" )
                              != std::string::npos, e.to_detail_string() );
      }
      trx.clear();
   }
   // (g) G4-06 fee-less genesis fallback: with the fee-schedule check
   // skipped (genesis/test/generator context — no fee paid, no subsidy
   // consumed) the float rule is a no-op: zero paid against a real anchor
   // gap neither throws nor debits the pool.
   {
      const asset_object& core = asset_id_type()(db);
      const asset_id_type core_id = core.get_id();
      share_type gap = stealth_parity_gap_core( db, 1, share_type( 0 ), 1 );
      BOOST_REQUIRE( gap.value > 0 ); // real gap: anchor above zero-fee parity
      BOOST_CHECK_NO_THROW( stealth_require_blind_fee( db, share_type( 0 ), false,
                                                       core_id, 1, share_type( 0 ), 1 ) );
      const auto& st0 = *db.get_index_type<stealth_status_index>().indices().begin();
      auto pit = st0.parity_pool.find( core_id );
      share_type before = ( pit == st0.parity_pool.end() ) ? share_type( 0 ) : pit->second;
      BOOST_CHECK_NO_THROW( stealth_consume_parity_subsidy( db, false, core_id, 1,
                                                            share_type( 0 ), share_type( 0 ), 1 ) );
      const auto& st1 = *db.get_index_type<stealth_status_index>().indices().begin();
      auto pit2 = st1.parity_pool.find( core_id );
      share_type after = ( pit2 == st1.parity_pool.end() ) ? share_type( 0 ) : pit2->second;
      BOOST_CHECK_EQUAL( after.value, before.value ); // no grant consumed
   }
   verify_asset_supplies( db );
   generate_block();
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( blind_wallet_defaults )
{ try {
   // G3-05 wallet unit coverage (offline: null remote api — the impl ctor
   // skips every remote call in that mode; no consensus effect anywhere).
   // (a) struct defaults match BLIND_DEFAULTS_CONTRACT.md exactly.
   graphene::wallet::blind_transfer_defaults d;
   BOOST_CHECK_EQUAL( d.blind_by_default, true );
   BOOST_CHECK_EQUAL( d.decoy_fetch_batch_size, 32u );
   BOOST_CHECK_EQUAL( d.min_broadcast_delay_sec, 3u );
   BOOST_CHECK_EQUAL( d.min_mix_blocks, 0u ); // reserved, unenforced (G3-05)
   // (b) batch-chunk math: one RPC trip per chunk, never per decoy.
   BOOST_CHECK_EQUAL( graphene::wallet::blind_batch_chunk_count( 0, 32 ), 0u );
   BOOST_CHECK_EQUAL( graphene::wallet::blind_batch_chunk_count( 1, 32 ), 1u );
   BOOST_CHECK_EQUAL( graphene::wallet::blind_batch_chunk_count( 32, 32 ), 1u );
   BOOST_CHECK_EQUAL( graphene::wallet::blind_batch_chunk_count( 33, 32 ), 2u );
   BOOST_CHECK_EQUAL( graphene::wallet::blind_batch_chunk_count( 64, 32 ), 2u );
   BOOST_CHECK_EQUAL( graphene::wallet::blind_batch_chunk_count( 65, 32 ), 3u );
   BOOST_CHECK_EQUAL( graphene::wallet::blind_batch_chunk_count( 5, 0 ), 5u ); // 0→1 guard
   // (c) offline wallet serves local state: fresh defaults + validation.
   graphene::wallet::wallet_data wdata;
   graphene::wallet::wallet_api w( wdata, fc::api<graphene::app::login_api>() );
   auto got = w.get_blind_defaults();
   BOOST_CHECK_EQUAL( got.blind_by_default, true );
   BOOST_CHECK_EQUAL( got.decoy_fetch_batch_size, 32u );
   BOOST_CHECK_EQUAL( got.min_broadcast_delay_sec, 3u );
   auto bad = got; bad.decoy_fetch_batch_size = 0;
   BOOST_CHECK_THROW( w.set_blind_defaults( bad ), fc::exception );
   w.set_blind_by_default( false );
   BOOST_CHECK_EQUAL( w.get_blind_defaults().blind_by_default, false );
   w.set_blind_by_default( true );
   // (d) injected sleep: hook observes seconds, no real wait. Default 3s
   // fires once; 0 disables (hook silent).
   uint32_t slept = 0;
   int calls = 0;
   w.set_blind_sleep_hook( [&]( uint32_t s ) { ++calls; slept = s; } );
   w.blind_broadcast_delay();
   BOOST_CHECK_EQUAL( calls, 1 );
   BOOST_CHECK_EQUAL( slept, 3u );
   auto off = w.get_blind_defaults(); off.min_broadcast_delay_sec = 0;
   w.set_blind_defaults( off );
   w.blind_broadcast_delay();
   BOOST_CHECK_EQUAL( calls, 1 );
   auto on = w.get_blind_defaults(); on.min_broadcast_delay_sec = 3;
   w.set_blind_defaults( on );
   // (e) fail-closed addressing (test hook unlock: no keys or files are
   // touched on these paths — both legs throw before any of that).
   w.set_unlocked_for_tests();
   // Non-empty memo with blind default → throws before any routing.
   BOOST_CHECK_THROW(
      w.transfer_default( "alice", "somekey", "1.00000", "CORE", "hello", false, false ),
      fc::exception );
   // Unresolvable blind recipient → throws (never silently transparent).
   // The public-account branch needs a node (get_account_id is remote-only);
   // offline it resolves as non-account and still fails closed here.
   BOOST_CHECK_THROW(
      w.transfer_default( "alice", "nolabel-no-such-key", "1.00000", "CORE", "", false, false ),
      fc::exception );
   // (f) Task 6 delay choke point: maybe_delay_blind_broadcast(true) fires
   // the sleep hook exactly once (the path every blind-sending leg calls);
   // (false) (build/sign-only) never sleeps.
   {
      uint32_t slept = 0;
      int calls = 0;
      w.set_blind_sleep_hook( [&]( uint32_t s ) { ++calls; slept = s; } );
      w.maybe_delay_blind_broadcast( true );
      BOOST_CHECK_EQUAL( calls, 1 );
      BOOST_CHECK_EQUAL( slept, 3u );
      w.maybe_delay_blind_broadcast( false );
      BOOST_CHECK_EQUAL( calls, 1 ); // no additional sleep
      auto off = w.get_blind_defaults(); off.min_broadcast_delay_sec = 0;
      w.set_blind_defaults( off );
      w.maybe_delay_blind_broadcast( true );
      BOOST_CHECK_EQUAL( calls, 1 ); // explicit 0 disables
      auto on = w.get_blind_defaults(); on.min_broadcast_delay_sec = 3;
      w.set_blind_defaults( on );
      w.set_blind_sleep_hook( nullptr );
   }
   // (g) Task 6 mix-hold rule (pure helper, no node): off by default;
   // unknown age (0) ineligible under any hold; boundary inclusive;
   // future receipts ineligible.
   {
      using graphene::wallet::blind_receipt_mix_eligible;
      BOOST_CHECK( blind_receipt_mix_eligible( 0, 0, 0 ) );
      BOOST_CHECK( blind_receipt_mix_eligible( 123, 456, 0 ) ); // off: always
      BOOST_CHECK( !blind_receipt_mix_eligible( 0, 1000, 5 ) ); // unknown age
      BOOST_CHECK( blind_receipt_mix_eligible( 995, 1000, 5 ) ); // exactly held
      BOOST_CHECK( !blind_receipt_mix_eligible( 996, 1000, 5 ) ); // one short
      BOOST_CHECK( !blind_receipt_mix_eligible( 1000, 1000, 1 ) ); // newborn
      BOOST_CHECK( blind_receipt_mix_eligible( 1000, 1000, 0 ) ); // off anyway
      BOOST_CHECK( !blind_receipt_mix_eligible( 1001, 1000, 5 ) ); // future
      BOOST_CHECK( blind_receipt_mix_eligible( 500, 1000, 500 ) ); // boundary
   }
   // (h) Task 6 blind_by_default end-to-end routing (offline, no node): the
   // SAME call with and without the transparent opt-out must take visibly
   // different branches — the blind branch fails at the blind memo guard
   // (proving blind routing was selected), the transparent branch gets past
   // it (and fails later at the remote-only transfer leg).
   {
      std::string blind_err, transparent_err;
      try { w.transfer_default( "alice", "somekey", "1.00000", "CORE", "hello", false, false ); }
      catch( const fc::exception& e ) { blind_err = e.to_detail_string(); }
      try { w.transfer_default( "alice", "somekey", "1.00000", "CORE", "hello", true, false ); }
      catch( const fc::exception& e ) { transparent_err = e.to_detail_string(); }
      BOOST_REQUIRE( !blind_err.empty() );
      BOOST_REQUIRE( !transparent_err.empty() );
      BOOST_CHECK_MESSAGE( blind_err.find( "blind legs carry no memo" ) != std::string::npos,
                           blind_err );
      BOOST_CHECK_MESSAGE( transparent_err.find( "blind legs carry no memo" ) == std::string::npos,
                           transparent_err );
   }
   // (i) Task 6 receipt schema compat: old wallet files (no received_block
   // key) load with unknown age 0; new receipts serialize the field.
   {
      graphene::wallet::blind_receipt r;
      fc::variant v;
      fc::to_variant( r, v, 20 );
      BOOST_CHECK_EQUAL( v.get_object()[ "received_block" ].as_uint64(), 0u );
      fc::variant empty_obj = fc::variant( fc::variant_object() );
      graphene::wallet::blind_receipt back;
      fc::from_variant( empty_obj, back, 20 );
      BOOST_CHECK_EQUAL( back.received_block, 0u );
   }
   // (j) Successful blind_by_default ROUTING selection (offline, no node):
   // with an empty memo and a registered blind-key label, the blind branch
   // is selected and proceeds PAST both fail-closed guards (memo + public
   // account + unknown recipient) into the blind leg itself — failing only
   // at the remote-only transfer_to_blind step. Neither guard fires and no
   // silent transparent fallback happens (GP-07/08, GC-11, V-04/05).
   {
      const auto bk = fc::ecc::private_key::generate();
      BOOST_REQUIRE( w.set_key_label(
            public_key_type( bk.get_public_key() ), "blindbob" ) );
      std::string err;
      try { w.transfer_default( "alice", "blindbob", "1.00000", "CORE", "", false, false ); }
      catch( const fc::exception& e ) { err = e.to_detail_string(); }
      BOOST_REQUIRE_MESSAGE( !err.empty(),
            "blind-routed transfer must reach the blind leg" );
      BOOST_CHECK_MESSAGE( err.find( "blind legs carry no memo" ) == std::string::npos, err );
      BOOST_CHECK_MESSAGE( err.find( "is a public account" ) == std::string::npos, err );
      BOOST_CHECK_MESSAGE( err.find( "unknown blind recipient" ) == std::string::npos, err );
   }
} FC_CAPTURE_AND_RETHROW() }

// ===========================================================================
// R15 (F-08 representation-proof recovery): RED tests (TDD).
//
// Defect (spec 2026-10-08-f08-representation-proof-recovery-design.md §1,
// RETIRED by the Task 3 nullifier migration): a ring spend spent-flagged
// EVERY ring member, so a stranger could brick any stealth output for one
// fee by including it as a decoy; the turnstile
// (stealth_evaluator.cpp:885) then refused it forever. Recovery: the turnstile
// takes an optional extension carrying the output's two key images (V1/V2
// domains) plus a Sigma representation proof binding both images to the old
// commitment's opening (b, v):
//   C  = b*G  + v*H
//   I1 = b*J1_1 + v*J2_1
//   I2 = b*J1_2 + v*J2_2
// Fiat-Shamir challenge over domain "BTS-STEALTH-RECOVERY-v1" (spec §3.2).
//
// RED STATUS: the extension types do not exist yet (Task 2 creates them), so
// this file MUST FAIL TO COMPILE with `turnstile_recovery_v2_extension was not
// declared in this scope`. That compile failure IS the RED — do not fix it
// here (Task 2 owns the types; Task 1 owns only this file).
//
// CONTRACT Task 2 must satisfy (do not reshape these tests to fit an impl):
// - protocol struct turnstile_recovery_v2_extension, aggregate with fields in
//   this order: key_image_v1 (commitment), key_image_v2 (commitment),
//   recovery_proof (163 bytes: A_C(33) || A_1(33) || A_2(33) || s_b(32 BE)
//   || s_v(32 BE)), wired into the turnstile op's extension set (r14 pattern:
//   variant + extensions-type + FC_REFLECT + hardfork visitor).
// - challenge: c = scalar( sha256( "BTS-STEALTH-RECOVERY-v1" || C || I1 || I2
//   || A_C || A_1 || A_2 || asset_id_le64 || C ) ), scalar mod n.
// - verify: s_b*G+s_v*H == A_C+c*C, s_b*J1_1+s_v*J2_1 == A_1+c*I1,
//   s_b*J1_2+s_v*J2_2 == A_2+c*I2; strict parsing throughout.
// - gate: owner+authority, then proof verify, then nullifier check on the
//   BOUND images (either present -> refuse, message names "nullifier").
//   Absent extension: the retired-flag branch (interim hole until Task 4
//   requires the extension on every path).
// ===========================================================================

/// Test-only representation prover (wallets own proving; consensus never
/// proves). Mirrors T_prove_ring structure. Random nonces via BN_rand_range
/// are test-only and fine here (no consensus path touches this function).
/// The domain parameter exists so Task 5 can pin domain separation: only the
/// exact consensus domain verifies; any other tag must refuse.
static void T_prove_recovery_with_domain( const std::vector<unsigned char>& C_bytes,
                              const BIGNUM* b, uint64_t v,
                              asset_id_type asset,
                              const std::string& domain,
                              fc::ecc::commitment_type& I1_out,
                              fc::ecc::commitment_type& I2_out,
                              std::vector<char>& proof_out )
{
   BOOST_REQUIRE( C_bytes.size() == 33 );
   EC_POINT* J1_1 = T_open( stealth_J1_point( GRAPHENE_STEALTH_PROOF_V1 ) );
   EC_POINT* J2_1 = T_open( stealth_J2_point( GRAPHENE_STEALTH_PROOF_V1 ) );
   EC_POINT* J1_2 = T_open( stealth_J1_point( GRAPHENE_STEALTH_PROOF_V2 ) );
   EC_POINT* J2_2 = T_open( stealth_J2_point( GRAPHENE_STEALTH_PROOF_V2 ) );
   EC_POINT* Hp = T_open( stealth_H_point() );
   BIGNUM* vv = BN_new(); BN_set_word( vv, (BN_ULONG)v );

   // I1 = b*J1_1 + v*J2_1, I2 = b*J1_2 + v*J2_2.
   EC_POINT* I1 = EC_POINT_new( T_group() );
   EC_POINT* I2 = EC_POINT_new( T_group() );
   EC_POINT* Tp = EC_POINT_new( T_group() );
   EC_POINT_mul( (EC_GROUP*)T_group(), I1, nullptr, J1_1, b, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), Tp, nullptr, J2_1, vv, T_ctx() );
   EC_POINT_add( (EC_GROUP*)T_group(), I1, I1, Tp, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), I2, nullptr, J1_2, b, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), Tp, nullptr, J2_2, vv, T_ctx() );
   EC_POINT_add( (EC_GROUP*)T_group(), I2, I2, Tp, T_ctx() );
   std::vector<unsigned char> I1c = T_compress( I1 ), I2c = T_compress( I2 );
   I1_out = T_commitment( I1c ); I2_out = T_commitment( I2c );

   // Random r_b, r_v in [1, n-1].
   BIGNUM* rb = BN_new(); BIGNUM* rv = BN_new();
   do { BOOST_REQUIRE( BN_rand_range( rb, T_order() ) == 1 ); } while( BN_is_zero( rb ) );
   do { BOOST_REQUIRE( BN_rand_range( rv, T_order() ) == 1 ); } while( BN_is_zero( rv ) );

   // A_C = r_b*G + r_v*H, A_1 = r_b*J1_1 + r_v*J2_1, A_2 = r_b*J1_2 + r_v*J2_2.
   EC_POINT* AC = EC_POINT_new( T_group() );
   EC_POINT* A1 = EC_POINT_new( T_group() );
   EC_POINT* A2 = EC_POINT_new( T_group() );
   EC_POINT_mul( (EC_GROUP*)T_group(), AC, rb, nullptr, nullptr, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), Tp, nullptr, Hp, rv, T_ctx() );
   EC_POINT_add( (EC_GROUP*)T_group(), AC, AC, Tp, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), A1, nullptr, J1_1, rb, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), Tp, nullptr, J2_1, rv, T_ctx() );
   EC_POINT_add( (EC_GROUP*)T_group(), A1, A1, Tp, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), A2, nullptr, J1_2, rb, T_ctx() );
   EC_POINT_mul( (EC_GROUP*)T_group(), Tp, nullptr, J2_2, rv, T_ctx() );
   EC_POINT_add( (EC_GROUP*)T_group(), A2, A2, Tp, T_ctx() );
   std::vector<unsigned char> ACc = T_compress( AC ),
                              A1c = T_compress( A1 ),
                              A2c = T_compress( A2 );

    // c = scalar( sha256( domain || C || I1 || I2 || A_C || A_1 || A_2
    //                      || asset_id_le64 || C ) ).
    std::string pre = domain;
   pre.append( (const char*)C_bytes.data(), 33 );
   pre.append( (const char*)I1c.data(), 33 );
   pre.append( (const char*)I2c.data(), 33 );
   pre.append( (const char*)ACc.data(), 33 );
   pre.append( (const char*)A1c.data(), 33 );
   pre.append( (const char*)A2c.data(), 33 );
   const uint64_t aid = (uint64_t)asset.instance.value;
   for( int i = 0; i < 8; ++i ) pre.push_back( (char)( aid >> (8*i) ) );
   pre.append( (const char*)C_bytes.data(), 33 );
   fc::sha256 h = fc::sha256::hash( pre.c_str(), (uint32_t)pre.size() );
   BIGNUM* c = BN_new();
   BN_bin2bn( (const unsigned char*)h.data(), 32, c );
   BN_mod( c, c, T_order(), T_ctx() );

   // s_b = r_b + c*b mod n, s_v = r_v + c*v mod n.
   BIGNUM* sb = BN_new(); BIGNUM* sv = BN_new(); BIGNUM* t = BN_new();
   BN_mod_mul( t, c, b, T_order(), T_ctx() );
   BN_mod_add( sb, rb, t, T_order(), T_ctx() );
   BN_mod_mul( t, c, vv, T_order(), T_ctx() );
   BN_mod_add( sv, rv, t, T_order(), T_ctx() );

   // proof = A_C(33) || A_1(33) || A_2(33) || s_b(32) || s_v(32) = 163 bytes.
   proof_out.clear();
   proof_out.insert( proof_out.end(), (const char*)ACc.data(), (const char*)ACc.data() + 33 );
   proof_out.insert( proof_out.end(), (const char*)A1c.data(), (const char*)A1c.data() + 33 );
   proof_out.insert( proof_out.end(), (const char*)A2c.data(), (const char*)A2c.data() + 33 );
   unsigned char buf[32];
   BN_bn2binpad( sb, buf, 32 );
   proof_out.insert( proof_out.end(), (char*)buf, (char*)buf + 32 );
   BN_bn2binpad( sv, buf, 32 );
   proof_out.insert( proof_out.end(), (char*)buf, (char*)buf + 32 );
   BOOST_REQUIRE( proof_out.size() == 163 );

   EC_POINT_free( J1_1 ); EC_POINT_free( J2_1 );
   EC_POINT_free( J1_2 ); EC_POINT_free( J2_2 );
   EC_POINT_free( Hp ); EC_POINT_free( I1 ); EC_POINT_free( I2 );
   EC_POINT_free( Tp ); EC_POINT_free( AC ); EC_POINT_free( A1 ); EC_POINT_free( A2 );
   BN_free( vv ); BN_free( rb ); BN_free( rv );
   BN_free( c ); BN_free( sb ); BN_free( sv ); BN_free( t );
}

/// Consensus-domain wrapper: every honest proof uses this tag.
static void T_prove_recovery( const std::vector<unsigned char>& C_bytes,
                              const BIGNUM* b, uint64_t v,
                              asset_id_type asset,
                              fc::ecc::commitment_type& I1_out,
                              fc::ecc::commitment_type& I2_out,
                              std::vector<char>& proof_out )
{
   T_prove_recovery_with_domain( C_bytes, b, v, asset,
      "BTS-STEALTH-RECOVERY-v1", I1_out, I2_out, proof_out );
}

/// Attach the (not-yet-existing) R15 recovery extension. Aggregate field
/// order { I1, I2, proof } is the wire contract Task 2 must implement.
static void T_set_recovery_v2( turnstile_reproof_operation& t,
                               const fc::ecc::commitment_type& I1,
                               const fc::ecc::commitment_type& I2,
                               const std::vector<char>& proof )
{
   t.extensions.insert( turnstile_recovery_v2_extension{ I1, I2, proof } );
}

/// Turnstile for pool output #s with an explicit (new_value, fee) split:
/// 1000 -> new_value new blind output + fee. The default (990, 10) is the
/// standard split; Task 5 uses a non-default fee to prove the supply delta
/// tracks the op fee exactly rather than a hardcoded constant.
static turnstile_reproof_operation T_r15_turnstile_value( const asset_object& core,
                                                    const t5_pool& p, size_t s,
                                                    const std::string& tag,
                                                    int64_t new_value, int64_t fee )
{
   BOOST_REQUIRE( p.each == 1000 );
   BOOST_REQUIRE( new_value + fee == p.each );
   turnstile_reproof_operation t;
   t.asset_id = core.get_id();
   t.old_commitment = p.commits[s];
   t.owner = p.owners[s];
   t.new_proof_version = GRAPHENE_STEALTH_PROOF_V2;
   stealth_blind_output no;
   auto Bn = T_blind_secret( tag );
   {
      BIGNUM* bnn = T_bn( Bn );
      no.commitment = T_commitment( T_commit( bnn, (uint64_t)new_value ) );
      BN_free( bnn );
   }
   no.range_proof = T_bp_prove( no.commitment, Bn, (uint64_t)new_value );
   no.owner = p.owners[s];
   t.new_output = no;
   t.fee = core.amount( fee );
   t.old_blind = p.blinds[s];
   t.new_blind = Bn;
   return t;
}

/// Turnstile for pool output #s: 1000 -> 990 new blind output + 10 fee.
static turnstile_reproof_operation T_r15_turnstile( const asset_object& core,
                                                    const t5_pool& p, size_t s,
                                                    const std::string& tag )
{
   return T_r15_turnstile_value( core, p, s, tag, 990, 10 );
}

/// Prove the true opening of pool output #s over its own commitment bytes.
static void T_r15_prove_true( const t5_pool& p, size_t s, asset_id_type asset,
                              fc::ecc::commitment_type& I1,
                              fc::ecc::commitment_type& I2,
                              std::vector<char>& proof )
{
   BIGNUM* bb = T_bn( p.blinds[s] );
   std::vector<unsigned char> Cvec( p.commits[s].begin(), p.commits[s].end() );
   T_prove_recovery( Cvec, bb, (uint64_t)p.each, asset, I1, I2, proof );
   BN_free( bb );
}

// Task 3 (flag retirement): a really-spent output (nullifiers present) with
// a VALID proof still refuses — fail-closed on either image. Formerly
// r15_recovery_decoyed_succeeds: the old helper only set the retired flag
// (no nullifier), so recovery succeeded; inserting the TRUE nullifiers is
// the exact production guard, and the proof passes while the nullifier
// lookup refuses.
BOOST_AUTO_TEST_CASE( r15_recovery_nullified_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-a", 16, true );
   const size_t s = 3;
   const int64_t live = t5_supply( db, core );

   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_r15_nullify( db, I1, I2 );

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-a-bn" );
   T_set_recovery_v2( t, I1, I2, proof );

   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "a nullified output must NOT be recoverable, even with a valid proof" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "nullifier" ) != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live ); // refused recovery moved nothing
} FC_CAPTURE_AND_RETHROW() }

// Spec §7.2 (the F08B-04 missing test): a really-spent output (nullifier
// present) with a VALID proof still refuses. Fail-closed on either image.
BOOST_AUTO_TEST_CASE( r15_recovery_really_spent_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-b", 16, true );
   const size_t s = 4;

   stealth_transfer_operation stop = t5_build_spend( core, p, s,
      GRAPHENE_STEALTH_PROOF_V2, "r15-b-sp", 600, 390, 10 );
   trx.operations = { stop };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   const int64_t live = t5_supply( db, core );

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-b-bn" );
   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_set_recovery_v2( t, I1, I2, proof );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "a really-spent output must NOT be recoverable, even with a valid proof" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "nullifier" ) != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live ); // refused recovery moved nothing
} FC_CAPTURE_AND_RETHROW() }

// Spec §7.3: proof over a foreign/wrong (b,v) fails against the real C.
BOOST_AUTO_TEST_CASE( r15_recovery_wrong_opening_fails )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-c", 16, true );
   const size_t s = 5;

   // Nullify the TRUE images (the foreign proof below still refuses at the
   // proof layer, before any nullifier is read).
   {
      fc::ecc::commitment_type tI1, tI2; std::vector<char> tproof;
      T_r15_prove_true( p, s, core.get_id(), tI1, tI2, tproof );
      T_r15_nullify( db, tI1, tI2 );
   }

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-c-bn" );
   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   {
      // Foreign opening, same value: proves nothing about C.
      BIGNUM* bf = T_bn( T_blind_secret( "r15-c-foreign-blind" ) );
      std::vector<unsigned char> Cvec( p.commits[s].begin(), p.commits[s].end() );
      T_prove_recovery( Cvec, bf, (uint64_t)p.each, core.get_id(), I1, I2, proof );
      BN_free( bf );
   }
   T_set_recovery_v2( t, I1, I2, proof );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   // B3: pin the refusal LAYER — the proof layer, by message (a bare
   // BOOST_CHECK_THROW would pass on any-layer refusal: fee, owner, gate...).
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "wrong-opening recovery must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find(
         "Turnstile recovery proof does not verify" ) != std::string::npos,
         e.to_detail_string() );
      BOOST_CHECK_MESSAGE( e.to_detail_string().find(
         "recovery equation C mismatch" ) != std::string::npos,
         e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
} FC_CAPTURE_AND_RETHROW() }

// Spec §7.4: I1/I2 exchanged (or replaced) fails — images are positional.
BOOST_AUTO_TEST_CASE( r15_recovery_swapped_images_fail )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-d", 16, true );
   const size_t s = 6;

   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_r15_nullify( db, I1, I2 );
   BOOST_REQUIRE( p.commits.size() > 9 );

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-d-bn" );
   BOOST_REQUIRE( I1 != I2 ); // versions MUST produce different bytes
   T_set_recovery_v2( t, I2, I1, proof ); // swapped
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   // B3: pin the refusal layer by message (proof layer, C-leg mismatch —
   // the swap changes the recomputed challenge).
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "swapped-images recovery must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find(
         "Turnstile recovery proof does not verify" ) != std::string::npos,
         e.to_detail_string() );
      BOOST_CHECK_MESSAGE( e.to_detail_string().find(
         "recovery equation C mismatch" ) != std::string::npos,
         e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
} FC_CAPTURE_AND_RETHROW() }

// Spec §7.5: a proof for commitment A replayed against commitment B fails
// (challenge binds C, so the statement does not transfer).
BOOST_AUTO_TEST_CASE( r15_recovery_replay_fails )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-e", 16, true );
   const size_t sa = 3, sb = 5;

   // Nullify sb's TRUE images (the replayed proof below still refuses at
   // the proof layer — the challenge binds the statement commitment).
   {
      fc::ecc::commitment_type tI1, tI2; std::vector<char> tproof;
      T_r15_prove_true( p, sb, core.get_id(), tI1, tI2, tproof );
      T_r15_nullify( db, tI1, tI2 );
   }

   // Prove over A's opening, submit against B's (decoyed) commitment.
   turnstile_reproof_operation t = T_r15_turnstile( core, p, sb, "r15-e-bn" );
   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, sa, core.get_id(), I1, I2, proof );
   T_set_recovery_v2( t, I1, I2, proof );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[sb] );
   // B3: pin the refusal layer by message (proof layer: the challenge binds
   // the statement commitment, so the replayed transcript mismatches).
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "replayed recovery proof must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find(
         "Turnstile recovery proof does not verify" ) != std::string::npos,
         e.to_detail_string() );
      BOOST_CHECK_MESSAGE( e.to_detail_string().find(
         "recovery equation C mismatch" ) != std::string::npos,
         e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
} FC_CAPTURE_AND_RETHROW() }

// Task 4 (turnstile always proves): the no-extension branch's only guard was
// the retired whole-ring spent flag (Task 3 stopped writing it), so a
// really-spent output could re-migrate with no proof. The R15 extension is
// now mandatory on every path; op106 is new on this branch
// (operations.hpp:170), so requiring the extension is replay-safe. Both a
// nullified and a live output refuse without the extension, moving nothing.
BOOST_AUTO_TEST_CASE( op106_turnstile_without_extension_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-f", 16, true );
   const int64_t live = t5_supply( db, core );

   // (a) nullified + no extension: the hole Task 4 closes — a really-spent
   // output re-migrated with no proof while the retired flag stood unwritten.
   {
      const size_t s = 7;
      fc::ecc::commitment_type I1, I2; std::vector<char> proof;
      T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
      T_r15_nullify( db, I1, I2 );
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-f-bn-a" );
      BOOST_REQUIRE( t.extensions.empty() );
      set_expiration( db, trx );
      trx.operations = { t };
      sign( trx, p.keys[s] );
      try {
         PUSH_TX( db, trx );
         BOOST_FAIL( "nullified plain turnstile must be refused" );
      } catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "Turnstile recovery takes one extension" ) != std::string::npos,
            e.to_detail_string() );
      }
      trx.clear_signatures(); trx.operations.clear();
   }
   // (b) live + no extension: still refused — every migration proves.
   {
      const size_t s = 2;
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-f-bn-b" );
      BOOST_REQUIRE( t.extensions.empty() );
      set_expiration( db, trx );
      trx.operations = { t };
      sign( trx, p.keys[s] );
      try {
         PUSH_TX( db, trx );
         BOOST_FAIL( "live plain turnstile must be refused" );
      } catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "Turnstile recovery takes one extension" ) != std::string::npos,
            e.to_detail_string() );
      }
      trx.clear_signatures(); trx.operations.clear();
   }
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live ); // refusals moved nothing
} FC_CAPTURE_AND_RETHROW() }

// Task 4 (turnstile always proves): the recovery kernel is charged on every
// path, and the do_evaluate gate and do_apply accounting share one definition
// (stealth_work_for_turnstile), so the two charge expressions are identical by
// construction and cannot drift. This pins the shared value arithmetically
// AND end-to-end: a real extension-carrying migration must accumulate exactly
// that many work units into the pending block's counter.
BOOST_AUTO_TEST_CASE( op106_turnstile_work_gate_matches_apply_accounting )
{ try {
   BOOST_REQUIRE_EQUAL( stealth_work_for_turnstile(),
      stealth_work_for_range_proofs( 1 )
      + 2u * GRAPHENE_STEALTH_WORK_US_PER_KERNEL );
   BOOST_REQUIRE_EQUAL( stealth_work_for_turnstile(), 10418u ); // 6322 + 2x2048

   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-wg", 16, true );
   const size_t s = 1;

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-wg-bn" );
   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_set_recovery_v2( t, I1, I2, proof );

   const uint32_t before = stealth_blind_work_this_block( db );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
   trx.clear_signatures(); trx.operations.clear();
   BOOST_CHECK_EQUAL( stealth_blind_work_this_block( db ) - before,
                      stealth_work_for_turnstile() );
} FC_CAPTURE_AND_RETHROW() }

// Spec §7.7: recovery requires owner authority; a stranger with the valid
// proof bytes but no ownership is refused before any image is read.
BOOST_AUTO_TEST_CASE( r15_owner_mismatch_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan)(eve) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-g", 16, true );
   const size_t s = 8;

   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_r15_nullify( db, I1, I2 );

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-g-bn" );
   T_set_recovery_v2( t, I1, I2, proof );
   // Eve claims ownership with her own key authority (same shape t5_fund_pool uses).
   t.owner = authority( 1, public_key_type( eve_private_key.get_public_key() ), 1 );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, eve_private_key );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "recovery without ownership must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Turnstile owner mismatch" )
                           != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
} FC_CAPTURE_AND_RETHROW() }

// Task 3 (flag retirement): a nullified output's refused recovery moves no
// supply — the do_evaluate refusal precedes do_apply, so confidential_supply
// is untouched. Formerly r15_supply_conservation (success-path supply pin on
// a flag-decoyed output); the success-path supply pin now lives on the
// never-spent superset case (r15_recovery_never_spent_with_extension_succeeds).
BOOST_AUTO_TEST_CASE( r15_nullified_recovery_moves_no_supply )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-h", 16, true );
   const size_t s = 9;

   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_r15_nullify( db, I1, I2 );
   const int64_t live = t5_supply( db, core );

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-h-bn" );
   T_set_recovery_v2( t, I1, I2, proof );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "nullified recovery must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "nullifier" ) != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live );
} FC_CAPTURE_AND_RETHROW() }

// Spec §7.9 (canonical-encoding negatives): non-canonical scalar,
// invalid-encoding point, and well-formed-but-off-curve point all refuse.
// Proof layout: A_C[0,33) A_1[33,66) A_2[66,99) s_b[99,131) s_v[131,163).
BOOST_AUTO_TEST_CASE( r15_recovery_malformed_proof_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-m", 16, true );
   const size_t s = 10;

   fc::ecc::commitment_type I1, I2; std::vector<char> good;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, good );
   T_r15_nullify( db, I1, I2 );
   BOOST_REQUIRE( good.size() == 163 );

   // (a) non-canonical s_b: 0xFF*32 exceeds the curve order, must refuse.
   {
      std::vector<char> bad = good;
      for( int i = 99; i < 131; ++i ) bad[i] = (char)0xFF;
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-m-bn-a" );
      T_set_recovery_v2( t, I1, I2, bad );
      set_expiration( db, trx );
      trx.operations = { t };
      sign( trx, p.keys[s] );
      // B3: pin the refusal LAYER + verifier error (bare throw = any layer).
      try {
         PUSH_TX( db, trx );
         BOOST_FAIL( "non-canonical s_b recovery must be refused" );
      } catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "Turnstile recovery proof does not verify" ) != std::string::npos,
            e.to_detail_string() );
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "recovery s_b not canonical" ) != std::string::npos,
            e.to_detail_string() );
      }
      trx.clear_signatures(); trx.operations.clear();
   }
   // (b) invalid point encoding: zeroed A_C (bad prefix, on no curve).
   {
      std::vector<char> bad = good;
      for( int i = 0; i < 33; ++i ) bad[i] = 0;
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-m-bn-b" );
      T_set_recovery_v2( t, I1, I2, bad );
      set_expiration( db, trx );
      trx.operations = { t };
      sign( trx, p.keys[s] );
      try {
         PUSH_TX( db, trx );
         BOOST_FAIL( "zeroed-A_C recovery must be refused" );
      } catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "Turnstile recovery proof does not verify" ) != std::string::npos,
            e.to_detail_string() );
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "bad recovery A_C" ) != std::string::npos,
            e.to_detail_string() );
      }
      trx.clear_signatures(); trx.operations.clear();
   }
   // (c) well-formed encoding but off-curve A_1: tweak the last byte until
   // compressed-point decode fails (half of x values are non-residues, so
   // this terminates in a few tries). Consensus strict parsing must refuse.
   {
      std::vector<unsigned char> off( good.begin() + 33, good.begin() + 66 );
      bool found = false;
      for( int k = 1; k < 256 && !found; ++k )
      {
         off[32] = (unsigned char)( (unsigned char)good[33 + 32] ^ (unsigned char)k );
         EC_POINT* q = EC_POINT_new( T_group() );
         if( EC_POINT_oct2point( T_group(), q, off.data(), 33, nullptr ) != 1 )
            found = true;
         EC_POINT_free( q );
      }
      BOOST_REQUIRE_MESSAGE( found, "test must find an off-curve tweak of A_1" );
      std::vector<char> bad = good;
      std::copy( off.begin(), off.end(), bad.begin() + 33 );
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-m-bn-c" );
      T_set_recovery_v2( t, I1, I2, bad );
      set_expiration( db, trx );
      trx.operations = { t };
      sign( trx, p.keys[s] );
      try {
         PUSH_TX( db, trx );
         BOOST_FAIL( "off-curve A_1 recovery must be refused" );
      } catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "Turnstile recovery proof does not verify" ) != std::string::npos,
            e.to_detail_string() );
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "bad recovery A_1" ) != std::string::npos,
            e.to_detail_string() );
      }
      trx.clear_signatures(); trx.operations.clear();
   }
   // (d) identity-adjacent encoding: 33 zero bytes (0x00 first byte =
   // invalid compressed prefix). SEC-1 compressed identity is 1 byte 0x00,
   // so no 33-byte compressed identity exists; 33x0x00 must fail prefix
   // validation in point_from_bytes — this vector pins that. Fed as A_C
   // and once as I1; both must refuse.
   {
      std::vector<char> bad = good;
      for( int i = 0; i < 33; ++i ) bad[i] = 0;
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-m-bn-d1" );
      T_set_recovery_v2( t, I1, I2, bad );
      set_expiration( db, trx );
      trx.operations = { t };
      sign( trx, p.keys[s] );
      try {
         PUSH_TX( db, trx );
         BOOST_FAIL( "33x00 A_C recovery must be refused" );
      } catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "Turnstile recovery proof does not verify" ) != std::string::npos,
            e.to_detail_string() );
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "bad recovery A_C" ) != std::string::npos,
            e.to_detail_string() );
      }
      trx.clear_signatures(); trx.operations.clear();
   }
   {
      fc::ecc::commitment_type zero_I1; zero_I1.fill( 0 );
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-m-bn-d2" );
      T_set_recovery_v2( t, zero_I1, I2, good );
      set_expiration( db, trx );
      trx.operations = { t };
      sign( trx, p.keys[s] );
      try {
         PUSH_TX( db, trx );
         BOOST_FAIL( "zero-I1 recovery must be refused" );
      } catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "Turnstile recovery proof does not verify" ) != std::string::npos,
            e.to_detail_string() );
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "bad recovery I1" ) != std::string::npos,
            e.to_detail_string() );
      }
      trx.clear_signatures(); trx.operations.clear();
   }
} FC_CAPTURE_AND_RETHROW() }

// Task 5 (R15 hardening): off-curve I1 refuses. The statement images are
// consensus-parsed (point_from_commit rejects bad/off-curve/identity), so a
// well-sized but off-curve I1 must fail before any equation runs. Positive
// control: the true I1 verifies against the same (C, I2, proof).
BOOST_AUTO_TEST_CASE( r15_recovery_offcurve_I1_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-i1", 16, true );
   const size_t s = 11;

   fc::ecc::commitment_type I1, I2; std::vector<char> good;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, good );
   T_r15_nullify( db, I1, I2 );
   const uint64_t aid = core.get_id().instance.value;

   // Positive control: true material verifies at the consensus entry point.
   {
      std::string err;
      BOOST_CHECK_MESSAGE( stealth_verify_recovery_proof( p.commits[s], I1, I2,
                            good, aid, err ), "true I1 must verify: " << err );
   }

   // Tweak I1's last byte until compressed-point decode fails (same search as
   // the off-curve A_1 vector above — half of x values are non-residues).
   std::vector<unsigned char> off( I1.begin(), I1.end() );
   bool found = false;
   for( int k = 1; k < 256 && !found; ++k )
   {
      off[32] = (unsigned char)( (unsigned char)I1[32] ^ (unsigned char)k );
      EC_POINT* q = EC_POINT_new( T_group() );
      if( EC_POINT_oct2point( T_group(), q, off.data(), 33, nullptr ) != 1 )
         found = true;
      EC_POINT_free( q );
   }
   BOOST_REQUIRE_MESSAGE( found, "test must find an off-curve tweak of I1" );
   fc::ecc::commitment_type bad_I1;
   std::copy( off.begin(), off.end(), bad_I1.begin() );

   // Negative control: off-curve I1 fails the direct verifier (parse level).
   {
      std::string err;
      BOOST_CHECK_MESSAGE( !stealth_verify_recovery_proof( p.commits[s], bad_I1,
                            I2, good, aid, err ), "off-curve I1 must not verify" );
      BOOST_CHECK_MESSAGE( err.find( "bad recovery I1" ) != std::string::npos, err );
   }

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-i1-bn" );
   T_set_recovery_v2( t, bad_I1, I2, good );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "off-curve I1 must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "does not verify" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
} FC_CAPTURE_AND_RETHROW() }

// Task 5 (R15 hardening): a proof built over the wrong Fiat-Shamir domain tag
// refuses. The responses satisfy the WRONG challenge, so the consensus
// equations (recomputed under "BTS-STEALTH-RECOVERY-v1") mismatch — this pins
// domain separation against cross-protocol replay. The wrong-domain proof is
// well-formed (parse-level clean: the refusal names an equation mismatch),
// proving the guard exercised is the domain binding, not shape.
BOOST_AUTO_TEST_CASE( r15_recovery_wrong_domain_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-wd", 16, true );
   const size_t s = 12;

   fc::ecc::commitment_type I1, I2; std::vector<char> good;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, good );
   T_r15_nullify( db, I1, I2 );
   const uint64_t aid = core.get_id().instance.value;

   // Positive control: consensus-domain proof verifies.
   {
      std::string err;
      BOOST_CHECK_MESSAGE( stealth_verify_recovery_proof( p.commits[s], I1, I2,
                            good, aid, err ), "consensus-domain proof must verify: " << err );
   }

   // Same opening, wrong domain tag: images identical (domain-independent),
   // responses bound to the wrong challenge.
   fc::ecc::commitment_type wI1, wI2; std::vector<char> wrong;
   {
      BIGNUM* bb = T_bn( p.blinds[s] );
      std::vector<unsigned char> Cvec( p.commits[s].begin(), p.commits[s].end() );
      T_prove_recovery_with_domain( Cvec, bb, (uint64_t)p.each, core.get_id(),
         "BTS-STEALTH-RECOVERY-v0", wI1, wI2, wrong );
      BN_free( bb );
   }
   BOOST_REQUIRE( wI1 == I1 );
   BOOST_REQUIRE( wI2 == I2 );
   BOOST_REQUIRE( wrong.size() == 163 );

   // Negative control: wrong-domain proof parses but mismatches equations.
   {
      std::string err;
      BOOST_CHECK_MESSAGE( !stealth_verify_recovery_proof( p.commits[s], I1, I2,
                            wrong, aid, err ), "wrong-domain proof must not verify" );
      BOOST_CHECK_MESSAGE( err.find( "mismatch" ) != std::string::npos, err );
   }

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-wd-bn" );
   T_set_recovery_v2( t, I1, I2, wrong );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "wrong-domain proof must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "does not verify" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
} FC_CAPTURE_AND_RETHROW() }

// Task 5 (R15 hardening): asset_id context mismatch refuses. The challenge
// binds asset_id_le64, so a proof minted for asset 7 does not transfer to the
// CORE op — this pins op-context binding (no cross-asset proof replay).
// Positive control: the same proof verifies under its own asset context.
BOOST_AUTO_TEST_CASE( r15_recovery_asset_context_mismatch_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-ax", 16, true );
   const size_t s = 13;

   // Prove the TRUE opening but under a foreign asset context (7 is only
   // hashed into the challenge — it need not exist on-chain).
   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   {
      BIGNUM* bb = T_bn( p.blinds[s] );
      std::vector<unsigned char> Cvec( p.commits[s].begin(), p.commits[s].end() );
      T_prove_recovery( Cvec, bb, (uint64_t)p.each, asset_id_type( 7 ), I1, I2, proof );
      BN_free( bb );
   }
   // Images are domain-independent (pinned below: wI1 == I1), so these are
   // the commitment's real images — nullify them. The submitted proof still
   // refuses at the proof layer (wrong asset context), first.
   T_r15_nullify( db, I1, I2 );
   const uint64_t core_aid = core.get_id().instance.value;

   // Positive control: verifies under its own (foreign) asset context...
   {
      std::string err;
      BOOST_CHECK_MESSAGE( stealth_verify_recovery_proof( p.commits[s], I1, I2,
                            proof, 7, err ), "proof must verify in its own context: " << err );
   }
   // ...but not under the op's CORE context (equation-level mismatch).
   {
      std::string err;
      BOOST_CHECK_MESSAGE( !stealth_verify_recovery_proof( p.commits[s], I1, I2,
                            proof, core_aid, err ), "cross-asset proof must not verify" );
      BOOST_CHECK_MESSAGE( err.find( "mismatch" ) != std::string::npos, err );
   }

   // Submitted against the CORE op: owner/asset legs pass (op is CORE), the
   // proof leg must refuse.
   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-ax-bn" );
   BOOST_REQUIRE( t.asset_id == core.get_id() );
   T_set_recovery_v2( t, I1, I2, proof );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "cross-asset proof must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "does not verify" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
} FC_CAPTURE_AND_RETHROW() }

// Task 5 (R15 hardening): recovery of a NEVER-SPENT output with the extension
// succeeds. The binding path (owner + valid proof + nullifier-absent) is a
// SUPERSET of the plain path (owner + nullifier-absent): it must
// accept every output the plain path accepts, proving the extension is a
// bound alternative, not a bypass that only fires on nullified outputs.
BOOST_AUTO_TEST_CASE( r15_recovery_never_spent_with_extension_succeeds )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-ns", 16, true );
   const size_t s = 14;

   // NOTE: no T_r15_nullify — the output is live and un-nullified.
   const int64_t live = t5_supply( db, core );

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-ns-bn" );
   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_set_recovery_v2( t, I1, I2, proof );

   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
   trx.clear_signatures(); trx.operations.clear();
   generate_block();
   const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
   BOOST_CHECK( bbi.find( p.commits[s] ) == bbi.end() ); // old consumed
   BOOST_CHECK( bbi.find( t.new_output.commitment ) != bbi.end() ); // fresh V2 output exists
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live - 10 ); // fee leg identical
} FC_CAPTURE_AND_RETHROW() }

// Task 3 (flag retirement): a nullified output's refused recovery moves no
// supply even with a NON-DEFAULT fee (37 over a 963 output) — the
// do_evaluate refusal precedes do_apply, so no fee leaves supply. Formerly
// r15_recovery_fee_exact (success-path fee-exactness pin on a flag-decoyed
// output); the success-path fee pin now lives on the never-spent superset
// case (r15_recovery_never_spent_with_extension_succeeds).
BOOST_AUTO_TEST_CASE( r15_nullified_nondefault_fee_refuses_cleanly )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-fe", 16, true );
   const size_t s = 15;

   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_r15_nullify( db, I1, I2 );
   const int64_t live = t5_supply( db, core );

   const int64_t fee = 37, out_v = 963;
   turnstile_reproof_operation t = T_r15_turnstile_value( core, p, s,
      "r15-fe-bn", out_v, fee );
   BOOST_REQUIRE_EQUAL( t.fee.amount.value, fee );
   T_set_recovery_v2( t, I1, I2, proof );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "nullified recovery must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "nullifier" ) != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live );
} FC_CAPTURE_AND_RETHROW() }

// R15C-01: substituting a SINGLE image under the otherwise-true proof
// refuses, in both directions. The Fiat-Shamir challenge binds BOTH images
// (C || I1 || I2 sit in the preimage), so any substitution changes c and
// the C leg — checked first — deterministically mismatches. Both legs are
// exercised so a verifier checking only one image leg cannot pass this
// case; the gate pins the proof-layer message in both directions.
BOOST_AUTO_TEST_CASE( r15_recovery_single_image_substitution_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-s1", 16, true );
   const size_t s = 3, f = 7;
   const uint64_t aid = core.get_id().instance.value;

   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_r15_nullify( db, I1, I2 );
   // Foreign images: another pool member's valid on-curve images.
   fc::ecc::commitment_type fI1, fI2; std::vector<char> fproof;
   T_r15_prove_true( p, f, core.get_id(), fI1, fI2, fproof );
   BOOST_REQUIRE( fI1 != I1 );
   BOOST_REQUIRE( fI2 != I2 );

   // Direct verifier: true I1 + foreign I2 under the true proof refuses.
   {
      std::string err;
      BOOST_CHECK_MESSAGE( !stealth_verify_recovery_proof( p.commits[s], I1, fI2,
                            proof, aid, err ), "true-I1/foreign-I2 must not verify" );
      BOOST_CHECK_MESSAGE( err.find( "recovery equation C mismatch" ) != std::string::npos, err );
   }
   // Direct verifier: foreign I1 + true I2 under the true proof refuses.
   {
      std::string err;
      BOOST_CHECK_MESSAGE( !stealth_verify_recovery_proof( p.commits[s], fI1, I2,
                            proof, aid, err ), "foreign-I1/true-I2 must not verify" );
      BOOST_CHECK_MESSAGE( err.find( "recovery equation C mismatch" ) != std::string::npos, err );
   }

   // Gate: true I1 + foreign I2 refuses with the proof-layer message.
   {
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-s1-bn-a" );
      T_set_recovery_v2( t, I1, fI2, proof );
      set_expiration( db, trx );
      trx.operations = { t };
      sign( trx, p.keys[s] );
      try {
         PUSH_TX( db, trx );
         BOOST_FAIL( "true-I1/foreign-I2 recovery must be refused" );
      } catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "does not verify" )
                              != std::string::npos, e.to_detail_string() );
      }
      trx.clear_signatures(); trx.operations.clear();
   }
   // Gate: foreign I1 + true I2 refuses with the proof-layer message.
   {
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-s1-bn-b" );
      T_set_recovery_v2( t, fI1, I2, proof );
      set_expiration( db, trx );
      trx.operations = { t };
      sign( trx, p.keys[s] );
      try {
         PUSH_TX( db, trx );
         BOOST_FAIL( "foreign-I1/true-I2 recovery must be refused" );
      } catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "does not verify" )
                              != std::string::npos, e.to_detail_string() );
      }
      trx.clear_signatures(); trx.operations.clear();
   }
} FC_CAPTURE_AND_RETHROW() }

// R15C-02 (plus R15B-02 tag pin): the recovery extension survives binary
// round-trip with stable variant tags. Tag order is consensus (P2P fork risk
// on reorder), so it is pinned both as constructed (void_t=0, recovery=1)
// and on the wire, and the payload round-trips byte-identical.
BOOST_AUTO_TEST_CASE( r15_recovery_wire_round_trip )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-w", 16, true );
   const size_t s = 3;

   // Tag-order pin: void_t is tag 0, the recovery extension is tag 1.
   {
      turnstile_extensions_v2 v0{ graphene::protocol::void_t{} };
      BOOST_CHECK( v0.which() == 0 );
      fc::ecc::commitment_type I1x, I2x; std::vector<char> px;
      T_r15_prove_true( p, s, core.get_id(), I1x, I2x, px );
      turnstile_extensions_v2 v1( turnstile_recovery_v2_extension{ I1x, I2x, px } );
      BOOST_CHECK( v1.which() == 1 );
   }

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-w-bn" );
   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_set_recovery_v2( t, I1, I2, proof );
   BOOST_REQUIRE( t.extensions.size() == 1 );
   BOOST_CHECK( t.extensions.begin()->which() == 1 );

   const std::vector<char> bytes = fc::raw::pack( t );
   const turnstile_reproof_operation back =
      fc::raw::unpack<turnstile_reproof_operation>( bytes );
   BOOST_REQUIRE( back.extensions.size() == 1 );
   BOOST_CHECK( back.extensions.begin()->which() == 1 );
   const auto& e = back.extensions.begin()->get<turnstile_recovery_v2_extension>();
   BOOST_CHECK_MESSAGE( e.key_image_v1 == I1, "I1 must survive round-trip" );
   BOOST_CHECK_MESSAGE( e.key_image_v2 == I2, "I2 must survive round-trip" );
   BOOST_CHECK_MESSAGE( e.recovery_proof.proof_bytes == proof,
                        "proof_bytes must survive round-trip" );
   // Re-pack stability: serialization is a fixed point (no P2P drift).
   BOOST_CHECK_MESSAGE( fc::raw::pack( back ) == bytes,
                        "re-pack must be byte-identical" );
} FC_CAPTURE_AND_RETHROW() }

// R15C-03/R15B-02: >1 extensions refuse at the gate (size pinned before any
// proof work), with the gate-layer message.
BOOST_AUTO_TEST_CASE( r15_recovery_oversize_extension_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-ov", 16, true );
   const size_t s = 3;

   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_r15_nullify( db, I1, I2 );

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-ov-bn" );
   T_set_recovery_v2( t, I1, I2, proof );
   t.extensions.insert( turnstile_extensions_v2( graphene::protocol::void_t() ) );
   BOOST_REQUIRE( t.extensions.size() == 2 );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "more than one recovery extension must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find(
         "Turnstile recovery takes one extension" ) != std::string::npos,
         e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
} FC_CAPTURE_AND_RETHROW() }

// R15C-03/R15B-02: a singleton void_t entry refuses — the gate's throwing
// get<> rejects the wrong variant type before any image is read.
BOOST_AUTO_TEST_CASE( r15_recovery_wrongtype_extension_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-wt", 16, true );
   const size_t s = 3;

   // Nullify the true images (the void_t gate throws before any image is
   // read, so the refusal layer is unchanged).
   {
      fc::ecc::commitment_type tI1, tI2; std::vector<char> tproof;
      T_r15_prove_true( p, s, core.get_id(), tI1, tI2, tproof );
      T_r15_nullify( db, tI1, tI2 );
   }

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-wt-bn" );
   t.extensions.insert( turnstile_extensions_v2( graphene::protocol::void_t() ) );
   BOOST_REQUIRE( t.extensions.size() == 1 );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "a void_t recovery extension must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find(
         "does not contain a value of type" ) != std::string::npos,
         e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
} FC_CAPTURE_AND_RETHROW() }

// R15C-03: empty proof_bytes refuse — the direct verifier names the shape
// refusal, the gate pins its 163-byte message.
BOOST_AUTO_TEST_CASE( r15_recovery_empty_proof_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-ep", 16, true );
   const size_t s = 3;
   const uint64_t aid = core.get_id().instance.value;

   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_r15_nullify( db, I1, I2 );
   const std::vector<char> empty;
   {
      std::string err;
      BOOST_CHECK_MESSAGE( !stealth_verify_recovery_proof( p.commits[s], I1, I2,
                            empty, aid, err ), "empty proof must not verify" );
      BOOST_CHECK_MESSAGE( err.find( "recovery proof size" ) != std::string::npos, err );
   }

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-ep-bn" );
   T_set_recovery_v2( t, I1, I2, empty );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "empty recovery proof must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find(
         "Turnstile recovery proof must be 163 bytes" ) != std::string::npos,
         e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
} FC_CAPTURE_AND_RETHROW() }

// R15C-03: non-canonical s_v refuses. The existing suite mutates only s_b;
// this is the s_v half (bytes [131,163) set past the curve order). The
// direct verifier names s_v; the gate pins the proof-layer message.
BOOST_AUTO_TEST_CASE( r15_recovery_noncanonical_sv_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-sv", 16, true );
   const size_t s = 3;
   const uint64_t aid = core.get_id().instance.value;

   fc::ecc::commitment_type I1, I2; std::vector<char> good;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, good );
   T_r15_nullify( db, I1, I2 );
   BOOST_REQUIRE( good.size() == 163 );
   std::vector<char> bad = good;
   for( int i = 131; i < 163; ++i ) bad[i] = (char)0xFF;
   {
      std::string err;
      BOOST_CHECK_MESSAGE( !stealth_verify_recovery_proof( p.commits[s], I1, I2,
                            bad, aid, err ), "non-canonical s_v must not verify" );
      BOOST_CHECK_MESSAGE( err.find( "recovery s_v not canonical" ) != std::string::npos, err );
   }

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-sv-bn" );
   T_set_recovery_v2( t, I1, I2, bad );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "non-canonical s_v recovery must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "does not verify" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
} FC_CAPTURE_AND_RETHROW() }

// R15C-04 — HONEST-PATH HALF ONLY. Renamed from r15_recovery_challenge_zero_guard
// (mimo-2.6 re-audit B2): this case does NOT exercise the c == 0 refusal at
// stealth_proof.cpp:709 and must not claim to. Forcing c == 0 requires a
// transcript whose sha256 is ≡ 0 mod n — {0, n} out of 2^256 hash outputs
// (~2^-256) — and every transcript byte is bound (domain || C || I1 || I2 ||
// A_C || A_1 || A_2 || aid_le64 || C), so no cheap free variable exists to
// grind. The only ways to force it are a test-only injection seam inside
// stealth_verify_recovery_proof (rejected: test-only code inside consensus
// crypto splits the verification path into two entry points — divergence
// risk on the consensus-critical function) or a refactor that hands the
// verifier a caller-supplied challenge (same objection). Therefore this
// case pins only what is observable in-tree: the true proof verifies (the
// guard does not misfire on honest input) and the honest recomputed
// challenge is nonzero (the guard's post-condition on real inputs). The
// c == 0 branch itself remains defense-in-depth, unexercised by unit test.
BOOST_AUTO_TEST_CASE( r15_recovery_honest_challenge_nonzero )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-c0", 16, true );
   const size_t s = 3;
   const uint64_t aid = core.get_id().instance.value;

   fc::ecc::commitment_type I1, I2; std::vector<char> good;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, good );
   BOOST_REQUIRE( good.size() == 163 );
   {
      std::string err;
      BOOST_CHECK_MESSAGE( stealth_verify_recovery_proof( p.commits[s], I1, I2,
                            good, aid, err ), "honest proof must verify: " << err );
   }

   // Recompute c exactly as stealth_verify_recovery_proof does and pin
   // nonzero: domain || C || I1 || I2 || A_C || A_1 || A_2 || aid_le64 || C.
   std::vector<unsigned char> Cvec( p.commits[s].begin(), p.commits[s].end() );
   std::vector<unsigned char> I1v( I1.begin(), I1.end() ), I2v( I2.begin(), I2.end() );
   std::vector<unsigned char> aC( good.begin(), good.begin() + 33 ),
                              a1( good.begin() + 33, good.begin() + 66 ),
                              a2( good.begin() + 66, good.begin() + 99 );
   std::string pre = "BTS-STEALTH-RECOVERY-v1";
   pre.append( (const char*)Cvec.data(), 33 );
   pre.append( (const char*)I1v.data(), 33 );
   pre.append( (const char*)I2v.data(), 33 );
   pre.append( (const char*)aC.data(), 33 );
   pre.append( (const char*)a1.data(), 33 );
   pre.append( (const char*)a2.data(), 33 );
   for( int i = 0; i < 8; ++i ) pre.push_back( (char)( aid >> (8*i) ) );
   pre.append( (const char*)Cvec.data(), 33 );
   fc::sha256 h = fc::sha256::hash( pre.c_str(), (uint32_t)pre.size() );
   BIGNUM* c = BN_new();
   BOOST_REQUIRE( c != nullptr );
   BN_bin2bn( (const unsigned char*)h.data(), 32, c );
   BN_mod( c, c, T_order(), T_ctx() );
   BOOST_CHECK_MESSAGE( !BN_is_zero( c ), "honest challenge must be nonzero" );
   BN_free( c );
} FC_CAPTURE_AND_RETHROW() }

// Task 3 (flag retirement, live-set rewrite): the counter measures the LIVE
// metadata-bearing set. A ring spend removes nothing (no per-member decrement;
// the two new outputs join: 16 -> 18), and a turnstile recovery swaps the
// consumed member for the migrated one 1:1 (net 0: -1 on had_metadata, +1 on
// create). The counter must equal the chain-derived live set after every leg.
// (The reverted 113202ea guard is behavior-neutral here — was_spent is now
// unwritable, so both guards agree — but the read of the retired field had
// to go with the field's retirement.)
BOOST_AUTO_TEST_CASE( r15_recovery_pool_count_preserved )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-pc", 16, true );
   const size_t s    = 3; // decoy of the ring below: stays live throughout
   const size_t real = 7; // honest real input of the ring (different owner key)

   // Chain-derived truth: metadata-bearing blinded balances of this asset
   // (the set the counter is supposed to MEASURE, never assume).
   auto true_depth = [&]() {
      uint32_t n = 0;
      const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
      for( const auto& b : bbi )
         if( b.asset_id == core.get_id() && b.created_block != 0 )
            ++n;
      return n;
   };
   auto counter = [&]() {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      auto itr = st.unspent_blind_count.find( core.get_id() );
      return ( itr == st.unspent_blind_count.end() ) ? uint32_t( 0 ) : itr->second;
   };

   // 16 fresh metadata-bearing outputs: counter == truth.
   BOOST_REQUIRE_EQUAL( counter(), 16u );
   BOOST_REQUIRE_EQUAL( counter(), true_depth() );

   // Genuine ring spend whose ring carries the target as a DECOY. Post-Task 3
   // the decoy is untouched: still indexed, images never nullified, still
   // counted — griefing by decoy-inclusion is impossible (§3.8).
   stealth_transfer_operation stop = t5_build_spend( core, p, real,
      GRAPHENE_STEALTH_PROOF_V2, "r15-pc-sp", 600, 390, 10 );
   trx.operations = { stop };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   {
      const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
      auto itr = bbi.find( p.commits[s] );
      BOOST_REQUIRE( itr != bbi.end() ); // decoy survives: still indexed
   }
   // The ring removed nothing; only the two new outputs joined: 16 -> 18.
   BOOST_REQUIRE_EQUAL( counter(), 18u );
   BOOST_REQUIRE_EQUAL( counter(), true_depth() );
   const uint32_t after_spend = counter();
   const int64_t supply_before_recovery = t5_supply( db, core );

   // Recovery of the decoyed balance (R15 extension path).
   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-pc-bn" );
   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_set_recovery_v2( t, I1, I2, proof );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
   trx.clear_signatures(); trx.operations.clear();
   generate_block();

   // Recovery succeeded: old balance consumed, migrated output live.
   const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
   BOOST_CHECK( bbi.find( p.commits[s] ) == bbi.end() );
   auto ntr = bbi.find( t.new_output.commitment );
   BOOST_REQUIRE( ntr != bbi.end() );
   // Conservation: recovery moved value by the fee only.
   BOOST_CHECK_EQUAL( t5_supply( db, core ), supply_before_recovery - t.fee.amount.value );

   // THE PIN: the migrated output replaces the consumed one 1:1 — net zero
   // across the recovery, and the counter still tracks the live set.
   BOOST_CHECK_EQUAL( counter(), after_spend );
   BOOST_CHECK_EQUAL( counter(), true_depth() );
} FC_CAPTURE_AND_RETHROW() }

/// B5(f): ring-spend builder for an ARBITRARY live commitment — mirrors
/// t5_build_spend exactly, but the ring, the real input's blind and the real
/// input's value are caller-supplied (the migrated commitment is not a pool
/// member and carries the turnstile's 990-value blind).
static stealth_transfer_operation T_r15_build_spend_of( const asset_object& core,
      const std::vector<fc::ecc::commitment_type>& ring, size_t real,
      const fc::sha256& real_blind, int64_t real_value,
      uint8_t version, const std::string& tag,
      int64_t out1, int64_t out2, int64_t fee )
{
   BOOST_REQUIRE( out1 + out2 + fee == real_value );
   BOOST_REQUIRE( real < ring.size() );
   const uint8_t alt_v = ( version == GRAPHENE_STEALTH_PROOF_V1 )
                         ? GRAPHENE_STEALTH_PROOF_V2
                         : GRAPHENE_STEALTH_PROOF_V1;
   BIGNUM* bs = T_bn( real_blind );
   BIGNUM* bprime = T_bn( T_blind_secret( tag + "-pseudo" ) );
   auto Bk1 = T_blind_secret( tag + "-o1" );
   auto Bk2 = T_blind_secret( tag + "-o2" );
   auto rk1 = fc::ecc::private_key::generate();
   auto rk2 = fc::ecc::private_key::generate();
   stealth_blind_output so1, so2;
   so1.commitment = fc::ecc::blind( Bk1, out1 );
   so2.commitment = fc::ecc::blind( Bk2, out2 );
   if( version == GRAPHENE_STEALTH_PROOF_V1 )
   {
      auto Nk1 = T_secret( tag + "-n1" );
      auto Nk2 = T_secret( tag + "-n2" );
      so1.range_proof = fc::ecc::range_proof_sign( 0, so1.commitment, Bk1, Nk1, 0, 0, out1 );
      so2.range_proof = fc::ecc::range_proof_sign( 0, so2.commitment, Bk2, Nk2, 0, 0, out2 );
   }
   else
   {
      so1.range_proof = T_bp_prove( so1.commitment, Bk1, (uint64_t)out1 );
      so2.range_proof = T_bp_prove( so2.commitment, Bk2, (uint64_t)out2 );
   }
   so1.owner = authority( 1, public_key_type( rk1.get_public_key() ), 1 );
   so2.owner = authority( 1, public_key_type( rk2.get_public_key() ), 1 );
   stealth_transfer_operation stop;
   stop.asset_id = core.get_id();
   stop.proof_version = version;
   stop.fee = core.amount( fee );
   stop.outputs = { so1, so2 };
   {
      BIGNUM* e = BN_new();
      BIGNUM* b1 = T_bn( Bk1 );
      BIGNUM* b2 = T_bn( Bk2 );
      BN_copy( e, bprime );
      BN_mod_sub( e, e, b1, T_order(), T_ctx() );
      BN_mod_sub( e, e, b2, T_order(), T_ctx() );
      unsigned char eb[32]; BN_bn2binpad( e, eb, 32 );
      std::copy( eb, eb + 32, (char*)stop.excess.data() );
      BN_free( e ); BN_free( b1 ); BN_free( b2 );
   }
   std::vector<std::vector<unsigned char>> Q;
   for( const auto& c : ring )
      Q.push_back( std::vector<unsigned char>( c.begin(), c.end() ) );
   std::vector<fc::ecc::commitment_type> out_cs = { so1.commitment, so2.commitment };
   auto Pv = T_commit( bprime, (uint64_t)real_value );
   fc::ecc::commitment_type pseudo_c = T_commitment( Pv );
   auto dry = T_dual_dry_run( version, alt_v, Q, real, bs, (uint64_t)real_value, bprime );
   BOOST_REQUIRE( dry.pseudo == Pv );
   std::vector<char> img_c( dry.img_main.begin(), dry.img_main.end() );
   std::vector<char> img_a( dry.img_alt.begin(), dry.img_alt.end() );
   fc::sha256 m = stealth_ring_message( version, stop.asset_id, img_c,
                                        ring, pseudo_c, out_cs, stop.fee.amount );
   fc::sha256 ma = stealth_ring_message( alt_v, stop.asset_id, img_a,
                                         ring, pseudo_c, out_cs, stop.fee.amount );
   std::string ms( (const char*)m.data(), 32 );
   std::string msa( (const char*)ma.data(), 32 );
   stop.inputs = { T_make_dual_ring_input( version, alt_v, Q, real, bs,
                                           (uint64_t)real_value, bprime, ms, msa ) };
   BN_free( bs ); BN_free( bprime );
   return stop;
}

// A1 (mimo-2.6 re-audit): turnstile_reproof_operation::validate() must bound
// the extension payload the way this file's own header comment promises
// (every size bound mirrors the verifier's): at most one element, a void_t
// element refused with a clean FC_ASSERT (never a static_variant exception
// escaping validate()), and the recovery proof exactly the verifier's 163
// bytes. key_image_v1/v2 are commitment_type — fixed 33-byte arrays — so the
// 163-byte proof is the only size-bearing field (no variable payload there).
BOOST_AUTO_TEST_CASE( r15_validate_bounds_extensions )
{ try {
   const asset_object& core = asset_id_type()( db );
   auto make_op = [&]() {
      turnstile_reproof_operation t;
      t.asset_id = core.get_id();
      t.fee = core.amount( 10 );
      t.owner = authority( 1, account_id_type( 0 ), 1 );
      stealth_blind_output no;
      no.range_proof.assign( 16, 0 );
      no.owner = t.owner;
      t.new_output = no;
      return t;
   };
   auto expect_validate_refusal = [&]( const turnstile_reproof_operation& op,
                                       const std::string& needle ) {
      bool threw = false;
      std::string detail;
      try {
         op.validate();
      } catch( const fc::exception& e ) {
         threw = true;
         detail = e.to_detail_string();
      }
      BOOST_CHECK_MESSAGE( threw, "expected validate() refusal containing: " << needle );
      if( threw )
         BOOST_CHECK_MESSAGE( detail.find( needle ) != std::string::npos, detail );
   };
   fc::ecc::commitment_type I1, I2;

   // (1) extension count > 1 refuses (message identical to the evaluator's
   // gate so the pinned text does not fork by layer).
   {
      turnstile_reproof_operation t = make_op();
      t.extensions.insert( turnstile_recovery_v2_extension{ I1, I2,
                            std::vector<char>( 163, 0 ) } );
      t.extensions.insert( turnstile_extensions_v2( graphene::protocol::void_t() ) );
      BOOST_REQUIRE( t.extensions.size() == 2 );
      expect_validate_refusal( t, "Turnstile recovery takes one extension" );
   }
   // (2) singleton void_t: clean FC_ASSERT out of validate(), with the same
   // refusal text the evaluator's get<> throws (pinned by
   // r15_recovery_wrongtype_extension_refuses).
   {
      turnstile_reproof_operation t = make_op();
      t.extensions.insert( turnstile_extensions_v2( graphene::protocol::void_t() ) );
      BOOST_REQUIRE( t.extensions.size() == 1 );
      expect_validate_refusal( t, "does not contain a value of type" );
   }
   // (3) recovery-proof payload off the verifier's exact size refuses at
   // validate() with the gate-pinned 163-byte message.
   for( size_t n : { size_t( 0 ), size_t( 162 ), size_t( 164 ) } )
   {
      turnstile_reproof_operation t = make_op();
      t.extensions.insert( turnstile_recovery_v2_extension{ I1, I2,
                            std::vector<char>( n, 0 ) } );
      BOOST_REQUIRE( t.extensions.size() == 1 );
      expect_validate_refusal( t, "Turnstile recovery proof must be 163 bytes" );
   }
   // (4) positive control: the well-shaped extension validates clean.
   {
      turnstile_reproof_operation t = make_op();
      t.extensions.insert( turnstile_recovery_v2_extension{ I1, I2,
                            std::vector<char>( 163, 0 ) } );
      BOOST_CHECK_NO_THROW( t.validate() );
      // Empty extension set stays legal (plain turnstile).
      turnstile_reproof_operation e = make_op();
      BOOST_REQUIRE( e.extensions.empty() );
      BOOST_CHECK_NO_THROW( e.validate() );
   }
} FC_CAPTURE_AND_RETHROW() }

// A2 (validate leg): the STORED owner — do_apply writes
// b.owner = o.new_output.owner — must be possible, not just the OLD owner
// (stealth.cpp only checked o.owner before).
BOOST_AUTO_TEST_CASE( r15_validate_new_output_owner )
{ try {
   const asset_object& core = asset_id_type()( db );
   turnstile_reproof_operation t;
   t.asset_id = core.get_id();
   t.fee = core.amount( 10 );
   t.owner = authority( 1, account_id_type( 0 ), 1 );
   stealth_blind_output no;
   no.range_proof.assign( 16, 0 );
   no.owner = authority(); // threshold 1 over zero weight -> impossible
   no.owner.weight_threshold = 1;
   BOOST_REQUIRE( no.owner.is_impossible() );
   t.new_output = no;
   {
      bool threw = false;
      std::string detail;
      try {
         t.validate();
      } catch( const fc::exception& e ) {
         threw = true;
         detail = e.to_detail_string();
      }
      BOOST_CHECK_MESSAGE( threw, "an impossible new_output.owner must fail validate()" );
      if( threw )
         BOOST_CHECK_MESSAGE( detail.find( "Migrated output owner is impossible" )
                              != std::string::npos,
                              detail );
   }
   // Positive control: a resolvable authority validates clean.
   no.owner = authority( 1, account_id_type( 0 ), 1 );
   BOOST_REQUIRE( !no.owner.is_impossible() );
   t.new_output = no;
   BOOST_CHECK_NO_THROW( t.validate() );
} FC_CAPTURE_AND_RETHROW() }

// A2 (evaluator leg): every blind-output path resolves owner account_auths
// (confidential_evaluator.cpp:46-47; the outputs loop at
// stealth_evaluator.cpp:518-524) — the turnstile must do the same for the
// STORED new_output.owner, or an unresolvable reference bricks the migrated
// balance's spend path.
BOOST_AUTO_TEST_CASE( r15_new_output_owner_unresolvable_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-no", 16, true );
   const size_t s = 2;

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-no-bn" );
   t.new_output.owner = authority( 1, account_id_type( 99999 ), 1 );
   BOOST_REQUIRE( !t.new_output.owner.is_impossible() ); // weight meets threshold
   BOOST_REQUIRE( db.find( account_id_type( 99999 ) ) == nullptr ); // but absent
   BOOST_REQUIRE( t.owner == p.owners[s] ); // old-authority leg untouched

   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "an unresolvable new_output.owner must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Unable to find Object 1.2.99999" )
                            != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
   // Refused: nothing migrated.
   const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
   BOOST_CHECK( bbi.find( p.commits[s] ) != bbi.end() );
   BOOST_CHECK( bbi.find( t.new_output.commitment ) == bbi.end() );
} FC_CAPTURE_AND_RETHROW() }

// B1 (R15B-01 coverage — the uniqueness assert had ZERO tests): a turnstile
// whose new_output.commitment equals a DIFFERENT live commitment is refused
// by name, and the ORDER R15B-01 introduced is pinned: uniqueness
// (stealth_evaluator.cpp:894) precedes the recovery-proof verification
// (:914), so a simultaneously invalid proof still surfaces the uniqueness
// message — never "does not verify".
BOOST_AUTO_TEST_CASE( r15_duplicate_new_commitment_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-dup", 16, true );
   const size_t s = 4, victim = 6; // victim: a DIFFERENT live commitment

   // new_output re-encodes the VICTIM exactly: commitment, owner, blind and
   // a genuinely valid BP+ proof over it — every leg that runs BEFORE the
   // uniqueness assert passes; only uniqueness can refuse.
   auto collide = [&]( turnstile_reproof_operation& t ) {
      stealth_blind_output no;
      no.commitment = p.commits[victim];
      no.range_proof = T_bp_prove( no.commitment, p.blinds[victim],
                                   (uint64_t)p.each );
      no.owner = p.owners[victim];
      t.new_output = no;
      t.new_blind = p.blinds[victim];
   };
   auto push_expect_uniqueness = [&]( const turnstile_reproof_operation& t,
                                      bool also_no_proof_msg ) {
      set_expiration( db, trx );
      trx.operations = { t };
      sign( trx, p.keys[s] );
      std::string detail;
      try {
         PUSH_TX( db, trx );
         BOOST_FAIL( "colliding new commitment must be refused" );
      } catch( const fc::exception& e ) {
         detail = e.to_detail_string();
      }
      trx.clear_signatures(); trx.operations.clear();
      BOOST_CHECK_MESSAGE( detail.find( "Turnstile new commitment already exists" )
                            != std::string::npos,
                           "uniqueness message expected: " << detail );
      if( also_no_proof_msg )
         BOOST_CHECK_MESSAGE( detail.find( "does not verify" ) == std::string::npos,
                              "uniqueness must precede proof verification: " << detail );
   };

   // (a) plain turnstile + collision.
   {
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-dup-a-bn" );
      collide( t );
      push_expect_uniqueness( t, false );
   }
   // (b) VALID recovery extension + collision: uniqueness still first.
   {
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-dup-b-bn" );
      collide( t );
      fc::ecc::commitment_type I1, I2; std::vector<char> proof;
      T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
      T_set_recovery_v2( t, I1, I2, proof );
      push_expect_uniqueness( t, false );
   }
   // (c) ORDER PIN: simultaneously INVALID proof + collision -> uniqueness
   // message fires, NOT the proof-layer message.
   {
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-dup-c-bn" );
      collide( t );
      fc::ecc::commitment_type I1, I2; std::vector<char> proof;
      T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
      for( int i = 99; i < 131; ++i ) proof[i] = (char)0xFF; // non-canonical s_b
      T_set_recovery_v2( t, I1, I2, proof );
      push_expect_uniqueness( t, true );
   }
} FC_CAPTURE_AND_RETHROW() }

// B4: single-byte flips of an otherwise-VALID 163-byte proof at structural
// offsets (A_C prefix / A_C tail / A_2 prefix / s_b head / s_v head / s_v
// tail). The existing malformed vectors only fill whole 32-byte blocks with
// 0xFF; these poke interior bytes of genuine material. Each flip must fail
// the direct verifier (pinning WHICH refusal) and the gate must refuse with
// the proof-layer message.
BOOST_AUTO_TEST_CASE( r15_recovery_single_byte_flips_refuse )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-fl", 16, true );
   const size_t s = 3;
   const uint64_t aid = core.get_id().instance.value;

   fc::ecc::commitment_type I1, I2; std::vector<char> good;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, good );
   BOOST_REQUIRE( good.size() == 163 );

   // Message sets are branch-accurate: which refusal fires depends on the
   // FRESH proof's byte values (verifier structure, stealth_proof.cpp:
   // point_from_bytes -> scalar_parse_strict -> equation legs):
   //  - prefix bytes (0, 66): header rejected -> always the point name;
   //  - A_C tail (32): x' on curve ~50% -> equation C, else point name;
   //  - s head bytes (99, 131): flipped MSB >= n ~25% -> canonical refusal,
   //    else the equation-C leg (both scalars feed that leg);
   //  - s tail (162): stays canonical -> equation C.
   struct flip_case { size_t off; const char* err; const char* alt; };
   const flip_case cases[] = {
      {   0, "bad recovery A_C", nullptr },   // A_C compressed prefix
      {  32, "bad recovery A_C", "recovery equation C mismatch" }, // A_C x tail
      {  66, "bad recovery A_2", nullptr },   // A_2 compressed prefix
      {  99, "recovery s_b not canonical", "recovery equation C mismatch" },
      { 131, "recovery s_v not canonical", "recovery equation C mismatch" },
      { 162, "recovery equation C mismatch", nullptr }, // s_v tail byte
   };
   int seq = 0;
   for( const auto& c : cases )
   {
      std::vector<char> bad = good;
      bad[c.off] = (char)~(unsigned char)bad[c.off];
      BOOST_REQUIRE( bad != good );
      // Direct verifier: false, with the pinned refusal.
      {
         std::string err;
         BOOST_CHECK_MESSAGE( !stealth_verify_recovery_proof( p.commits[s], I1, I2,
                               bad, aid, err ),
                              "flip@" << c.off << " must not verify" );
         BOOST_CHECK_MESSAGE( err == std::string( c.err ) ||
                              ( c.alt && err == std::string( c.alt ) ),
                              "flip@" << c.off << " err: expected '" << c.err
                              << "' or '" << ( c.alt ? c.alt : "-" )
                              << "', got '" << err << "'" );
      }
      // Gate: refuses at the proof layer, by message.
      {
         turnstile_reproof_operation t = T_r15_turnstile( core, p, s,
            "r15-fl-bn-" + std::to_string( seq++ ) );
         T_set_recovery_v2( t, I1, I2, bad );
         set_expiration( db, trx );
         trx.operations = { t };
         sign( trx, p.keys[s] );
         try {
            PUSH_TX( db, trx );
            BOOST_FAIL( "flipped-proof recovery must be refused (offset "
                        << c.off << ")" );
         } catch( const fc::exception& e ) {
            BOOST_CHECK_MESSAGE( e.to_detail_string().find(
               "Turnstile recovery proof does not verify" ) != std::string::npos,
               "offset " << c.off << ": " << e.to_detail_string() );
         }
         trx.clear_signatures(); trx.operations.clear();
      }
   }
} FC_CAPTURE_AND_RETHROW() }

// B5 (matrix pair b): recover/migrate the OLD commitment, then ring-spend
// it. The migrated output REPLACED it in the blinded-balance index, so the
// ring membership gate refuses by name. The spend is built BEFORE the
// migration (rings are stateless), proving the refusal is index state.
BOOST_AUTO_TEST_CASE( r15_recover_then_ring_spend_old_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-b5b", 16, true );
   const size_t s = 3;
   const int64_t live = t5_supply( db, core );

   // Full-pool ring spend of s, built first (ring = all 16 members incl. s).
   stealth_transfer_operation stop = t5_build_spend( core, p, s,
      GRAPHENE_STEALTH_PROOF_V2, "r15-b5b-sp", 600, 390, 10 );

   // Migration of the old commitment (valid: unspent, owner-signed).
   // Task 4: the turnstile proves on every path — attach the true extension.
   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-b5b-bn" );
   {
      fc::ecc::commitment_type I1, I2; std::vector<char> proof;
      T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
      T_set_recovery_v2( t, I1, I2, proof );
   }
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
   trx.clear_signatures(); trx.operations.clear();
   generate_block();
   {
      const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
      BOOST_REQUIRE( bbi.find( p.commits[s] ) == bbi.end() ); // old consumed
      BOOST_REQUIRE( bbi.find( t.new_output.commitment ) != bbi.end() );
   }
   BOOST_REQUIRE_EQUAL( t5_supply( db, core ), live - 10 ); // migration fee only

   // The pre-built ring spend now names the consumed commitment: refused by
   // the membership gate, by message.
   set_expiration( db, trx );
   trx.operations = { stop };
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "ring-spend of the consumed (recovered) commitment must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find(
         "Ring member is not a live blinded balance" ) != std::string::npos,
         e.to_detail_string() );
   }
   trx.operations.clear();
   // Refusal moved nothing (only the migration fee ever left supply).
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live - 10 );
} FC_CAPTURE_AND_RETHROW() }

// B5 (matrix pair f): ring-spend the MIGRATED output after an EXTENSION
// recovery — expect success as a single spend, and the pool counter
// unchanged by the migration (the recovery swaps the consumed member for
// the migrated one 1:1 under live-set semantics; the spend then only adds
// its outputs, like any other ring spend).
BOOST_AUTO_TEST_CASE( r15_migrated_output_ring_spend_succeeds )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-b5f", 16, true );
   // Take s from funding group 4: the migrated output's created_block lands
   // in group 4's 100-block skew window (recovery runs right after funding),
   // so consuming one member of THAT window keeps every window at <=4 of 16
   // (thin-pool 25% rule, R-04). s from group 1 would make that window 5/16
   // and the decoy policy would refuse the spend.
   const size_t s = 15;

   // Chain-derived truth vs the counter (same pins as
   // r15_recovery_pool_count_preserved).
   auto true_depth = [&]() {
      uint32_t n = 0;
      const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
      for( const auto& b : bbi )
         if( b.asset_id == core.get_id() && b.created_block != 0 )
            ++n;
      return n;
   };
   auto counter = [&]() {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      auto itr = st.unspent_blind_count.find( core.get_id() );
      return ( itr == st.unspent_blind_count.end() ) ? uint32_t( 0 ) : itr->second;
   };
   BOOST_REQUIRE_EQUAL( counter(), 16u );
   BOOST_REQUIRE_EQUAL( counter(), true_depth() );
   const int64_t supply0 = t5_supply( db, core );

   // Extension recovery of s (never-spent superset path: bound alternative,
   // not a bypass — r15_recovery_never_spent_with_extension_succeeds).
   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-b5f-bn" );
   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_set_recovery_v2( t, I1, I2, proof );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
   trx.clear_signatures(); trx.operations.clear();
   generate_block();

   // Recovery succeeded... and the pool counter is UNCHANGED by the
   // migration: consumed member out, migrated member in, same depth.
   {
      const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
      BOOST_REQUIRE( bbi.find( p.commits[s] ) == bbi.end() );
      BOOST_REQUIRE( bbi.find( t.new_output.commitment ) != bbi.end() );
   }
   BOOST_REQUIRE_EQUAL( counter(), 16u );
   BOOST_REQUIRE_EQUAL( counter(), true_depth() );
   BOOST_REQUIRE_EQUAL( t5_supply( db, core ), supply0 - 10 );

   // Cross maintenances DETERMINISTICALLY (targeting next_maintenance_time
   // directly; a plain time jump can skip grid points and process the grant
   // interval only once). (1) The first maintenance processes the recovery's
   // parity grant: 1.000000 BTS granted against ~0 routed fee in its
   // interval -> worst=100% -> burn_critical armed (G3-03: new subsidies
   // suspended). (2) The next, idle interval recomputes worst=0 from empty
   // stats and auto-clears the alarm — the same re-arm fresh routed flow
   // gives production. Both transitions are pinned, then the migrated
   // output is aged past the 24h decoy minimum (any later maintenance stays
   // idle-safe: empty stats can only recompute worst=0).
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time );
   generate_block();
   {
      const auto& stx = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_REQUIRE( stx.alarms.burn_critical ); // G3-03 armed by the grant interval
   }
   generate_blocks( db.get_dynamic_global_properties().next_maintenance_time );
   generate_block();
   {
      const auto& stx = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_REQUIRE( !stx.alarms.burn_critical ); // idle interval cleared it
   }
   // Age the migrated output past the decoy minimum (membership applies to
   // every ring member, incl. the real input).
   generate_blocks( db.head_block_time() + GRAPHENE_STEALTH_DECOY_MIN_AGE_SEC + 600 );
   generate_block();
   {
      const auto& stx = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_REQUIRE( !stx.alarms.burn_critical ); // still clear after aging
   }
   set_expiration( db, trx );

   // Ring: the 15 surviving pool members + the migrated output LAST (real).
   std::vector<fc::ecc::commitment_type> ring;
   for( size_t i = 0; i < p.commits.size(); ++i )
      if( i != s ) ring.push_back( p.commits[i] );
   ring.push_back( t.new_output.commitment );
   const size_t real = ring.size() - 1;
   BOOST_REQUIRE_EQUAL( ring.size(), 16u ); // thin-pool ring target size

   // The migrated output carries value 990 (1000 - the migration fee).
   stealth_transfer_operation stop = T_r15_build_spend_of( core, ring, real,
      t.new_blind, 990, GRAPHENE_STEALTH_PROOF_V2, "r15-b5f-sp", 600, 380, 10 );
   trx.operations = { stop };
   {
      // Precondition pin: the spend rides the parity subsidy (paid fee 10
      // is far below the 1.500000 cost anchor for 2 outputs), so the pool
      // must be able to cover the gap at push time.
      share_type parity2 = db.current_fee_schedule().calculate_fee( operation( stop ) ).amount;
      BOOST_REQUIRE( stealth_parity_gap_core( db, 2, parity2, 2 ) > share_type( 0 ) );
      BOOST_REQUIRE( stealth_parity_available( db, core.get_id(),
         stealth_parity_gap_core( db, 2, parity2, 2 ) ) );
   }
   try {
      PUSH_TX( db, trx );
   } catch( const fc::exception& e ) {
      BOOST_FAIL( "migrated-output ring spend refused: " + e.to_detail_string() );
   }
   trx.operations.clear();
   generate_block();

   // Single spend: the migrated output stays indexed (ring spends remove
   // nothing; the nullifier set, not the index, records the spend).
   {
      const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
      auto ntr = bbi.find( t.new_output.commitment );
      BOOST_REQUIRE( ntr != bbi.end() );
   }
   // Fee-only supply movement across the spend, and the counter STILL
   // tracks the chain-derived truth through recovery + spend.
   BOOST_CHECK_EQUAL( t5_supply( db, core ), supply0 - 10 - 10 );
   BOOST_CHECK_EQUAL( counter(), true_depth() );
} FC_CAPTURE_AND_RETHROW() }

// B6 (owner divergence): new_output.owner != o.owner with a valid proof and
// old-authority signature is legitimate (owner-controlled re-key on
// migration — the signer satisfies the OLD authority, so divergence is a
// gift, not a theft; blind-transfer outputs have their own owners too). Pin
// the ACTUAL contract: the migrated balance's owner IS new_output.owner
// (exactly what do_apply stores), not the consumed balance's.
BOOST_AUTO_TEST_CASE( r15_new_output_owner_divergence_pins_migrated_owner )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan)(eve) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-b6", 16, true );
   const size_t s = 2;

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-b6-bn" );
   authority eve_owner( 1, public_key_type( eve_private_key.get_public_key() ), 1 );
   t.new_output.owner = eve_owner;
   // Task 4: the turnstile proves on every path — attach the true extension.
   // The proof is over the OLD commitment's opening, so the re-keyed
   // new_output.owner does not affect it.
   {
      fc::ecc::commitment_type I1, I2; std::vector<char> proof;
      T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
      T_set_recovery_v2( t, I1, I2, proof );
   }
   BOOST_REQUIRE( t.owner == p.owners[s] );        // OLD authority on the op
   BOOST_REQUIRE( t.new_output.owner == eve_owner ); // NEW authority on output
   BOOST_REQUIRE( t.owner != t.new_output.owner );  // divergence, by construction

   // Signed under the OLD authority (the old-authority leg is the gate).
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
   trx.clear_signatures(); trx.operations.clear();
   generate_block();

   const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
   BOOST_CHECK( bbi.find( p.commits[s] ) == bbi.end() ); // old consumed
   auto ntr = bbi.find( t.new_output.commitment );
   BOOST_REQUIRE( ntr != bbi.end() );
   // THE PIN: stored owner == new_output.owner (divergence persisted), and
   // explicitly != the consumed balance's owner.
   BOOST_CHECK( ntr->owner == eve_owner );
   BOOST_CHECK( ntr->owner == t.new_output.owner );
   BOOST_CHECK( ntr->owner != p.owners[s] );
} FC_CAPTURE_AND_RETHROW() }

// ---- op108 wire validation (Task 1) -------------------------------
// Pure wire-layer test: validate() never touches the database, so no
// fixture setup is needed. Use hardcoded account_ids — validate() only
// checks non-default `to`, never resolves accounts.
BOOST_AUTO_TEST_CASE( op108_validate_rejects_bad_shapes )
{
   stealth_explicit_spend_operation o;
   o.fee      = asset( 10*GRAPHENE_BLOCKCHAIN_PRECISION, asset_id_type() );
   o.asset_id = asset_id_type();           // core
   o.to       = account_id_type( 1 );      // non-default; not resolved in validate()
   o.amount   = asset( 1000, asset_id_type() );   // exit leg: amount is mandatory

   stealth_spend_input in;
   in.commitment    = T_commitment( T_commit( T_bn( T_blind_secret( "op108a" ) ), 1000 ) );
   in.owner         = authority( 1, account_id_type( 2 ), 1 );
   in.key_image_v1  = in.commitment;
   in.key_image_v2  = in.commitment;
   in.recovery_proof = stealth_recovery_proof( std::vector<char>( 163, 0 ) );
   o.inputs.push_back( in );
   o.outputs.clear();          // blind -> transparent leg

   // baseline: the shape itself is legal, so any throw below is the specific gate
   BOOST_REQUIRE_NO_THROW( o.validate() );

   o.amount.amount = 0;                    // exit with no value fails
   BOOST_REQUIRE_THROW( o.validate(), fc::assert_exception );
   o.amount.amount = 1000;

   o.amount.asset_id = asset_id_type( 1 );  // exit amount asset mismatch (core is 0)
   BOOST_REQUIRE_THROW( o.validate(), fc::assert_exception );
   o.amount.asset_id = asset_id_type();

   o.fee.amount = -1;
   BOOST_REQUIRE_THROW( o.validate(), fc::assert_exception );
   o.fee.amount = 10*GRAPHENE_BLOCKCHAIN_PRECISION;

   o.fee.asset_id = asset_id_type( 1 );   // mismatch vs asset_id (core is 0)
   BOOST_REQUIRE_THROW( o.validate(), fc::assert_exception );
   o.fee.asset_id = asset_id_type();

   o.inputs[0].recovery_proof = stealth_recovery_proof( std::vector<char>( 162, 0 ) );
   BOOST_REQUIRE_THROW( o.validate(), fc::assert_exception );   // proof != 163B
   o.inputs[0].recovery_proof = stealth_recovery_proof( std::vector<char>( 163, 0 ) );

   o.proof_version = 3;                   // unknown version fails closed
   BOOST_REQUIRE_THROW( o.validate(), fc::assert_exception );
   o.proof_version = GRAPHENE_STEALTH_PROOF_V2;

   o.inputs.clear();
   BOOST_REQUIRE_THROW( o.validate(), fc::assert_exception );   // >= 1 input
}

// ---- op108 evaluator (Task 2, nullifier migration) --------------------
// Helper: well-formed transparent-exit op108 over pool output s with the
// TRUE images and a real consensus-domain proof. amount + fee must equal
// the input value (p.each) for conservation to hold; excess is the input
// blind (single input, no outputs).
static stealth_explicit_spend_operation T_op108_exit_true( const asset_object& core,
      const t5_pool& p, size_t s, account_id_type to, int64_t amount, int64_t fee )
{
   stealth_explicit_spend_operation o;
   o.fee = core.amount( fee );
   o.asset_id = core.get_id();
   o.to = to;
   o.amount = core.amount( amount );
   o.proof_version = GRAPHENE_STEALTH_PROOF_V2;
   o.excess = p.blinds[s];
   stealth_spend_input in;
   in.commitment = p.commits[s];
   in.owner = p.owners[s];
   BIGNUM* bb = T_bn( p.blinds[s] );
   std::vector<unsigned char> Cvec( p.commits[s].begin(), p.commits[s].end() );
   std::vector<char> proof;
   T_prove_recovery( Cvec, bb, (uint64_t)p.each, core.get_id(),
                     in.key_image_v1, in.key_image_v2, proof );
   BN_free( bb );
   in.recovery_proof = stealth_recovery_proof( proof );
   o.inputs.push_back( in );
   return o;
}

// ---- op108 blind->blind over pool output s with the TRUE images ---------
// Single 1000-value input into two V2 outputs (600 + 390, fee 10); excess =
// b_in - b_o1 - b_o2 (mod n), mirroring the ring-spend excess pattern in
// t5_build_spend. Pins the blind->blind leg's stealth_verify_excess kernel
// (the Task-2 suite exercises only the exit leg).
static stealth_explicit_spend_operation T_op108_blind_true( const asset_object& core,
      const t5_pool& p, size_t s, const std::string& tag )
{
   stealth_explicit_spend_operation o;
   o.fee = core.amount( 10 );
   o.asset_id = core.get_id();
   o.proof_version = GRAPHENE_STEALTH_PROOF_V2;
   stealth_spend_input in;
   in.commitment = p.commits[s];
   in.owner = p.owners[s];
   BIGNUM* bb = T_bn( p.blinds[s] );
   std::vector<unsigned char> Cvec( p.commits[s].begin(), p.commits[s].end() );
   std::vector<char> proof;
   T_prove_recovery( Cvec, bb, (uint64_t)p.each, core.get_id(),
                     in.key_image_v1, in.key_image_v2, proof );
   BN_free( bb );
   in.recovery_proof = stealth_recovery_proof( proof );
   o.inputs.push_back( in );
   auto Bo1 = T_blind_secret( tag + "-o1" );
   auto Bo2 = T_blind_secret( tag + "-o2" );
   stealth_blind_output so1, so2;
   {
      BIGNUM* b1 = T_bn( Bo1 );
      so1.commitment = T_commitment( T_commit( b1, (uint64_t)600 ) );
      BN_free( b1 );
   }
   {
      BIGNUM* b2 = T_bn( Bo2 );
      so2.commitment = T_commitment( T_commit( b2, (uint64_t)390 ) );
      BN_free( b2 );
   }
   so1.range_proof = T_bp_prove( so1.commitment, Bo1, (uint64_t)600 );
   so2.range_proof = T_bp_prove( so2.commitment, Bo2, (uint64_t)390 );
   so1.owner = p.owners[s];
   so2.owner = p.owners[s];
   o.outputs = { so1, so2 };
   {
      BIGNUM* e = BN_new();
      BIGNUM* bi = T_bn( p.blinds[s] );
      BIGNUM* b1 = T_bn( Bo1 );
      BIGNUM* b2 = T_bn( Bo2 );
      BN_copy( e, bi );
      BN_mod_sub( e, e, b1, T_order(), T_ctx() );
      BN_mod_sub( e, e, b2, T_order(), T_ctx() );
      unsigned char eb[32]; BN_bn2binpad( e, eb, 32 );
      std::copy( eb, eb + 32, (char*)o.excess.data() );
      BN_free( e ); BN_free( bi ); BN_free( b1 ); BN_free( b2 );
   }
   return o;
}

// ---- op108 fabricated-image double spend (Task 2, spec §3.2a) ------
BOOST_AUTO_TEST_CASE( op108_rejects_fabricated_images_on_ring_spent_output )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "op108-dbl", 16, true );
   const size_t s = 3;

   // Genuine nullification of C's REAL images (both version legs) via the
   // real ring-spend path — not simulated.
   stealth_transfer_operation stop = t5_build_spend( core, p, s,
      GRAPHENE_STEALTH_PROOF_V2, "op108-dbl-sp", 600, 390, 10 );
   trx.operations = { stop };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();

   // Victim submits op108 on the ring-spent C with NEVER-nullified images:
   // the proof bytes are REAL (over the real I1/I2) but the carried images
   // are fabricated (C itself) — a spender who knows (b,v) supplying images
   // the proof does not bind to.
   stealth_explicit_spend_operation o = T_op108_exit_true( core, p, s, dan.get_id(), 990, 10 );
   o.inputs[0].key_image_v1 = p.commits[s]; // fabricated: never nullified
   o.inputs[0].key_image_v2 = p.commits[s]; // fabricated
   set_expiration( db, trx );
   trx.operations = { o };
   sign( trx, p.keys[s] );
   // Pin the refusal LAYER by message (proof gate 3a, not nullifier gate
   // 3b): a bare CHECK_THROW would pass on any-layer refusal.
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "fabricated-image explicit spend on a ring-spent output must be refused" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find(
         "Explicit spend recovery proof does not verify" ) != std::string::npos,
         e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
   // Refusal happened in do_evaluate before do_apply: no nullifier was
   // recorded for the fabricated images (linked through the single
   // production nullifier_key identity, never a duplicated hash).
   {
      const auto& nul = db.get_index_type<stealth_nullifier_index>()
                           .indices().get<by_nullifier_image>();
      const std::vector<char> fake( p.commits[s].begin(), p.commits[s].end() );
      BOOST_CHECK( nul.find( nullifier_key( fake ) ) == nul.end() );
   }
} FC_CAPTURE_AND_RETHROW() }

// ---- spec §6 item 14 (matched pair with 13): true images after ring spend ----
// Same sequence as op108_rejects_fabricated_images_on_ring_spent_output, but
// supplying C's TRUE images (unmodified T_op108_exit_true). Must pass the
// proof gate 3a and refuse at the nullifier gate 3b. Pins that the two gates
// are distinct (a fix rejecting every op108 on a ring participant would pass
// 13 while breaking legitimate spends; 14 pins the layer).
BOOST_AUTO_TEST_CASE( op108_true_images_after_ring_spend_refused_at_nullifier )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "op108-tn", 16, true );
   const size_t s = 3;

   // Genuine nullification via the real ring-spend path — not simulated.
   stealth_transfer_operation stop = t5_build_spend( core, p, s,
      GRAPHENE_STEALTH_PROOF_V2, "op108-tn-sp", 600, 390, 10 );
   trx.operations = { stop };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();

   const int64_t live = t5_supply( db, core );
   const asset before = db.get_balance( dan.get_id(), core.get_id() );

   // TRUE images, real proof — proof gate 3a passes, nullifier gate 3b refuses.
   stealth_explicit_spend_operation o = T_op108_exit_true( core, p, s, dan.get_id(), 990, 10 );
   set_expiration( db, trx );
   trx.operations = { o };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "true-image explicit spend on a ring-spent output must be refused at the nullifier" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find(
         "Explicit spend refused: V1 image nullified" ) != std::string::npos,
         e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
   // No state moves: balances/supply untouched, input still live (retained
   // for decoys, not removed by the ring spend; refusal precedes do_apply).
   BOOST_CHECK_EQUAL( db.get_balance( dan.get_id(), core.get_id() ).amount.value,
                      before.amount.value );
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live );
   const auto& bbi = db.get_index_type<blinded_balance_index>()
                        .indices().get<by_commitment>();
   BOOST_CHECK( bbi.find( p.commits[s] ) != bbi.end() );
} FC_CAPTURE_AND_RETHROW() }

// ---- transparent exit (spec §6 5a): honest exit succeeds --------------
BOOST_AUTO_TEST_CASE( op108_transparent_exit_succeeds_and_debits_pool )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "op108-xa", 4, false );
   const size_t s = 1;
   const int64_t live = t5_supply( db, core );
   const asset before = db.get_balance( dan.get_id(), core.get_id() );

   stealth_explicit_spend_operation o = T_op108_exit_true( core, p, s, dan.get_id(), 990, 10 );
   set_expiration( db, trx );
   trx.operations = { o };
   sign( trx, p.keys[s] );
   BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
   trx.clear_signatures(); trx.operations.clear();
   generate_block();

   // `to` credited exactly amount; blind pool debited amount + fee.
   BOOST_CHECK_EQUAL( db.get_balance( dan.get_id(), core.get_id() ).amount.value,
                      before.amount.value + 990 );
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live - 990 - 10 );
   const auto& bbi = db.get_index_type<blinded_balance_index>()
                        .indices().get<by_commitment>();
   BOOST_CHECK( bbi.find( p.commits[s] ) == bbi.end() ); // input consumed
} FC_CAPTURE_AND_RETHROW() }

// ---- transparent exit (spec §6 5b): inflation refused before apply ----
BOOST_AUTO_TEST_CASE( op108_transparent_exit_inflation_refused )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "op108-xb", 4, false );
   const size_t s = 2;
   const int64_t live = t5_supply( db, core );
   const asset before = db.get_balance( dan.get_id(), core.get_id() );

   // A 1000-value input cannot cover 1500 + 10: the verify_sum kernel in
   // do_evaluate must refuse. Proof/images are TRUE, so only the kernel
   // stands between this op and inflation.
   stealth_explicit_spend_operation o = T_op108_exit_true( core, p, s, dan.get_id(), 1500, 10 );
   set_expiration( db, trx );
   trx.operations = { o };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "inflated exit amount must be refused by the conservation kernel" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find(
         "Explicit spend conservation mismatch (exit leg)" ) != std::string::npos,
         e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
   // The kernel ran before do_apply: no balance moved, supply untouched,
   // input still live.
   BOOST_CHECK_EQUAL( db.get_balance( dan.get_id(), core.get_id() ).amount.value,
                      before.amount.value );
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live );
   const auto& bbi = db.get_index_type<blinded_balance_index>()
                        .indices().get<by_commitment>();
   BOOST_CHECK( bbi.find( p.commits[s] ) != bbi.end() );
} FC_CAPTURE_AND_RETHROW() }

// ---- blind→blind inflation refused (M-03): outputs exceed inputs ---------
// Single 1000-value input into two V2 outputs (800 + 390, fee 10): 1190 > 990
// net available. Range proofs are REAL (for the inflated values),
// images/proof are TRUE, so only the stealth_verify_excess kernel stands
// between this op and inflation. Must refuse with "Stealth conservation
// mismatch" (the blind→blind kernel, not the exit-leg verify_sum), with no
// state move.
BOOST_AUTO_TEST_CASE( op108_blind_inflation_refused )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "op108-xd", 4, false );
   const size_t s = 2;
   const int64_t live = t5_supply( db, core );
   const asset before = db.get_balance( dan.get_id(), core.get_id() );

   // Build inflated blind→blind: mirror T_op108_blind_true but with 800+390.
   stealth_explicit_spend_operation o;
   o.fee = core.amount( 10 );
   o.asset_id = core.get_id();
   o.proof_version = GRAPHENE_STEALTH_PROOF_V2;
   stealth_spend_input in;
   in.commitment = p.commits[s];
   in.owner = p.owners[s];
   BIGNUM* bb = T_bn( p.blinds[s] );
   std::vector<unsigned char> Cvec( p.commits[s].begin(), p.commits[s].end() );
   std::vector<char> proof;
   T_prove_recovery( Cvec, bb, (uint64_t)p.each, core.get_id(),
                     in.key_image_v1, in.key_image_v2, proof );
   BN_free( bb );
   in.recovery_proof = stealth_recovery_proof( proof );
   o.inputs.push_back( in );
   auto Bo1 = T_blind_secret( "op108-xd-o1" );
   auto Bo2 = T_blind_secret( "op108-xd-o2" );
   stealth_blind_output so1, so2;
   {
      BIGNUM* b1 = T_bn( Bo1 );
      so1.commitment = T_commitment( T_commit( b1, (uint64_t)800 ) );
      BN_free( b1 );
   }
   {
      BIGNUM* b2 = T_bn( Bo2 );
      so2.commitment = T_commitment( T_commit( b2, (uint64_t)390 ) );
      BN_free( b2 );
   }
   so1.range_proof = T_bp_prove( so1.commitment, Bo1, (uint64_t)800 );
   so2.range_proof = T_bp_prove( so2.commitment, Bo2, (uint64_t)390 );
   so1.owner = p.owners[s];
   so2.owner = p.owners[s];
   o.outputs = { so1, so2 };
   {
      BIGNUM* e = BN_new();
      BIGNUM* bi = T_bn( p.blinds[s] );
      BIGNUM* b1 = T_bn( Bo1 );
      BIGNUM* b2 = T_bn( Bo2 );
      BN_copy( e, bi );
      BN_mod_sub( e, e, b1, T_order(), T_ctx() );
      BN_mod_sub( e, e, b2, T_order(), T_ctx() );
      unsigned char eb[32]; BN_bn2binpad( e, eb, 32 );
      std::copy( eb, eb + 32, (char*)o.excess.data() );
      BN_free( e ); BN_free( bi ); BN_free( b1 ); BN_free( b2 );
   }
   set_expiration( db, trx );
   trx.operations = { o };
   sign( trx, p.keys[s] );
   try {
      PUSH_TX( db, trx );
      BOOST_FAIL( "inflated blind→blind amounts must be refused by stealth_verify_excess" );
   } catch( const fc::exception& e ) {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find(
         "Stealth conservation mismatch" ) != std::string::npos,
         e.to_detail_string() );
   }
   trx.clear_signatures(); trx.operations.clear();
   BOOST_CHECK_EQUAL( db.get_balance( dan.get_id(), core.get_id() ).amount.value,
                      before.amount.value );
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live );
   const auto& bbi = db.get_index_type<blinded_balance_index>()
                        .indices().get<by_commitment>();
   BOOST_CHECK( bbi.find( p.commits[s] ) != bbi.end() );
} FC_CAPTURE_AND_RETHROW() }

// ---- transparent exit (spec §6 5c): wrong-kernel tripwire -------------
// A WELL-FORMED exit must succeed here. If a future refactor unifies both
// legs onto stealth_verify_excess, the empty-outs trap at
// stealth_proof.cpp:759-760 ("io count out of bounds") fires and this test
// goes RED — telling the refactorer the exit leg needs verify_sum, not
// verify_excess. Same success path as 5a by design; the value is the name
// and this comment, so the failure reads as a kernel-routing regression
// rather than a conservation mystery.
BOOST_AUTO_TEST_CASE( op108_exit_never_uses_stealth_verify_excess )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "op108-xc", 4, false );
   const size_t s = 0;
   const asset before = db.get_balance( dan.get_id(), core.get_id() );

   stealth_explicit_spend_operation o = T_op108_exit_true( core, p, s, dan.get_id(), 990, 10 );
   set_expiration( db, trx );
   trx.operations = { o };
   sign( trx, p.keys[s] );
   BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
   trx.clear_signatures(); trx.operations.clear();
   BOOST_CHECK_EQUAL( db.get_balance( dan.get_id(), core.get_id() ).amount.value,
                      before.amount.value + 990 );
} FC_CAPTURE_AND_RETHROW() }

// ---- op108 proposal gating (spec §6 5d): pre-hardfork refusal ---------
BOOST_AUTO_TEST_CASE( op108_proposal_gated_before_hardfork )
{ try {
   // Fresh fixture is pre-STEALTH (no advance to the fork).
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   // (i) op108 embedded in a proposal is refused at the visitor. The op is
   // well-formed (passes proposal-time operation_validate) so the throw can
   // only come from the hardfork visitor, pinned by message.
   {
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      stealth_explicit_spend_operation o;
      o.fee = core.amount( 10 );
      o.asset_id = core.get_id();
      o.to = dan.get_id();
      o.amount = core.amount( 990 );
      stealth_spend_input in;
      in.commitment = T_commitment( T_commit( T_bn( T_blind_secret( "op108-p" ) ), 1000 ) );
      in.owner = authority( 1, dan.get_id(), 1 );
      in.key_image_v1 = in.commitment;
      in.key_image_v2 = in.commitment;
      in.recovery_proof = stealth_recovery_proof( std::vector<char>( 163, 0 ) );
      o.inputs.push_back( in );
      BOOST_REQUIRE_NO_THROW( o.validate() );
      cop.proposed_ops.emplace_back( o );
      trx.operations.push_back( cop );
      try {
         PUSH_TX( db, trx, ~0 );
         BOOST_FAIL( "pre-hardfork proposal embedding op108 must be refused" );
      } catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "Not allowed until the stealth hardfork" ) != std::string::npos,
            e.to_detail_string() );
      }
      trx.clear();
   }
   // (ii) a current_fees entry naming op108 is refused pre-hardfork. The
   // schedule names ONLY op108, so the throw pins this op's gate rather
   // than an earlier overload's.
   {
      proposal_create_operation cop = proposal_create_operation::committee_proposal(
            db.get_global_properties().parameters, db.head_block_time() );
      cop.fee_paying_account = GRAPHENE_TEMP_ACCOUNT;
      committee_member_update_global_parameters_operation cmuop;
      cmuop.new_parameters = db.get_global_properties().parameters;
      fee_schedule fs;
      fs.parameters.insert( stealth_explicit_spend_operation::fee_params_t() );
      cmuop.new_parameters.current_fees = std::make_shared<fee_schedule>( fs );
      cop.proposed_ops.emplace_back( cmuop );
      trx.operations.push_back( cop );
      try {
         PUSH_TX( db, trx, ~0 );
         BOOST_FAIL( "pre-hardfork fee schedule naming op108 must be refused" );
      } catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "stealth explicit spend" ) != std::string::npos,
            e.to_detail_string() );
      }
      trx.clear();
   }
} FC_CAPTURE_AND_RETHROW() }

// ---- flag retirement (Task 3, spec §6 items 1+12) ----------------------
// Under the old flag, an output used as a ring decoy was permanently
// unspendable on every leg. After retirement it must still be spendable by
// its owner via op108 (blind->blind leg: the Task-2 suite covers only the
// exit leg), and must still be decoy-eligible (reusable in a later ring).
BOOST_AUTO_TEST_CASE( g1_decoyed_output_remains_spendable_after_flag_retirement )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "t3-decoy", 16, true );
   const size_t s = 5; // honest real input of the first ring
   const size_t d = 7; // decoy target: never the real input, never nullified
   const int64_t live = t5_supply( db, core );

   // Ring spend #1 (real s, d rides as a decoy). Only s's images nullify.
   stealth_transfer_operation stop1 = t5_build_spend( core, p, s,
      GRAPHENE_STEALTH_PROOF_V2, "t3-decoy-sp1", 600, 390, 10 );
   trx.operations = { stop1 };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   // Live-set counter: the ring removes nothing, two outputs join it.
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 18u );

   // Re-arm the subsidy path so spend #2 and the op108 leg reach their
   // gates (not the fee gate): the 16 funding deposits already consumed
   // ~16M of the 21M seed, and the three legs below need ~4.5M combined.
   transfer( account_id_type()(db), dan, core.amount( 1000000000 ) );
   generate_block();
   g1c_seed_pool( db, dan.get_id(), core, 10000000 );

   // Ring spend #2 over the SAME ring with a different real input: d is a
   // decoy again. Pre-retirement this refuses at the spent-membership gate
   // (every member was whole-ring flagged); post-retirement it succeeds.
   // NOTE: the real input here is r2, NOT d — d must stay un-nullified so
   // the op108 leg below proves owner-spendability (spending d as real here
   // would nullify it, and the op108 refusal would be a correct double-spend
   // guard, not the retirement property).
   const size_t r2 = 9;
   stealth_transfer_operation stop2 = t5_build_spend( core, p, r2,
      GRAPHENE_STEALTH_PROOF_V2, "t3-decoy-sp2", 600, 390, 10 );
   trx.operations = { stop2 };
   set_expiration( db, trx );
   BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
   trx.clear();
   generate_block();

   // Owner-spendability: d was a decoy twice, never nullified — op108
   // blind->blind with the true opening succeeds.
   stealth_explicit_spend_operation o = T_op108_blind_true( core, p, d, "t3-decoy-x" );
   set_expiration( db, trx );
   trx.operations = { o };
   sign( trx, p.keys[d] );
   BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
   trx.clear_signatures(); trx.operations.clear();
   generate_block();

   // Chain-derived truth: the counter equals the live metadata-bearing set.
   {
      uint32_t n = 0;
      const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
      for( const auto& b : bbi )
         if( b.asset_id == core.get_id() && b.created_block != 0 )
            ++n;
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      auto itr = st.unspent_blind_count.find( core.get_id() );
      BOOST_REQUIRE( itr != st.unspent_blind_count.end() );
      BOOST_CHECK_EQUAL( itr->second, n );
   }
   // Three blind fees left the pool: two ring spends + one explicit spend.
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live - 10 - 10 - 10 );
} FC_CAPTURE_AND_RETHROW() }

// ---- spec §6 item 4: grandfathered balances still spend via legacy legs -
// A balance with created_block == 0 (pre-fork/grandfathered) MUST still be
// spendable by op40 (blind_transfer) and op41 (transfer_from_blind) exactly
// as before: the new created_block gate must not brick the migration path.
BOOST_AUTO_TEST_CASE( g1_grandfathered_balance_still_spends_via_legacy_legs )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   transfer( account_id_type()(db), dan, core.amount( 500000000 ) );
   generate_block();
   // Legacy legs still settle parity subsidies post-fork (fee 10 carries a
   // full anchor gap), so seed the pool past both gaps before spending.
   g1c_seed_pool( db, dan.get_id(), core, 5000000 );
   auto k = fc::ecc::private_key::generate();
   authority own( 1, public_key_type( k.get_public_key() ), 1 );
   // Two post-fork deposits, sealed, then grandfathered below:
   // created_block == 0, never counted — exactly what a pre-fork balance
   // looks like.
   std::vector<fc::ecc::commitment_type> cs;
   std::vector<fc::sha256> bs;
   for( int i = 0; i < 2; ++i )
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 1000 );
      ttb.from = dan.id;
      blind_output bo;
      bo.owner = own;
      ttb.fee = core.amount( 1000000 ); // cost path: pool reserved for the legs
      auto B = T_blind_secret( std::string( "t3-gf-b|" ) + std::to_string( i ) );
      auto N = T_secret( std::string( "t3-gf-n|" ) + std::to_string( i ) );
      bo.commitment = fc::ecc::blind( B, 1000 );
      bo.range_proof = fc::ecc::range_proof_sign( 0, bo.commitment, B, N, 0, 0, 1000 );
      ttb.blinding_factor = B;
      ttb.outputs = { bo };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      cs.push_back( bo.commitment );
      bs.push_back( B );
   }
   generate_block(); // seal BEFORE grandfathering (see T_grandfather note)
   // Grandfather the sealed deposits: created_block == 0, never counted —
   // exactly what a pre-fork balance looks like.
   for( const auto& c : cs )
      T_grandfather( db, core.get_id(), c );
   // (a) op40 blind_transfer on a grandfathered balance (1000 -> 990 under
   // the same blind + fee 10, real V1 range proof).
   {
      blind_transfer_operation btx;
      btx.fee = core.amount( 10 );
      blind_input bi; bi.commitment = cs[0]; bi.owner = own;
      btx.inputs = { bi };
      blind_output bo;
      bo.owner = own;
      auto N = T_secret( "t3-gf-nout" );
      bo.commitment = fc::ecc::blind( bs[0], 990 );
      bo.range_proof = fc::ecc::range_proof_sign( 0, bo.commitment, bs[0], N, 0, 0, 990 );
      btx.outputs = { bo };
      BOOST_CHECK_NO_THROW( btx.validate() );
      set_expiration( db, trx );
      trx.operations = { btx };
      sign( trx, k );
      BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
      trx.clear_signatures(); trx.operations.clear();
   }
   // (b) op41 transfer_from_blind on a grandfathered balance (990 + 10).
   {
      transfer_from_blind_operation x;
      x.to = dan.id;
      x.amount = core.amount( 990 );
      x.fee = core.amount( 10 );
      blind_input bi; bi.commitment = cs[1]; bi.owner = own;
      x.inputs = { bi };
      x.blinding_factor = bs[1];
      BOOST_CHECK_NO_THROW( x.validate() );
      set_expiration( db, trx );
      trx.operations = { x };
      sign( trx, k );
      BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
      trx.clear_signatures(); trx.operations.clear();
   }
   generate_block();
} FC_CAPTURE_AND_RETHROW() }

// ---- spec §6 item 5: post-fork balances refuse the legacy legs ---------
// A balance with created_block != 0 (post-fork) MUST be refused by op40 AND
// op41 with the new message, routing the spender to op108.
BOOST_AUTO_TEST_CASE( g1_postfork_balance_refuses_legacy_legs )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   transfer( account_id_type()(db), dan, core.amount( 500000000 ) );
   generate_block();
   g1c_seed_pool( db, dan.get_id(), core, 5000000 );
   auto k = fc::ecc::private_key::generate();
   authority own( 1, public_key_type( k.get_public_key() ), 1 );
   // One post-fork deposit (created_block != 0, counted — NOT grandfathered).
   fc::ecc::commitment_type c;
   fc::sha256 B;
   {
      transfer_to_blind_operation ttb;
      ttb.amount = core.amount( 1000 );
      ttb.from = dan.id;
      blind_output bo;
      bo.owner = own;
      ttb.fee = core.amount( 1000000 );
      B = T_blind_secret( "t3-pf-b" );
      auto N = T_secret( "t3-pf-n" );
      bo.commitment = fc::ecc::blind( B, 1000 );
      bo.range_proof = fc::ecc::range_proof_sign( 0, bo.commitment, B, N, 0, 0, 1000 );
      ttb.blinding_factor = B;
      ttb.outputs = { bo };
      set_expiration( db, trx );
      trx.operations = { ttb };
      sign( trx, dan_private_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      c = bo.commitment;
   }
   generate_block();
   // (a) op40 refuses with the new message (not the old spent-flag one).
   {
      blind_transfer_operation btx;
      btx.fee = core.amount( 10 );
      blind_input bi; bi.commitment = c; bi.owner = own;
      btx.inputs = { bi };
      blind_output bo;
      bo.owner = own;
      auto N = T_secret( "t3-pf-nout" );
      bo.commitment = fc::ecc::blind( B, 990 );
      bo.range_proof = fc::ecc::range_proof_sign( 0, bo.commitment, B, N, 0, 0, 990 );
      btx.outputs = { bo };
      BOOST_CHECK_NO_THROW( btx.validate() );
      set_expiration( db, trx );
      trx.operations = { btx };
      sign( trx, k );
      try {
         PUSH_TX( db, trx );
         BOOST_FAIL( "post-fork op40 spend must be routed to stealth_explicit_spend" );
      } catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "stealth_explicit_spend" )
                              != std::string::npos, e.to_detail_string() );
      }
      trx.clear_signatures(); trx.operations.clear();
   }
   // (b) op41 refuses with the new message.
   {
      transfer_from_blind_operation x;
      x.to = dan.id;
      x.amount = core.amount( 990 );
      x.fee = core.amount( 10 );
      blind_input bi; bi.commitment = c; bi.owner = own;
      x.inputs = { bi };
      x.blinding_factor = B;
      BOOST_CHECK_NO_THROW( x.validate() );
      set_expiration( db, trx );
      trx.operations = { x };
      sign( trx, k );
      try {
         PUSH_TX( db, trx );
         BOOST_FAIL( "post-fork op41 spend must be routed to stealth_explicit_spend" );
      } catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "stealth_explicit_spend" )
                              != std::string::npos, e.to_detail_string() );
      }
      trx.clear_signatures(); trx.operations.clear();
   }
} FC_CAPTURE_AND_RETHROW() }

namespace {

// ---- G2 (stealth pool swaps) test-side helpers (TEST-ONLY provers) ----
// Style mirrors T_prove_ring: deterministic labels, explicit byte ops, no
// randomness. Wallets reimplement proving from the verifier spec in
// stealth_proof.hpp; consensus never proves.

/// Canonical-minimal ULEB128 encode of a uint64 (the G2VP/G2RM pool field).
/// Independent reimplementation of the header-documented encoding (the
/// production encoder lives in stealth_proof.cpp and is never shared here,
// so a shared bug cannot mask itself).
std::string T_uleb128( uint64_t v )
{
   std::string out;
   do {
      unsigned char b = (unsigned char)( v & 0x7f );
      v >>= 7;
      if( v ) b |= 0x80;
      out.push_back( (char)b );
   } while( v );
   return out;
}

/// Fixed-width little-endian 64-bit encode (amount/min/F/n/m fields).
std::string T_le64( uint64_t v )
{
   std::string out;
   for( int i = 0; i < 8; ++i ) out.push_back( (char)( v >> (8*i) ) );
   return out;
}

/// Test-side G2VP challenge e = H("G2VP" || P || amount LE64 || pool ULEB128
/// || T), parsed mod n (scalar_from_sha semantics). Built from the
/// header-documented encoding with explicit byte ops only.
BIGNUM* T_g2vp_challenge( const fc::ecc::commitment_type& P, int64_t amount,
                          uint64_t pool, const std::vector<unsigned char>& T33 )
{
   BOOST_REQUIRE( T33.size() == 33 );
   std::string pre = "G2VP";
   pre.append( (const char*)P.data(), 33 );
   pre.append( T_le64( (uint64_t)amount ) );
   pre.append( T_uleb128( pool ) );
   pre.append( (const char*)T33.data(), 33 );
   fc::sha256 h = fc::sha256::hash( pre.data(), pre.size() );
   return T_bn( h );
}

/// Test-side Schnorr value-pin prover: given P = amount*H + b_P*G, produce
/// (T, s) with T = k*G, s = k + e*b_P mod n. Deterministic k from a label.
void T_prove_value_pin( const fc::ecc::commitment_type& P, int64_t amount,
                        uint64_t pool, const BIGNUM* b_P,
                        std::vector<char>& T_out /*33B*/,
                        std::string& s_out /*32B*/ )
{
   BIGNUM* k = T_scalar( "g2-pin-k|" + std::to_string( amount )
                         + "|" + std::to_string( pool ) );
   BOOST_REQUIRE( !BN_is_zero( k ) );
   EC_POINT* Tp = EC_POINT_new( T_group() );
   BOOST_REQUIRE( EC_POINT_mul( (EC_GROUP*)T_group(), Tp, k,
                               nullptr, nullptr, T_ctx() ) == 1 );
   std::vector<unsigned char> T33 = T_compress( Tp );
   BIGNUM* e = T_g2vp_challenge( P, amount, pool, T33 );
   BIGNUM* s = BN_new();
   BN_mod_mul( s, e, b_P, T_order(), T_ctx() );
   BN_mod_add( s, s, k, T_order(), T_ctx() );
   T_out.assign( T33.begin(), T33.end() );
   unsigned char buf[32];
   BOOST_REQUIRE( BN_bn2binpad( s, buf, 32 ) == 32 );
   s_out.assign( (char*)buf, 32 );
   BN_free( k ); BN_free( e ); BN_free( s );
   EC_POINT_free( Tp );
}

/// Deterministic synthetic commitment for G2RM partition searches (the ring
/// message never validates points, so any distinct 33B values do; real
/// on-curve commitments keep the vectors honest).
fc::ecc::commitment_type T_g2mk( int seed )
{
   return T_commitment( T_commit( T_scalar( "g2rm-c|" + std::to_string( seed ) ),
                                 (uint64_t)( 1000 + seed ) ) );
}

std::vector<char> T_g2img()
{
   auto v = T_commit( T_scalar( "g2rm-img" ), 7 );
   return std::vector<char>( v.begin(), v.end() );
}

} // namespace

BOOST_AUTO_TEST_CASE( value_pin_happy_path )
{ try {
   // P = a*H + b_P*G for known (a, b_P); test-side prover builds (T, s);
   // the verifier must accept.
   const int64_t amount = 5000;
   const uint64_t pool = 7;
   BIGNUM* b_P = T_bn( T_blind_secret( "g2-pin-b" ) );
   fc::ecc::commitment_type P = T_commitment( T_commit( b_P, (uint64_t)amount ) );
   std::vector<char> T33;
   std::string s32;
   T_prove_value_pin( P, amount, pool, b_P, T33, s32 );
   BOOST_REQUIRE_EQUAL( T33.size(), 33u );
   BOOST_REQUIRE_EQUAL( s32.size(), 32u );
   std::string err;
   BOOST_CHECK_MESSAGE( stealth_verify_value_pin( P, amount, pool, T33, s32, err ), err );
   BN_free( b_P );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( value_pin_rejects_substituted_P )
{ try {
   // (T, s) proven for P must fail for a different P' committing to the
   // SAME amount under a different blind (Lemma 1 binding note).
   const int64_t amount = 5000;
   const uint64_t pool = 7;
   BIGNUM* b_P = T_bn( T_blind_secret( "g2-pin-b" ) );
   fc::ecc::commitment_type P = T_commitment( T_commit( b_P, (uint64_t)amount ) );
   std::vector<char> T33;
   std::string s32;
   T_prove_value_pin( P, amount, pool, b_P, T33, s32 );
   BIGNUM* b2 = T_bn( T_blind_secret( "g2-pin-b-other" ) );
   fc::ecc::commitment_type P2 = T_commitment( T_commit( b2, (uint64_t)amount ) );
   BOOST_REQUIRE( P2 != P );
   std::string err;
   BOOST_CHECK_MESSAGE( !stealth_verify_value_pin( P2, amount, pool, T33, s32, err ),
                        "substituted P accepted" );
   BN_free( b_P ); BN_free( b2 );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( value_pin_rejects_substituted_amount )
{ try {
   // Same P and (T, s), claimed amount off by one in either direction.
   const int64_t amount = 5000;
   const uint64_t pool = 7;
   BIGNUM* b_P = T_bn( T_blind_secret( "g2-pin-b" ) );
   fc::ecc::commitment_type P = T_commitment( T_commit( b_P, (uint64_t)amount ) );
   std::vector<char> T33;
   std::string s32;
   T_prove_value_pin( P, amount, pool, b_P, T33, s32 );
   std::string err;
   BOOST_CHECK_MESSAGE( !stealth_verify_value_pin( P, amount + 1, pool, T33, s32, err ),
                        "overstated amount accepted" );
   BOOST_CHECK_MESSAGE( !stealth_verify_value_pin( P, amount - 1, pool, T33, s32, err ),
                        "understated amount accepted" );
   BN_free( b_P );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( value_pin_rejects_substituted_pool )
{ try {
   // Same P, amount, and (T, s) replayed against a different pool id.
   const int64_t amount = 5000;
   const uint64_t pool = 7;
   BIGNUM* b_P = T_bn( T_blind_secret( "g2-pin-b" ) );
   fc::ecc::commitment_type P = T_commitment( T_commit( b_P, (uint64_t)amount ) );
   std::vector<char> T33;
   std::string s32;
   T_prove_value_pin( P, amount, pool, b_P, T33, s32 );
   std::string err;
   BOOST_CHECK_MESSAGE( !stealth_verify_value_pin( P, amount, pool + 1, T33, s32, err ),
                        "cross-pool replay accepted" );
   BOOST_CHECK_MESSAGE( !stealth_verify_value_pin( P, amount, pool + 300, T33, s32, err ),
                        "cross-pool replay (varint-width change) accepted" );
   BN_free( b_P );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( value_pin_rejects_malformed )
{ try {
   // Interface-1 fail-closed gates: non-positive amount, wrong-size T/s,
   // non-canonical s. A canonical-but-wrong s must still fail the equation.
   const int64_t amount = 5000;
   const uint64_t pool = 7;
   BIGNUM* b_P = T_bn( T_blind_secret( "g2-pin-b" ) );
   fc::ecc::commitment_type P = T_commitment( T_commit( b_P, (uint64_t)amount ) );
   std::vector<char> T33;
   std::string s32;
   T_prove_value_pin( P, amount, pool, b_P, T33, s32 );
   std::string err;
   BOOST_CHECK( !stealth_verify_value_pin( P, 0, pool, T33, s32, err ) );
   BOOST_CHECK( !stealth_verify_value_pin( P, -5, pool, T33, s32, err ) );
   BOOST_CHECK( !stealth_verify_value_pin( P, amount, pool,
                                           std::vector<char>( T33.begin(), T33.begin() + 32 ),
                                           s32, err ) );
   BOOST_CHECK( !stealth_verify_value_pin( P, amount, pool,
                                           std::vector<char>(), s32, err ) );
   BOOST_CHECK( !stealth_verify_value_pin( P, amount, pool, T33,
                                           s32.substr( 0, 31 ), err ) );
   // Non-canonical s (all 0xFF > curve order): strict-parse refusal.
   BOOST_CHECK( !stealth_verify_value_pin( P, amount, pool, T33,
                                           std::string( 32, (char)0xff ), err ) );
   // Canonical-but-wrong s (all zeros): parse passes, equation must fail.
   BOOST_CHECK( !stealth_verify_value_pin( P, amount, pool, T33,
                                           std::string( 32, '\0' ), err ) );
   BN_free( b_P );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( g2rm_repartition_search )
{ try {
   // F-03 closure method (overlay §4b; tooling/g1rm_preimage_probe.cpp §E):
   // exhaustive re-partition search over every full-consumption split of a
   // shared K-commitment byte run (ring[0..n), pseudo=run[n],
   // outputs=run[n+1..]) for K=2..8, crossed with pool-varint widths
   // (1..10 bytes) and single-field (amount, min, F) flips. Distinct
   // (pool, amount, min, ring, pseudo, outputs, F) tuples must never share
   // a G2RM hash: 0 collisions.
   const uint8_t ver = GRAPHENE_STEALTH_PROOF_V2;
   const asset_id_type asset;
   const std::vector<char> img = T_g2img();
   // Pool probes span every ULEB128 width 1..10 bytes (boundary values).
   const uint64_t pools[] = { 0, 1, 7, 127, 128, 300, 16383, 16384,
      2097151, 268435455, 4294967295ULL, 4294967296ULL, 1099511627776ULL,
      0xFFFFFFFFFFFFFFFFULL };
   const int64_t amounts[] = { 1000, 1001 };
   const int64_t mins[] = { 900, 901 };
   const int64_t Fs[] = { 100, 101 };
   size_t total = 0;
   for( int K = 2; K <= 8; ++K )
   {
      std::vector<fc::ecc::commitment_type> run;
      for( int i = 0; i < K; ++i ) run.push_back( T_g2mk( i ) );
      std::map<std::string, std::string> seen;
      for( auto pool : pools )
         for( auto amount : amounts )
            for( auto min : mins )
               for( auto F : Fs )
                  for( int n = 0; n <= K - 1; ++n )
                  {
                     const int m = K - 1 - n;
                     const std::vector<fc::ecc::commitment_type> ring( run.begin(), run.begin() + n );
                     const fc::ecc::commitment_type pseudo = run[n];
                     const std::vector<fc::ecc::commitment_type> outs( run.begin() + n + 1, run.end() );
                     BOOST_REQUIRE_EQUAL( (int)outs.size(), m );
                     const fc::sha256 h = stealth_pool_message( ver, asset, pool, amount,
                                                                min, img, ring, pseudo, outs, F );
                     const std::string key( h.data(), 32 );
                     std::ostringstream tag;
                     tag << "(K=" << K << ",pool=" << pool << ",amt=" << amount
                         << ",min=" << min << ",F=" << F << ",n=" << n << ",m=" << m << ")";
                     auto ins = seen.emplace( key, tag.str() );
                     BOOST_REQUIRE_MESSAGE( ins.second,
                        "G2RM collision: " << ins.first->second << " vs " << tag.str() );
                     ++total;
                  }
   }
   // Pins exhaustiveness: sum_{K=2..8}(K) partitions x 14 pools x 2^3 flips.
   BOOST_REQUIRE_EQUAL( total, (size_t)( 35 * 14 * 8 ) );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( g2rm_field_binding )
{ try {
   // Every bound field is load-bearing: flipping exactly one of version,
   // asset, pool, amount, min, image, ring, pseudo, outputs, F changes the
   // message. The same tuple twice agrees (determinism). G2RM never equals
   // G1RM for the same content (domain separation; G1 bytes untouched).
   const uint8_t ver = GRAPHENE_STEALTH_PROOF_V2;
   const asset_id_type asset;
   const uint64_t pool = 7;
   const int64_t amount = 1000, min = 900, F = 100;
   const std::vector<char> img = T_g2img();
   const std::vector<fc::ecc::commitment_type> ring = { T_g2mk( 0 ), T_g2mk( 1 ) };
   const fc::ecc::commitment_type pseudo = T_g2mk( 2 );
   const std::vector<fc::ecc::commitment_type> outs = { T_g2mk( 3 ) };
   const fc::sha256 base = stealth_pool_message( ver, asset, pool, amount, min,
                                                 img, ring, pseudo, outs, F );
   BOOST_REQUIRE_EQUAL( stealth_pool_message( ver, asset, pool, amount, min,
                                              img, ring, pseudo, outs, F ), base );
   BOOST_CHECK( stealth_pool_message( GRAPHENE_STEALTH_PROOF_V1, asset, pool, amount,
                                      min, img, ring, pseudo, outs, F ) != base );
   BOOST_CHECK( stealth_pool_message( ver, asset_id_type( 1 ), pool, amount,
                                      min, img, ring, pseudo, outs, F ) != base );
   BOOST_CHECK( stealth_pool_message( ver, asset, pool + 1, amount,
                                      min, img, ring, pseudo, outs, F ) != base );
   BOOST_CHECK( stealth_pool_message( ver, asset, pool, amount + 1,
                                      min, img, ring, pseudo, outs, F ) != base );
   BOOST_CHECK( stealth_pool_message( ver, asset, pool, amount, min + 1,
                                      img, ring, pseudo, outs, F ) != base );
   BOOST_CHECK( stealth_pool_message( ver, asset, pool, amount,
                                      min, img, ring, pseudo, outs, F + 1 ) != base );
   std::vector<char> img2 = img; img2[0] ^= 0x01;
   BOOST_CHECK( stealth_pool_message( ver, asset, pool, amount,
                                      min, img2, ring, pseudo, outs, F ) != base );
   const std::vector<fc::ecc::commitment_type> ring2 = { T_g2mk( 0 ), T_g2mk( 4 ) };
   BOOST_CHECK( stealth_pool_message( ver, asset, pool, amount,
                                      min, img, ring2, pseudo, outs, F ) != base );
   BOOST_CHECK( stealth_pool_message( ver, asset, pool, amount,
                                      min, img, ring, T_g2mk( 4 ), outs, F ) != base );
   const std::vector<fc::ecc::commitment_type> outs2 = { T_g2mk( 4 ) };
   BOOST_CHECK( stealth_pool_message( ver, asset, pool, amount,
                                      min, img, ring, pseudo, outs2, F ) != base );
   // G1RM over the same content (fee carries F) differs by domain alone.
   const share_type g1fee( F );
   BOOST_CHECK_MESSAGE(
      stealth_ring_message( ver, asset, img, ring, pseudo, outs, g1fee ) != base,
      "G2RM must never equal G1RM" );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( g2rm_work_exceeds_transfer )
{ try {
   // A G2 swap costs strictly more than a same-ring G1 transfer (design §7:
   // ring + 2xBP + kernel + pool math): dual-verified ring legs, the
   // Schnorr-pin kernel allowance, 2x range allowance (output BP+ m=1 +
   // conceptual pin cost), plus the pool-math leg.
   const uint32_t n = 16;
   stealth_transfer_operation small;
   small.inputs.resize( 1 ); small.inputs[0].ring.resize( n );
   small.outputs.resize( 1 );
   const uint32_t tx = stealth_work_for_stealth_transfer( small );
   const uint32_t g2 = stealth_work_for_pool_exchange( n );
   BOOST_CHECK_MESSAGE( g2 > tx, "G2 work " << g2 << " must exceed G1 work " << tx );
   // Exact model-arithmetic pin (single input leg, single output).
   BOOST_REQUIRE_EQUAL( g2, (uint32_t)( GRAPHENE_STEALTH_WORK_US_PER_KERNEL
      + 2u * n * GRAPHENE_STEALTH_WORK_US_PER_RING_MEMBER
      + 2u * GRAPHENE_STEALTH_WORK_US_PER_RANGE_PROOF
      + GRAPHENE_STEALTH_WORK_US_PER_POOL_MATH ) );
   // Saturation discipline (proposal-embedded unbounded ring_size —
   // saturate, never wrap, mirroring :334-347).
   BOOST_REQUIRE_EQUAL( stealth_work_for_pool_exchange( 0xFFFFFFFFu ), 0xFFFFFFFFu );
} FC_CAPTURE_AND_RETHROW() }

// ---- G2-2 (stealth pool swaps, op109): Step 1 tag/shape existence ----
// RED: stealth_pool_exchange_operation is undeclared (compile failure).
// After declaration: tag 109 pinned; pre-STEALTH push refused at the fork
// gate; post-STEALTH default-constructed op fails closed at validate()
// (relay-side pin layer: value_pin must be exactly 65 bytes).
BOOST_AUTO_TEST_CASE( poolswap_tag109_exists )
{ try {
   const int tag109 = operation::tag<stealth_pool_exchange_operation>::value;
   BOOST_CHECK_EQUAL( tag109, 109 );
   stealth_pool_exchange_operation op;
   // Default-constructed op fails closed at validate() (relay-side pin
   // layer: zero amounts / empty value_pin). The consensus pin-layer refusal
   // of a well-formed-but-unpinned op is covered post-fork below.
   BOOST_CHECK_THROW( op.validate(), fc::exception );
   // A relay-shape-valid op carries a 65-byte pin slot; truncation refuses.
   {
      stealth_pool_exchange_operation bad = op;
      bad.fee = asset( 10, asset_id_type() );
      bad.amount_to_sell = asset( 1000, asset_id_type() );
      bad.min_to_receive = asset( 900, asset_id_type() );
      for( int i = 0; i < 16; ++i )
      {
         std::vector<unsigned char> raw( 33, 0 );
         raw[32] = char( i + 1 );
         bad.input.ring.push_back( T_commitment( raw ) );
      }
      bad.input.key_image.assign( 33, 2 );
      bad.input.ring_sig.assign( 32 + 96 * 16, 0 );
      bad.input.alt_key_image.assign( 33, 3 );
      bad.input.alt_ring_sig.assign( 32 + 96 * 16, 0 );
      bad.output.range_proof.assign( 592, 0 );
      bad.output.owner = authority( 1, account_id_type( 1 ), 1 );
      bad.value_pin.assign( 64, 0 ); // one byte short of the 65-byte (T‖s) pin
      try
      {
         bad.validate();
         BOOST_FAIL( "64-byte value_pin must fail validate" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "value_pin" ) != std::string::npos,
                              e.to_detail_string() );
      }
   }
   // Pre-fork push refused at the consensus fork gate (not a shape check:
   // the default op would fail validate first on relay, so dispatch
   // directly to prove the evaluator's fork gate fires).
   {
      transaction_evaluation_state es( &db );
      try
      {
         db.apply_operation( es, operation( op ) );
         BOOST_FAIL( "pre-fork op109 was ACCEPTED" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "stealth hardfork" ) != std::string::npos,
                              e.to_detail_string() );
      }
   }
   // Post-fork, an asset-shape-valid op with a malformed pin fails closed
   // at the pin layer (field-bounds 65-byte gate, before any pool lookup).
   {
      generate_blocks( HARDFORK_STEALTH_TIME );
      generate_block();
      set_expiration( db, trx );
      const asset_object& core = asset_id_type()( db );
      stealth_pool_exchange_operation bad;
      bad.fee = core.amount( 10 );
      bad.amount_to_sell = core.amount( 1000 );
      bad.min_to_receive = core.amount( 900 );
      bad.value_pin.assign( 64, 0 ); // one byte short of the 65-byte (T‖s) pin
      transaction_evaluation_state es( &db );
      try
      {
         db.apply_operation( es, operation( bad ) );
         BOOST_FAIL( "post-fork malformed-pin op109 was ACCEPTED" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "value_pin" ) != std::string::npos,
                              e.to_detail_string() );
      }
      trx.clear();
   }
} FC_CAPTURE_AND_RETHROW() }

// ---- G2-2 pool-swap scaffold (additive; Task-3 hunks untouched) ----
// Two dan-issued UIAs (A = sold/blind input, B = bought/blind output) plus a
// share asset, one constant-product pool (1M/1M), and 16 aged A-blinds
// (4/4/4/4 skew windows + 25h age, mirroring t5_fund_pool's aged pattern so
// the TARGET-size ring satisfies the decoy policy and pool floor).
struct g2_pool
{
   asset_id_type            asset_a;
   asset_id_type            asset_b;
   liquidity_pool_id_type   pool;
   std::vector<fc::ecc::commitment_type> commits;
   std::vector<fc::sha256>               blinds;
   int64_t                               each = 1000;
};

// each = per-blind-output value (default 1000, the historical fixture size).
// A caller that has to compare a routed MARKET FEE against the ~1e6-unit cost
// anchor (the burn-rate ratio) needs a bigger output; the issuance below is
// sized off it so the funder always covers 16 outputs + the pool deposit +
// the fee pool (24,984,000 of slack at the default, which is exactly the 25M
// this helper used to issue).
static g2_pool g2_fund_pool( database_fixture& f, const account_object& funder,
      const fc::ecc::private_key& funder_key, const std::string& tag,
      uint16_t market_fee_percent, int64_t each = 1000 )
{
   database& db = f.db;
   signed_transaction& trx = f.trx;
   const price cer = price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) );
   // NOTE: keep narrow ID VALUES, never long-lived object refs — refs into
   // the index dangle across generate_block (the checked get_id conversion
   // then throws "space or type mismatch"); re-resolve via id(db) instead.
   const asset_id_type aid_a = f.create_user_issued_asset( tag + "A", funder,
      charge_market_fee, cer, 2, market_fee_percent ).get_id();
   const asset_id_type aid_b = f.create_user_issued_asset( tag + "B", funder,
      charge_market_fee, cer, 2, market_fee_percent ).get_id();
   const asset_id_type sid = f.create_user_issued_asset( tag + "S", funder,
      charge_market_fee, cer, 2, 0 ).get_id();
   // Pool + deposit pre-date the blinds (no aging needed for reserves).
   const liquidity_pool_id_type pool_id = f.create_liquidity_pool( funder.get_id(),
      aid_a, aid_b, sid, 0, 0 ).get_id();
   // 25M of A (not 3M) at the default `each`: EE-1's Rule R puts op109's
   // 1-output subsidy gap at anchor(1) = 10 BTS = 1,000,000 units of A, and
   // T_seed_pool_uia funds parity_pool[A] through the REAL 5%-share market-fee
   // routing, so the payer must spend 20x the gap (20,020,000) plus 1M to the
   // pool and 1M to the fee pool — 3M leaves nothing. The extra is inert: it
   // sits on the funder's balance and never enters the pool reserves the cases
   // assert. Scaled by `each` so a caller with bigger outputs still funds all
   // 16 of them.
   f.issue_uia( funder, asset( 16 * each + 24984000, aid_a ) );
   f.issue_uia( funder, asset( 3000000, aid_b ) );
   f.deposit_to_liquidity_pool( funder.get_id(), pool_id,
      asset( 1000000, aid_a ), asset( 1000000, aid_b ) );
   // UIA tx fees convert through the fee pool (prepare_fee): fund A's pool
   // (fee.asset_id == sold asset by consensus). 10 CORE covers the 1-sat
   // conversions of every swap below.
   f.fund_fee_pool( funder, aid_a( db ), 1000000 );
   f.generate_block();
   // Seed on SEALED state (db_block.cpp:423 pattern): generate_block resets
   // pending state, wiping direct modifies — seeding before it (as first
   // attempted) is silently discarded. Blind funding runs subsidized
   // (transfer_to_blind carries a 0 fee — t5_fund_pool discipline); G2 swaps
   // themselves need no subsidy (no parity consume call).
   g1c_seed_pool( db, funder.get_id(), asset_id_type()( db ), 16 * 1000000 + 5000000 );
   g2_pool p;
   p.asset_a = aid_a;
   p.asset_b = aid_b;
   p.pool = pool_id;
   p.each = each;
   auto fund_one = [&]( int i ) {
      transfer_to_blind_operation ttb;
      ttb.amount = asset( p.each, p.asset_a );
      ttb.from = funder.id;
      auto k = fc::ecc::private_key::generate();
      blind_output o;
      o.owner = authority( 1, public_key_type( k.get_public_key() ), 1 );
      auto B = T_blind_secret( tag + "-b|" + std::to_string( i ) );
      auto N = T_secret( tag + "-n|" + std::to_string( i ) );
      o.commitment = fc::ecc::blind( B, p.each );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B, N, 0, 0, p.each );
      ttb.blinding_factor = B;
      ttb.outputs = { o };
      set_expiration( db, trx );
      trx.operations = { ttb };
      f.sign( trx, funder_key );
      PUSH_TX( db, trx ); trx.clear_signatures(); trx.operations.clear();
      p.commits.push_back( o.commitment );
      p.blinds.push_back( B );
   };
   for( int i = 0; i < 4; ++i ) { fund_one( i ); f.generate_block(); }
   f.generate_blocks( 110 );
   for( int i = 4; i < 8; ++i ) { fund_one( i ); f.generate_block(); }
   f.generate_blocks( 110 );
   for( int i = 8; i < 12; ++i ) { fund_one( i ); f.generate_block(); }
   f.generate_blocks( 110 );
   for( int i = 12; i < 16; ++i ) { fund_one( i ); f.generate_block(); }
   f.generate_blocks( db.head_block_time() + 90000 ); // +25h: decoys old
   f.generate_block();
   set_expiration( db, trx );
   return p;
}

// Honest 1-in/1-out G2 swap of pool output s (value p.each) into one V2 BP+
// counter-asset output. The tx fee is COMPUTED, not chosen: the kernel pins
// v_out = a − F (Lemma 3) and the pool pins v_out = pool_pays − f_taker
// (Lemma 4), so f_tx = a − f_maker − pool_pays exactly (slippage cover).
// min_to_receive = v_out − discount (a floor only: pool math is
// min-independent, asserted below).
struct g2_swap
{
   stealth_pool_exchange_operation op;
   pool_exchange_amounts expect;
   int64_t f_tx = 0;
   int64_t F = 0;
   int64_t v_out = 0;
};

static g2_swap g2_build_swap( database& db, const g2_pool& p, size_t s,
      uint8_t version, const std::string& tag, int64_t min_discount )
{
   const uint8_t alt_v = ( version == GRAPHENE_STEALTH_PROOF_V1 )
                         ? GRAPHENE_STEALTH_PROOF_V2
                         : GRAPHENE_STEALTH_PROOF_V1;
   const liquidity_pool_object& pool = p.pool( db );
   const asset sell( p.each, p.asset_a );
   // Probe with a dust floor to learn the min-independent payout, then build
   // the real floor below it.
   pool_exchange_amounts probe = calculate_pool_exchange_amounts( db, pool,
      sell, asset( 1, p.asset_b ) );
   const int64_t v = probe.account_receives.amount.value;
   const int64_t minv = v - min_discount;
   BOOST_REQUIRE( minv > 0 );
   pool_exchange_amounts ex = calculate_pool_exchange_amounts( db, pool,
      sell, asset( minv, p.asset_b ) );
   BOOST_REQUIRE_EQUAL( ex.account_receives.amount.value, v ); // min is a floor only
   const int64_t f_maker = ex.maker_market_fee.amount.value;
   const int64_t f_taker = ex.taker_market_fee.amount.value;
   const int64_t pool_pays = ex.pool_pays.amount.value;
   const int64_t f_tx = p.each - f_maker - pool_pays;
   BOOST_REQUIRE_MESSAGE( f_tx >= 0, "slippage exceeds input (pool too thin for fees)" );
   const int64_t F = f_maker + f_taker + f_tx;
   BOOST_REQUIRE_EQUAL( v, p.each - F ); // Lemmas 3+4 agree by construction

   BIGNUM* bs = T_bn( p.blinds[s] );
   BIGNUM* bprime = T_bn( T_blind_secret( tag + "-pseudo" ) );
   auto Bout = T_blind_secret( tag + "-o" );
   fc::ecc::commitment_type Cout;
   {
      BIGNUM* bo = T_bn( Bout );
      auto Cv = T_commit( bo, (uint64_t)v );
      BN_free( bo );
      std::copy( Cv.begin(), Cv.end(), Cout.begin() );
   }
   stealth_blind_output sout;
   sout.commitment = Cout;
   sout.range_proof = T_bp_prove( Cout, Bout, (uint64_t)v );
   BOOST_REQUIRE_EQUAL( sout.range_proof.size(), 592u );
   auto rk = fc::ecc::private_key::generate();
   sout.owner = authority( 1, public_key_type( rk.get_public_key() ), 1 );

   fc::ecc::commitment_type P;
   {
      auto Pv = T_commit( bprime, (uint64_t)p.each );
      std::copy( Pv.begin(), Pv.end(), P.begin() );
   }
   std::vector<char> T33;
   std::string s32;
   T_prove_value_pin( P, p.each, p.pool.instance.value, bprime, T33, s32 );
   BOOST_REQUIRE_EQUAL( T33.size(), 33u );
   BOOST_REQUIRE_EQUAL( s32.size(), 32u );

   std::vector<std::vector<unsigned char>> Q;
   for( const auto& c : p.commits )
      Q.push_back( std::vector<unsigned char>( c.begin(), c.end() ) );
   auto dry = T_dual_dry_run( version, alt_v, Q, s, bs, (uint64_t)p.each, bprime );
   {
      auto Pv = T_commit( bprime, (uint64_t)p.each );
      BOOST_REQUIRE( dry.pseudo == Pv );
   }
   std::vector<char> img_c( dry.img_main.begin(), dry.img_main.end() );
   std::vector<char> img_a( dry.img_alt.begin(), dry.img_alt.end() );
   std::vector<fc::ecc::commitment_type> out_cs = { Cout };
   fc::ecc::commitment_type Pc = T_commitment( dry.pseudo );
   fc::sha256 m = stealth_pool_message( version, p.asset_a, p.pool.instance.value,
      p.each, minv, img_c, p.commits, Pc, out_cs, F );
   fc::sha256 ma = stealth_pool_message( alt_v, p.asset_a, p.pool.instance.value,
      p.each, minv, img_a, p.commits, Pc, out_cs, F );
   std::string ms( (const char*)m.data(), 32 );
   std::string msa( (const char*)ma.data(), 32 );
   stealth_ring_input rin = T_make_dual_ring_input( version, alt_v, Q, s, bs,
      (uint64_t)p.each, bprime, ms, msa );

   g2_swap sw;
   sw.op.fee = asset( f_tx, p.asset_a );
   sw.op.pool = p.pool;
   sw.op.amount_to_sell = sell;
   sw.op.min_to_receive = asset( minv, p.asset_b );
   sw.op.proof_version = version;
   {
      BIGNUM* e = BN_new();
      BIGNUM* bo = T_bn( Bout );
      BN_copy( e, bprime );
      BN_mod_sub( e, e, bo, T_order(), T_ctx() );
      unsigned char eb[32]; BN_bn2binpad( e, eb, 32 );
      std::copy( eb, eb + 32, (char*)sw.op.excess.data() );
      BN_free( e ); BN_free( bo );
   }
   sw.op.input = rin;
   sw.op.output = sout;
   sw.op.value_pin.assign( T33.begin(), T33.end() );
   sw.op.value_pin.insert( sw.op.value_pin.end(), s32.begin(), s32.end() );
   BOOST_REQUIRE_EQUAL( sw.op.value_pin.size(), 65u );
   sw.expect = ex;
   sw.f_tx = f_tx;
   sw.F = F;
   sw.v_out = v;
   BN_free( bs ); BN_free( bprime );
   return sw;
}

BOOST_AUTO_TEST_CASE( poolswap_happy_path )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2HAPPY", 0 );
   // EE-1 (Rule R, F-02): op109 is now INSIDE the parity mechanism, so with an
   // empty pool it must pay the cost anchor (stealth_require_blind_fee) — which
   // a swap's kernel-pinned tx fee (f_tx = a - f_maker - pool_pays) cannot reach.
   // Seed parity_pool[A] through the real funding path, exactly as the wallet
   // builder test does, so this case tests the swap, not the float rule.
   // Fixture discipline (db_block.cpp:423, same as wallet_poolswap_builder_*
   //): SEAL the pool setup with a block first, then make the direct modifies
   // (fee cap, parity seeding) into the fresh pending session the push reads —
   // a generate_block AFTER them would reset pending and wipe them.
   generate_block();
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   {
      share_type parity_core =
         db.current_fee_schedule().calculate_fee(
            operation( stealth_pool_exchange_operation() ) ).amount;
      share_type anchor = stealth_cost_anchor_core( db, 1 );
      share_type gap = ( anchor > parity_core ) ? ( anchor - parity_core ) : share_type( 0 );
      share_type need = stealth_gap_to_asset( db, p.asset_a, gap ) + share_type( 1000 );
      T_seed_pool_uia( *this, dan, p.asset_a( db ), need.value );
   }
   set_expiration( db, trx );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, p.asset_a ), 16u );
   const liquidity_pool_object& pool0 = p.pool( db );
   const int64_t bal_a0 = pool0.balance_a.value, bal_b0 = pool0.balance_b.value;
   const size_t nul_before =
      db.get_index_type<stealth_nullifier_index>().indices().size();
   const int64_t conf_a0 = p.asset_a( db ).dynamic_asset_data_id( db ).confidential_supply.value;
   const int64_t conf_b0 = p.asset_b( db ).dynamic_asset_data_id( db ).confidential_supply.value;

   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "g2-happy-sp", 50 );
   BOOST_CHECK_NO_THROW( sw.op.validate() );
   // Fee schedule mirror: single blind output ⇒ fee + 1×price_per_output.
   BOOST_CHECK_EQUAL( sw.op.calculate_fee(
      stealth_pool_exchange_operation::fee_params_t() ).value,
      ( stealth_pool_exchange_operation::fee_params_t().fee
        + stealth_pool_exchange_operation::fee_params_t().price_per_output ) );
   trx.operations = { sw.op };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();

   // Pool reserves moved exactly per the shared math.
   const liquidity_pool_object& pool1 = p.pool( db );
   BOOST_CHECK_EQUAL( pool1.balance_a.value,
      bal_a0 + sw.expect.pool_receives.amount.value );
   BOOST_CHECK_EQUAL( pool1.balance_b.value,
      bal_b0 - sw.expect.pool_pays.amount.value );
   // Output exists as a counter-asset blinded balance; input retained.
   const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
   auto oit = bbi.find( sw.op.output.commitment );
   BOOST_REQUIRE( oit != bbi.end() );
   BOOST_CHECK( oit->asset_id == p.asset_b );
   BOOST_CHECK( bbi.find( p.commits[5] ) != bbi.end() ); // retained (still live)
   // Nullifiers: both version legs recorded; re-push double-spend refuses.
   BOOST_CHECK_EQUAL(
      db.get_index_type<stealth_nullifier_index>().indices().size() - nul_before, 2u );
   {
      trx.operations = { sw.op };
      BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
      trx.clear();
   }
   // Blind supply: A releases input principal + tx-fee value (the fee leg
   // pairs the framework's accumulated_fees/pending credit), B absorbs the
   // kernel-pinned output.
   BOOST_CHECK_EQUAL(
      p.asset_a( db ).dynamic_asset_data_id( db ).confidential_supply.value,
      conf_a0 - p.each - sw.f_tx );
   BOOST_CHECK_EQUAL(
      p.asset_b( db ).dynamic_asset_data_id( db ).confidential_supply.value,
      conf_b0 + sw.v_out );
   // EE-1 (Rule R): op109 now draws its subsidy from parity_pool, so the
   // zero-fee / zero-market-fee assets mean only "no market-fee routing" —
   // parity_pool[A] holds exactly the seed MINUS the grant. Before EE-1 this
   // pair asserted the pools were untouched (op109 had no parity pair at all,
   // finding F-02).
   const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
   {
      auto ita = st.parity_pool.find( p.asset_a );
      BOOST_REQUIRE( ita != st.parity_pool.end() );
      BOOST_CHECK_EQUAL( ita->second.value, 1000 ); // seed surplus after the debit
      // B never receives a market fee here (0%), and the subsidy is
      // denominated in the sold asset, so B is untouched.
      BOOST_CHECK( st.parity_pool.find( p.asset_b ) == st.parity_pool.end() );
   }
   // Counter-asset decoy set grew by the one new output; input side unchanged.
   BOOST_CHECK_EQUAL( stealth_pool_depth( db, p.asset_b ), 1u );
   BOOST_CHECK_EQUAL( stealth_pool_depth( db, p.asset_a ), 16u );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// Theft direction (proof §4d, understatement): real input worth 1000, pin +
// ring honestly prove 1000, but amount_to_sell claims 999. The value-pin
// fails first (P opens to 1000, not 999) — the pool can never be
// under-debited against a bound pseudo-output.
BOOST_AUTO_TEST_CASE( poolswap_understated_input_fails )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2UNDER", 0 );
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "G2UNDER-sp", 50 );
   sw.op.amount_to_sell = asset( p.each - 1, p.asset_a );
   trx.operations = { sw.op };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "understated poolswap was ACCEPTED" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "value-pin" ) != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear();
   // Nothing moved: pool reserves and blind supply are untouched.
   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value, 1000000 );
   BOOST_CHECK_EQUAL( p.pool( db ).balance_b.value, 1000000 );
} FC_CAPTURE_AND_RETHROW() }

// Griefing direction (proof §4d, overstatement): real input worth 1000,
// proofs bind 1000, but amount_to_sell claims 1001. The pool would be debited
// for value nobody holds (phantom reserve) — the pin fails first.
BOOST_AUTO_TEST_CASE( poolswap_overstated_input_fails )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2OVER", 0 );
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "G2OVER-sp", 50 );
   sw.op.amount_to_sell = asset( p.each + 1, p.asset_a );
   trx.operations = { sw.op };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "overstated poolswap was ACCEPTED" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "value-pin" ) != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear();
   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value, 1000000 );
   BOOST_CHECK_EQUAL( p.pool( db ).balance_b.value, 1000000 );
} FC_CAPTURE_AND_RETHROW() }

// Pool re-targeting: an honest swap for pool 1 re-pointed at a second pool
// with the same asset pair. G2VP binds the pool instance, so the pin fails
// (the G2RM ring leg binds it too — defense in depth, verified second).
BOOST_AUTO_TEST_CASE( poolswap_retarget_pool_fails )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2POOL", 0 );
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   // Second pool, same pair, different instance and reserves.
   const asset_id_type sid2 = create_user_issued_asset( "G2POOLS2", dan,
      charge_market_fee, price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) ), 2, 0 ).get_id();
   const liquidity_pool_id_type pool2 = create_liquidity_pool( dan.get_id(),
      p.asset_a, p.asset_b, sid2, 0, 0 ).get_id();
   issue_uia( dan, asset( 3000000, p.asset_a ) );
   issue_uia( dan, asset( 3000000, p.asset_b ) );
   deposit_to_liquidity_pool( dan.get_id(), pool2,
      asset( 2000000, p.asset_a ), asset( 2000000, p.asset_b ) );
   generate_block();
   set_expiration( db, trx );
   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "G2POOL-sp", 50 );
   sw.op.pool = pool2;
   trx.operations = { sw.op };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "pool-retargeted poolswap was ACCEPTED" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "value-pin" ) != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear();
} FC_CAPTURE_AND_RETHROW() }

// Slippage-floor re-targeting: same claimed input, different min_to_receive
// (still satisfiable, so pool math passes). The pin is unaffected (it binds
// P/amount/pool only) — the G2RM ring leg, which binds min, refuses.
BOOST_AUTO_TEST_CASE( poolswap_retarget_amount_fails )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2MIN", 0 );
   // EE-1: op109 is inside the parity mechanism now — seed parity_pool[A] so
   // this case still fails at the RING (the property under test), not at the
   // float rule that fires earlier in do_evaluate. Seal first (db_block.cpp:423).
   generate_block();
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   {
      share_type parity_core =
         db.current_fee_schedule().calculate_fee(
            operation( stealth_pool_exchange_operation() ) ).amount;
      share_type anchor = stealth_cost_anchor_core( db, 1 );
      share_type gap = ( anchor > parity_core ) ? ( anchor - parity_core ) : share_type( 0 );
      share_type need = stealth_gap_to_asset( db, p.asset_a, gap ) + share_type( 1000 );
      T_seed_pool_uia( *this, dan, p.asset_a( db ), need.value );
   }
   set_expiration( db, trx );
   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "G2MIN-sp", 50 );
   // Tighter but still satisfiable floor: pool math passes, ring message differs.
   sw.op.min_to_receive = asset( sw.v_out - 10, p.asset_b );
   trx.operations = { sw.op };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "min-retargeted poolswap was ACCEPTED" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Ring signature does not verify" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear();
} FC_CAPTURE_AND_RETHROW() }

// Counter-asset re-targeting: same input, payout re-denominated to a third
// asset C. The pool pair gate fires first (output-asset confusion would mint
// C-supply against B-reserves — the pair gate is load-bearing, not
// decorative; deletion testing proves acceptance without it).
BOOST_AUTO_TEST_CASE( poolswap_retarget_counterasset_fails )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2CCY", 0 );
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   const asset_id_type cid = create_user_issued_asset( "G2CCYC", dan,
      charge_market_fee, price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) ), 2, 0 ).get_id();
   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "G2CCY-sp", 50 );
   sw.op.min_to_receive = asset( sw.op.min_to_receive.amount.value, cid );
   trx.operations = { sw.op };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "counterasset-retargeted poolswap was ACCEPTED" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Asset type mismatch" ) != std::string::npos,
                           e.to_detail_string() );
   }
   trx.clear();
} FC_CAPTURE_AND_RETHROW() }

// Fee routing (design §5): 2% market fees on both assets. The issuer market-fee
// shares land EXACTLY (maker/taker helper values) in parity_pool[A/B] — never
// in accumulated_fees (which takes only the 1-unit tx-fee conversion, never
// market fees). Committee cut is 0 under default network_percent (pinned);
// registrar/referrer rewards are forfeited (no identifiable taker).
BOOST_AUTO_TEST_CASE( poolswap_fee_routing )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2FEE", 200 );
   // EE-1: op109 draws from parity_pool now, so seed it enough to clear the
   // float rule. The DEBIT is asserted exactly below against the pre-push
   // balance, so this case still pins the market-fee routing claim.
   // Seal the pool setup first (db_block.cpp:423 pending discipline).
   generate_block();
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   BOOST_REQUIRE_EQUAL( db.get_global_properties().parameters.get_market_fee_network_percent(), 0 );
   int64_t gap_sub = 0;
   int64_t pp_a0 = 0;
   {
      share_type parity_core =
         db.current_fee_schedule().calculate_fee(
            operation( stealth_pool_exchange_operation() ) ).amount;
      share_type anchor = stealth_cost_anchor_core( db, 1 );
      share_type gap = ( anchor > parity_core ) ? ( anchor - parity_core ) : share_type( 0 );
      share_type need = stealth_gap_to_asset( db, p.asset_a, gap ) + share_type( 1000 );
      T_seed_pool_uia( *this, dan, p.asset_a( db ), need.value );
      gap_sub = stealth_parity_gap_core( db, 1, parity_core, 1 ).value;
      BOOST_REQUIRE( gap_sub > 0 );
      const auto& st0 = *db.get_index_type<stealth_status_index>().indices().begin();
      auto i0 = st0.parity_pool.find( p.asset_a );
      BOOST_REQUIRE( i0 != st0.parity_pool.end() );
      pp_a0 = i0->second.value;
      BOOST_REQUIRE_EQUAL( pp_a0 - gap_sub, 1000 ); // seed left the exact surplus
   }
   set_expiration( db, trx );
   const int64_t acc_a0 = p.asset_a( db ).dynamic_asset_data_id( db ).accumulated_fees.value;
   const int64_t acc_b0 = p.asset_b( db ).dynamic_asset_data_id( db ).accumulated_fees.value;
   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "G2FEE-sp", 50 );
   BOOST_REQUIRE( sw.expect.maker_market_fee.amount.value > 0 );
   BOOST_REQUIRE( sw.expect.taker_market_fee.amount.value > 0 );
   trx.operations = { sw.op };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
   auto ita = st.parity_pool.find( p.asset_a );
   auto itb = st.parity_pool.find( p.asset_b );
   BOOST_REQUIRE( ita != st.parity_pool.end() );
   BOOST_REQUIRE( itb != st.parity_pool.end() );
   // A: seed + maker market fee routed in - the Rule R subsidy debit (op109 is
   // the fee asset's asset, and the circulation rule grants anchor(1)-parity).
   // B: taker market fee only — no subsidy leg (the subsidy is denominated in
   // o.fee.asset_id, which the evaluator pins to the SOLD asset).
   BOOST_CHECK_EQUAL( ita->second.value,
      pp_a0 + sw.expect.maker_market_fee.amount.value - gap_sub );
   BOOST_CHECK_EQUAL( itb->second.value, sw.expect.taker_market_fee.amount.value );
   // Market fees bypass accumulated_fees: A additionally takes the Rule R
   // subsidy credit (the pool debit is supply-neutral by construction), B
   // takes nothing at all.
   BOOST_CHECK_EQUAL(
      p.asset_a( db ).dynamic_asset_data_id( db ).accumulated_fees.value,
      acc_a0 + sw.f_tx + gap_sub );
   BOOST_CHECK_EQUAL(
      p.asset_b( db ).dynamic_asset_data_id( db ).accumulated_fees.value, acc_b0 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// G2RM golden vector (carries review Note 5): fixed inputs → hardcoded
// digest. The preimage is rebuilt here with explicit byte ops (T_le64 /
// T_uleb128, never the production encoder), so the test pins both the
// documented encoding and the digest against silent change.
BOOST_AUTO_TEST_CASE( stealth_pool_message_golden )
{ try {
   const uint8_t ver = GRAPHENE_STEALTH_PROOF_V2;
   const asset_id_type asset_a( 3 );
   const uint64_t pool = 7;
   const int64_t amount = 1000, min = 900, F = 15;
   const std::vector<char> img = T_g2img();
   const std::vector<fc::ecc::commitment_type> ring = { T_g2mk( 0 ), T_g2mk( 1 ) };
   const fc::ecc::commitment_type pseudo = T_g2mk( 2 );
   const std::vector<fc::ecc::commitment_type> outs = { T_g2mk( 3 ) };
   // Independent preimage: "G2RM" || ver || LE64(n) || LE64(m) || asset ||
   // pool || amount || min || image || ring || pseudo || outs || F.
   std::string pre = "G2RM";
   pre.push_back( (char)ver );
   pre.append( T_le64( 2 ) );
   pre.append( T_le64( 1 ) );
   pre.append( T_uleb128( 3 ) );
   pre.append( T_uleb128( pool ) );
   pre.append( T_le64( (uint64_t)amount ) );
   pre.append( T_le64( (uint64_t)min ) );
   pre.append( img.data(), img.size() );
   for( const auto& c : ring ) pre.append( (const char*)c.data(), 33 );
   pre.append( (const char*)pseudo.data(), 33 );
   for( const auto& c : outs ) pre.append( (const char*)c.data(), 33 );
   pre.append( T_le64( (uint64_t)F ) );
   const fc::sha256 expect = fc::sha256::hash( pre.data(), pre.size() );
   const fc::sha256 got = stealth_pool_message( ver, asset_a, pool, amount,
                                                min, img, ring, pseudo, outs, F );
   BOOST_CHECK_EQUAL( got, expect );
   // Hardcoded digest (observed RED on the placeholder, pinned GREEN here).
   BOOST_CHECK_EQUAL( got.str(),
                      "8446d4d146f23e609e2cd22c8ba44ce191f19648acc319fb7052d4ec9f3aa58c" );
} FC_CAPTURE_AND_RETHROW() }

// 1-in/1-out is structural (proof: multi-input value-offsetting): single
// stealth_ring_input / stealth_blind_output fields — there is no vector to
// attach a second input to. Compile-level property; guard-deletion N/A
// (no guard to delete — the struct shape IS the guard).
BOOST_AUTO_TEST_CASE( poolswap_multi_input_rejected )
{ try {
   BOOST_CHECK( ( std::is_same<decltype( stealth_pool_exchange_operation::input ),
                               stealth_ring_input >::value ) );
   BOOST_CHECK( ( std::is_same<decltype( stealth_pool_exchange_operation::output ),
                               stealth_blind_output >::value ) );
   // The single-input shape validates end-to-end (relay layer accepts exactly
   // what consensus accepts — no hidden second-input path).
   stealth_pool_exchange_operation op;
   op.fee = asset( 1, asset_id_type() );
   op.amount_to_sell = asset( 1000, asset_id_type() );
   op.min_to_receive = asset( 900, asset_id_type() );
   for( int i = 0; i < 16; ++i )
   {
      std::vector<unsigned char> raw( 33, 0 );
      raw[32] = char( i + 1 );
      op.input.ring.push_back( T_commitment( raw ) );
   }
   op.input.key_image.assign( 33, 2 );
   op.input.ring_sig.assign( 32 + 96 * 16, 0 );
   op.input.alt_key_image.assign( 33, 3 );
   op.input.alt_ring_sig.assign( 32 + 96 * 16, 0 );
   op.output.range_proof.assign( 592, 0 );
   op.output.owner = authority( 1, account_id_type( 1 ), 1 );
   op.value_pin.assign( 65, 0 );
   BOOST_CHECK_NO_THROW( op.validate() );
} FC_CAPTURE_AND_RETHROW() }

// Pre-fork refusal (dedicated PUSH-level pin; the Step-1 case pins the
// dispatch-level gate): a relay-shape-valid op pushed pre-fork refuses at
// the consensus fork gate, never at a shape or crypto check.
BOOST_AUTO_TEST_CASE( poolswap_pre_fork_refused )
{ try {
   stealth_pool_exchange_operation op;
   op.fee = asset( 1, asset_id_type() );
   op.amount_to_sell = asset( 1000, asset_id_type() );
   op.min_to_receive = asset( 900, asset_id_type() );
   for( int i = 0; i < 16; ++i )
   {
      std::vector<unsigned char> raw( 33, 0 );
      raw[32] = char( i + 1 );
      op.input.ring.push_back( T_commitment( raw ) );
   }
   op.input.key_image.assign( 33, 2 );
   op.input.ring_sig.assign( 32 + 96 * 16, 0 );
   op.input.alt_key_image.assign( 33, 3 );
   op.input.alt_ring_sig.assign( 32 + 96 * 16, 0 );
   op.output.range_proof.assign( 592, 0 );
   op.output.owner = authority( 1, account_id_type( 1 ), 1 );
   op.value_pin.assign( 65, 0 );
   BOOST_CHECK_NO_THROW( op.validate() );
   signed_transaction tx;
   tx.operations.push_back( op );
   // Fee set on the funded path so the refusal reaches the consensus gate
   // (with fee 0 the tx dies in insufficient_fee and deleting the fork
   // gate stays green — H1-03 discipline).
   db.current_fee_schedule().set_fee( tx.operations.back() );
   set_expiration( db, tx );
   try
   {
      PUSH_TX( db, tx );
      BOOST_FAIL( "pre-fork op109 was ACCEPTED" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "stealth hardfork" ) != std::string::npos,
                           e.to_detail_string() );
   }
} FC_CAPTURE_AND_RETHROW() }

// Link-4 adversarial builder (design §3 link 4; proof Lemma 4): mirrors
// g2_build_swap exactly, except the tx fee is FORCED to fee_override instead
// of the computed slippage cover (f_tx = a − f_maker − pool_pays). F' and v'
// are rebuilt consistently (output commitment + range proof for v' = a − F',
// ring messages binding F', excess binding F'), so every pre-link-4 guard —
// pin, F-bounds, ring, BP+, kernel — still verifies. Only the equality
// a − F == pool_pays − f_taker is broken. Without the link-4 assert the push
// is ACCEPTED (invisible mint on understatement); with it, it refuses.
static g2_swap g2_build_swap_with_fee( database& db, const g2_pool& p, size_t s,
      uint8_t version, const std::string& tag, int64_t min_discount,
      int64_t fee_override )
{
   const uint8_t alt_v = ( version == GRAPHENE_STEALTH_PROOF_V1 )
                         ? GRAPHENE_STEALTH_PROOF_V2
                         : GRAPHENE_STEALTH_PROOF_V1;
   const liquidity_pool_object& pool = p.pool( db );
   const asset sell( p.each, p.asset_a );
   // Probe with a dust floor to learn the min-independent payout, then build
   // the real floor below it.
   pool_exchange_amounts probe = calculate_pool_exchange_amounts( db, pool,
      sell, asset( 1, p.asset_b ) );
   const int64_t v = probe.account_receives.amount.value;
   const int64_t minv = v - min_discount;
   BOOST_REQUIRE( minv > 0 );
   pool_exchange_amounts ex = calculate_pool_exchange_amounts( db, pool,
      sell, asset( minv, p.asset_b ) );
   BOOST_REQUIRE_EQUAL( ex.account_receives.amount.value, v ); // min is a floor only
   const int64_t f_maker = ex.maker_market_fee.amount.value;
   const int64_t f_taker = ex.taker_market_fee.amount.value;
   const int64_t pool_pays = ex.pool_pays.amount.value;
   const int64_t f_tx = p.each - f_maker - pool_pays;
   BOOST_REQUIRE_MESSAGE( f_tx >= 0, "slippage exceeds input (pool too thin for fees)" );
   BOOST_REQUIRE_MESSAGE( fee_override != f_tx,
      "fee override must differ from the honest slippage cover" );
   BOOST_REQUIRE_MESSAGE( fee_override >= 0, "fee override must be non-negative" );
   const int64_t F = f_maker + f_taker + fee_override;
   BOOST_REQUIRE( F >= 0 );
   BOOST_REQUIRE( F <= p.each ); // F-bounds pass: only link 4 may fire
   const int64_t v_out = p.each - F;
   BOOST_REQUIRE( v_out > 0 );
   BOOST_REQUIRE_MESSAGE( v_out != v,
      "wrong-fee output must diverge from the helper payout (else no gap)" );

   BIGNUM* bs = T_bn( p.blinds[s] );
   BIGNUM* bprime = T_bn( T_blind_secret( tag + "-pseudo" ) );
   auto Bout = T_blind_secret( tag + "-o" );
   fc::ecc::commitment_type Cout;
   {
      BIGNUM* bo = T_bn( Bout );
      auto Cv = T_commit( bo, (uint64_t)v_out );
      BN_free( bo );
      std::copy( Cv.begin(), Cv.end(), Cout.begin() );
   }
   stealth_blind_output sout;
   sout.commitment = Cout;
   sout.range_proof = T_bp_prove( Cout, Bout, (uint64_t)v_out );
   BOOST_REQUIRE_EQUAL( sout.range_proof.size(), 592u );
   auto rk = fc::ecc::private_key::generate();
   sout.owner = authority( 1, public_key_type( rk.get_public_key() ), 1 );

   fc::ecc::commitment_type P;
   {
      auto Pv = T_commit( bprime, (uint64_t)p.each );
      std::copy( Pv.begin(), Pv.end(), P.begin() );
   }
   std::vector<char> T33;
   std::string s32;
   T_prove_value_pin( P, p.each, p.pool.instance.value, bprime, T33, s32 );
   BOOST_REQUIRE_EQUAL( T33.size(), 33u );
   BOOST_REQUIRE_EQUAL( s32.size(), 32u );

   std::vector<std::vector<unsigned char>> Q;
   for( const auto& c : p.commits )
      Q.push_back( std::vector<unsigned char>( c.begin(), c.end() ) );
   auto dry = T_dual_dry_run( version, alt_v, Q, s, bs, (uint64_t)p.each, bprime );
   {
      auto Pv = T_commit( bprime, (uint64_t)p.each );
      BOOST_REQUIRE( dry.pseudo == Pv );
   }
   std::vector<char> img_c( dry.img_main.begin(), dry.img_main.end() );
   std::vector<char> img_a( dry.img_alt.begin(), dry.img_alt.end() );
   std::vector<fc::ecc::commitment_type> out_cs = { Cout };
   fc::ecc::commitment_type Pc = T_commitment( dry.pseudo );
   fc::sha256 m = stealth_pool_message( version, p.asset_a, p.pool.instance.value,
      p.each, minv, img_c, p.commits, Pc, out_cs, F );
   fc::sha256 ma = stealth_pool_message( alt_v, p.asset_a, p.pool.instance.value,
      p.each, minv, img_a, p.commits, Pc, out_cs, F );
   std::string ms( (const char*)m.data(), 32 );
   std::string msa( (const char*)ma.data(), 32 );
   stealth_ring_input rin = T_make_dual_ring_input( version, alt_v, Q, s, bs,
      (uint64_t)p.each, bprime, ms, msa );

   g2_swap sw;
   sw.op.fee = asset( fee_override, p.asset_a );
   sw.op.pool = p.pool;
   sw.op.amount_to_sell = sell;
   sw.op.min_to_receive = asset( minv, p.asset_b );
   sw.op.proof_version = version;
   {
      BIGNUM* e = BN_new();
      BIGNUM* bo = T_bn( Bout );
      BN_copy( e, bprime );
      BN_mod_sub( e, e, bo, T_order(), T_ctx() );
      unsigned char eb[32]; BN_bn2binpad( e, eb, 32 );
      std::copy( eb, eb + 32, (char*)sw.op.excess.data() );
      BN_free( e ); BN_free( bo );
   }
   sw.op.input = rin;
   sw.op.output = sout;
   sw.op.value_pin.assign( T33.begin(), T33.end() );
   sw.op.value_pin.insert( sw.op.value_pin.end(), s32.begin(), s32.end() );
   BOOST_REQUIRE_EQUAL( sw.op.value_pin.size(), 65u );
   sw.expect = ex;
   sw.f_tx = fee_override;
   sw.F = F;
   sw.v_out = v_out;
   BN_free( bs ); BN_free( bprime );
   return sw;
}

// Link-4 equality (design §3 link 4; proof Lemma 4): the kernel pins
// v_out = a − F while the helper pins account_receives = pool_pays − f_taker;
// without an explicit equality assert an understated fee mints invisible
// counter-asset value (v_out > account_receives, pool debited only the helper
// leg) and an overstated fee burns. Both MUST refuse at the link-4 assert —
// every earlier guard still verifies by construction (F-bounds and the helper
// min-check both pass for these parameters).
BOOST_AUTO_TEST_CASE( poolswap_wrong_fee_fails )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2L4", 0 );
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   // Understated fee (0): below the honest slippage cover, so v_out exceeds
   // the helper payout and the mint gap is exercised.
   {
      const liquidity_pool_object& pool = p.pool( db );
      pool_exchange_amounts ex = calculate_pool_exchange_amounts( db, pool,
         asset( p.each, p.asset_a ), asset( 1, p.asset_b ) );
      const int64_t f_tx_honest =
         p.each - ex.maker_market_fee.amount.value - ex.pool_pays.amount.value;
      BOOST_REQUIRE_MESSAGE( f_tx_honest > 0,
         "honest cover must be positive (else 0 is not an understatement)" );
      g2_swap sw = g2_build_swap_with_fee( db, p, 5, GRAPHENE_STEALTH_PROOF_V2,
         "G2L4-under-sp", 50, 0 );
      trx.operations = { sw.op };
      try
      {
         PUSH_TX( db, trx );
         BOOST_FAIL( "understated-fee poolswap was ACCEPTED (link-4 gap open)" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Fee must exactly cover slippage" )
                              != std::string::npos, e.to_detail_string() );
      }
      trx.clear();
   }
   // Overstated fee (+10 over cover; the helper min-check still passes since
   // pool math is min-independent, so only link 4 can refuse). Re-probed on
   // current state so the variant is self-consistent either way.
   {
      const liquidity_pool_object& pool = p.pool( db );
      pool_exchange_amounts ex = calculate_pool_exchange_amounts( db, pool,
         asset( p.each, p.asset_a ), asset( 1, p.asset_b ) );
      const int64_t f_tx_honest =
         p.each - ex.maker_market_fee.amount.value - ex.pool_pays.amount.value;
      BOOST_REQUIRE_MESSAGE( f_tx_honest >= 0, "slippage exceeds input" );
      g2_swap sw = g2_build_swap_with_fee( db, p, 6, GRAPHENE_STEALTH_PROOF_V2,
         "G2L4-over-sp", 50, f_tx_honest + 10 );
      trx.operations = { sw.op };
      try
      {
         PUSH_TX( db, trx );
         BOOST_FAIL( "overstated-fee poolswap was ACCEPTED (link-4 gap open)" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Fee must exactly cover slippage" )
                              != std::string::npos, e.to_detail_string() );
      }
      trx.clear();
   }
   // Nothing moved: both refusals leave pool reserves and blind supply intact.
   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value, 1000000 );
   BOOST_CHECK_EQUAL( p.pool( db ).balance_b.value, 1000000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// ---- EE-5: the four Note refusal vectors (G2-5 §1 rows 3a/3b/3c/6) and the
// three V1 vectors (G2-2 Note-3) for op109.
//
// Every case below pushes through the real PUSH_TX path and asserts the
// EXPECTED message, so a refusal raised by an EARLIER guard fails the case
// instead of silently satisfying it.

// EE-5 shared preamble = poolswap_happy_path's exactly (sealed pool + parity
// seeded + fee cap). Parity seeding is REQUIRED by the late-guard cases: op109's
// float rule (stealth_evaluator.cpp:2209) sits between the composite-F asserts
// and the ring/BP+ legs, so an unseeded pool refuses every late-guard case at
// the float rule and the case would prove nothing about its own guard.
static g2_pool T_g2_ready_pool( database_fixture& f, const account_object& funder,
      const fc::ecc::private_key& funder_key, const std::string& tag )
{
   database& db = f.db;
   g2_pool p = g2_fund_pool( f, funder, funder_key, tag, 0 );
   // Fixture discipline (db_block.cpp:423): SEAL the pool setup with a block
   // first, then make the direct modifies into the fresh pending session.
   f.generate_block();
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   share_type parity_core = db.current_fee_schedule().calculate_fee(
      operation( stealth_pool_exchange_operation() ) ).amount;
   share_type anchor = stealth_cost_anchor_core( db, 1 );
   share_type gap = ( anchor > parity_core ) ? ( anchor - parity_core ) : share_type( 0 );
   share_type need = stealth_gap_to_asset( db, p.asset_a, gap ) + share_type( 1000 );
   T_seed_pool_uia( f, funder, p.asset_a( db ), need.value );
   return p;
}

// EE-5 / G2-5 §1 row 3a — the composite-F REFUSAL legs. The positive legs of the
// evaluator's (9) block (per-term >= 0, F <= MAX_SUPPLY, F <= amount_to_sell)
// execute green in every existing poolswap test; only the refusal legs were
// unpinned. F = maker_market_fee + taker_market_fee + o.fee.amount.
//
// (a) NEGATIVE FEE TERM. The earliest guard is the RELAY validator, not the
//     evaluator: stealth_pool_exchange_operation::validate()
//     (protocol/stealth.cpp:218, `FC_ASSERT( fee.amount >= 0 )` — no message)
//     runs before do_evaluate, so the evaluator's own "Stealth pool swap fee
//     cannot be negative" (stealth_evaluator.cpp:2077) is unreachable through
//     PUSH_TX: a negative wire fee never reaches the evaluator at all. Pinned
//     here deliberately, at the guard that actually refuses.
// (b) OVERFLOWING FEE TERM — and the finding that the evaluator's 128-bit cap
//     assert is NOT reachable from a pushable op. F > GRAPHENE_MAX_SHARE_SUPPLY
//     needs a fee above ~4.6e18, and such a fee is refused EARLIER by the
//     framework's own UIA->CORE conversion in prepare_fee (the fee-pool balance
//     bound), which runs before do_evaluate. So
//     stealth_evaluator.cpp:2187-2188 ("composite fee exceeds max supply") is
//     defense-in-depth BEHIND that bound and unreachable from any pushable op109.
//     Pinned at the guard that actually refuses, and recorded so a later audit
//     does not re-open it as an unpinned leg. (The sibling cap
//     F <= amount_to_sell IS reachable and is pinned by
//     poolswap_f_over_amount_rejected below.)
//
// The maker/taker market-fee legs (stealth_evaluator.cpp:2179-2180) are not
// constructible: calculate_pool_exchange_amounts derives both from
// calculate_market_fee over a uint16_t market_fee_percent, so neither term can
// be negative from any pool state, and the helper itself asserts
// `maker_market_fee < amount_to_sell` and `taker_market_fee <= pool_pays`.
BOOST_AUTO_TEST_CASE( poolswap_composite_f_rejected )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = T_g2_ready_pool( *this, dan, dan_private_key, "G2CF" );
   set_expiration( db, trx );

   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "g2-cf", 50 );
   BOOST_REQUIRE_NO_THROW( sw.op.validate() );

   // Leg (a): negative tx-fee term.
   {
      stealth_pool_exchange_operation bad = sw.op;
      bad.fee.amount = -1;
      trx.operations = { bad };
      try
      {
         PUSH_TX( db, trx );
         BOOST_FAIL( "negative-fee-term poolswap was ACCEPTED" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "fee.amount >= 0" )
                              != std::string::npos, e.to_detail_string() );
      }
      trx.clear();
   }
   // Leg (b): a fee large enough to overflow the composite-F cap. Refused by
   // prepare_fee's fee-pool conversion bound, before the evaluator runs.
   {
      stealth_pool_exchange_operation bad = sw.op;
      bad.fee.amount = GRAPHENE_MAX_SHARE_SUPPLY;
      trx.operations = { bad };
      try
      {
         PUSH_TX( db, trx );
         BOOST_FAIL( "max-supply-overflowing composite F was ACCEPTED" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Fee pool balance" )
                              != std::string::npos, e.to_detail_string() );
      }
      trx.clear();
   }
   // Nothing moved: both refusals leave pool reserves and blind supply intact.
   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value, 1000000 );
   BOOST_CHECK_EQUAL( p.pool( db ).balance_b.value, 1000000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// EE-5 / G2-5 §1 row 3b — non-592-byte BP+ blob and m != 1, pinned at BOTH
// layers as the row requires.
//   (a) VERIFIER: stealth_verify_bp_plus refuses m != 1 before any m-sized
//       indexing (stealth_proof.cpp:989 "only m=1 is wired"), and refuses a
//       wrong-size blob (:991 "blob size"). Both are reachable directly.
//   (b) CONSENSUS/RELAY: op109 pins the output blob at exactly 592 bytes, so a
//       non-592 blob is refused on the wire before the verifier ever sees it.
//       The relay bound is protocol/stealth.cpp:246 and the evaluator repeats
//       it at stealth_evaluator.cpp:2084-2085; both carry the same message
//       tail, so the assertion below is layer-agnostic by construction.
BOOST_AUTO_TEST_CASE( poolswap_non_m1_blob_rejected )
{ try {
   // (a) Verifier layer.
   {
      std::string err;
      std::vector<char> none;
      BOOST_CHECK( !stealth_verify_bp_plus( 2, none, {}, err ) );
      BOOST_CHECK_EQUAL( err, std::string( "only m=1 is wired" ) );
      err.clear();
      BOOST_CHECK( !stealth_verify_bp_plus( 0, none, {}, err ) );
      BOOST_CHECK_EQUAL( err, std::string( "m out of range" ) );
      err.clear();
      BOOST_CHECK( !stealth_verify_bp_plus( 1, none, {}, err ) );
      BOOST_CHECK_EQUAL( err, std::string( "commit count != m" ) );
   }
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = T_g2_ready_pool( *this, dan, dan_private_key, "G2M1" );
   set_expiration( db, trx );

   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "g2-m1", 50 );
   BOOST_REQUIRE_EQUAL( sw.op.output.range_proof.size(), 592u );

   // (b) Wire layer, short blob: 591 bytes.
   {
      stealth_pool_exchange_operation bad = sw.op;
      bad.output.range_proof.resize( 591 );
      trx.operations = { bad };
      try
      {
         PUSH_TX( db, trx );
         BOOST_FAIL( "591-byte BP+ blob was ACCEPTED" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "must be 592 bytes (BP+ m=1)" )
                              != std::string::npos, e.to_detail_string() );
      }
      trx.clear();
   }
   // Wire layer, long blob: two m=1 proofs concatenated (1184 bytes) — the shape
   // an "m=2 by concatenation" prover would emit.
   {
      stealth_pool_exchange_operation bad = sw.op;
      bad.output.range_proof.insert( bad.output.range_proof.end(),
                                     sw.op.output.range_proof.begin(),
                                     sw.op.output.range_proof.end() );
      BOOST_REQUIRE_EQUAL( bad.output.range_proof.size(), 1184u );
      trx.operations = { bad };
      try
      {
         PUSH_TX( db, trx );
         BOOST_FAIL( "1184-byte BP+ blob was ACCEPTED" );
      }
      catch( const fc::exception& e )
      {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find( "must be 592 bytes (BP+ m=1)" )
                              != std::string::npos, e.to_detail_string() );
      }
      trx.clear();
   }
   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value, 1000000 );
   BOOST_CHECK_EQUAL( p.pool( db ).balance_b.value, 1000000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// EE-5 / G2-5 §1 row 3c — the dedicated F > amount_to_sell vector, DISTINCT from
// poolswap_wrong_fee_fails (which keeps F in bounds by construction and so can
// only ever reach the link-4 equality assert). Here the honest swap is built and
// the tx fee is then raised until F exceeds the sold amount, so the evaluator's
// F <= amount_to_sell bound (stealth_evaluator.cpp:2189-2190) refuses. That
// assert runs BEFORE link-4 (:2197-2199) and before the ring/BP+ legs, so the
// raise cannot be masked by a later guard.
BOOST_AUTO_TEST_CASE( poolswap_f_over_amount_rejected )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = T_g2_ready_pool( *this, dan, dan_private_key, "G2FOA" );
   set_expiration( db, trx );

   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "g2-foa", 50 );
   BOOST_REQUIRE_NO_THROW( sw.op.validate() );
   BOOST_REQUIRE_EQUAL( sw.F, p.each - sw.v_out ); // honest: F + v_out == amount

   const liquidity_pool_object& pool = p.pool( db );
   pool_exchange_amounts ex = calculate_pool_exchange_amounts( db, pool,
      asset( p.each, p.asset_a ), sw.op.min_to_receive );
   const int64_t helper_fees = ex.maker_market_fee.amount.value
                             + ex.taker_market_fee.amount.value;
   // Smallest fee that pushes F strictly past the sold amount.
   const int64_t fee_over = ( p.each - helper_fees ) + 1;
   BOOST_REQUIRE_MESSAGE( fee_over > sw.f_tx, "override must exceed the honest cover" );
   BOOST_REQUIRE_MESSAGE( helper_fees + fee_over > p.each, "override must exceed the bound" );

   stealth_pool_exchange_operation bad = sw.op;
   bad.fee.amount = fee_over;
   trx.operations = { bad };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "F > amount_to_sell poolswap was ACCEPTED (F-bounds leg unproven)" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "composite fee exceeds sell amount" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear();
   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value, 1000000 );
   BOOST_CHECK_EQUAL( p.pool( db ).balance_b.value, 1000000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// EE-5 / G2-5 §1 row 6 — the structural claim G2 rests on: a successful op109
// writes NO real account balance. The only account the op touches is
// GRAPHENE_TEMP_ACCOUNT (the fee leg, db_notify.cpp:523-526); everything else
// is pool reserves, the parity singleton, nullifiers, the blinded output and
// supply counters. Until now this was supported only by reading the code.
//
// Anti-vacuity: the case asserts the swap SUCCEEDED first (reserves moved,
// output created, both nullifiers recorded). A snapshot-and-compare that never
// pushes anything would pass forever without testing the property.
BOOST_AUTO_TEST_CASE( poolswap_no_real_account_writes )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS((dan)(bob));
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   transfer( account_id_type()( db ), bob, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = T_g2_ready_pool( *this, dan, dan_private_key, "G2NOW" );
   set_expiration( db, trx );

   const asset_id_type core = asset_id_type();
   // Snapshot every balance any real account holds in any asset the swap could
   // conceivably move: CORE, both pool legs, and the fee/side asset.
   std::vector<account_id_type> actors;
   actors.push_back( dan.get_id() );
   actors.push_back( bob.get_id() );
   std::vector<asset_id_type> watched;
   watched.push_back( core );
   watched.push_back( p.asset_a );
   watched.push_back( p.asset_b );
   std::vector<std::vector<int64_t>> before;
   for( const auto& a : actors )
   {
      std::vector<int64_t> row;
      for( const auto& aid : watched ) row.push_back( db.get_balance( a, aid ).amount.value );
      before.push_back( row );
   }
   const int64_t bal_a0 = p.pool( db ).balance_a.value;
   const size_t nul_before = db.get_index_type<stealth_nullifier_index>().indices().size();

   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "g2-now", 50 );
   BOOST_CHECK_NO_THROW( sw.op.validate() );
   trx.operations = { sw.op };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();

   // --- anti-vacuity: the swap really happened. ---
   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value,
                      bal_a0 + sw.expect.pool_receives.amount.value );
   BOOST_CHECK_EQUAL(
      db.get_index_type<stealth_nullifier_index>().indices().size() - nul_before, 2u );
   {
      const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
      BOOST_CHECK( bbi.find( sw.op.output.commitment ) != bbi.end() );
   }
   // --- the property under test: no real account balance moved. ---
   for( size_t i = 0; i < actors.size(); ++i )
      for( size_t j = 0; j < watched.size(); ++j )
         BOOST_CHECK_EQUAL( db.get_balance( actors[i], watched[j] ).amount.value,
                            before[i][j] );
   // --- and the only impacted account is the temp fee payer (the output owner
   //     is a fresh key authority, so it contributes no account id). ---
   {
      flat_set<account_id_type> impacted;
      operation_get_impacted_accounts( operation( sw.op ), impacted, true );
      BOOST_CHECK_EQUAL( impacted.size(), (size_t)1 );
      BOOST_CHECK( impacted.count( GRAPHENE_TEMP_ACCOUNT ) == 1 );
   }
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// ---- EE-5 Part D: the three V1 vectors (G2-2 Note-3). op109's BP+ OUTPUT path
// is V2-only (exact 592 bytes, "G2 wires no V1 Borromean leg"), and its V1 RING
// leg is frozen past sunset — none of which was pinned.

// D5: a V1 (Borromean) range-proof blob on the op109 output path is refused.
// The blob is produced by the same fc::ecc::range_proof_sign call the op39
// fixture uses for its V1 outputs, so it is a genuine V1 proof and not a
// malformed 592-byte blob in disguise. It is refused on the exact-size bound,
// which is the guard that keeps the V1 Borromean wire format off op109.
BOOST_AUTO_TEST_CASE( poolswap_v1_blob_refused )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = T_g2_ready_pool( *this, dan, dan_private_key, "G2V1B" );
   set_expiration( db, trx );

   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "g2-v1b", 50 );
   auto v1_blob = fc::ecc::range_proof_sign( 0, sw.op.output.commitment,
      T_blind_secret( "g2-v1b-o" ), T_secret( "g2-v1b-n" ), 0, 0, sw.v_out );
   BOOST_REQUIRE( v1_blob.size() != 592u );

   stealth_pool_exchange_operation bad = sw.op;
   bad.output.range_proof = v1_blob;
   trx.operations = { bad };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "V1 Borromean range proof was ACCEPTED on the op109 output path" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "must be 592 bytes (BP+ m=1)" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear();
   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value, 1000000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// D6: op109 past stealth_v1_sunset_time is refused by the sunset gate
// (stealth_evaluator.cpp:2088-2090). Without it a V1 op109 past sunset would
// mint fresh V1-domain-nullified outputs, defeating the sunset for the swap
// path. The gate sits BEFORE the float rule and before every crypto leg, so the
// rest of the op need not be valid — only its proof_version and its bounds.
BOOST_AUTO_TEST_CASE( poolswap_v1_sunset_refused )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = T_g2_ready_pool( *this, dan, dan_private_key, "G2SUN" );
   set_expiration( db, trx );

   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "g2-sun", 50 );
   sw.op.proof_version = GRAPHENE_STEALTH_PROOF_V1;
   BOOST_REQUIRE_NO_THROW( sw.op.validate() ); // V1 is a legal version pre-sunset

   // Cross the sunset.
   generate_blocks( stealth_v1_sunset_time( db ) + 10 );
   set_expiration( db, trx );
   BOOST_REQUIRE( db.head_block_time() >= stealth_v1_sunset_time( db ) );

   trx.operations = { sw.op };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "V1 pool swap past sunset was ACCEPTED" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "frozen past sunset" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear();
   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value, 1000000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// D7: a V1-PROVING ring input on op109 is refused. op109's ring leg is
// version-bound through G2RM (stealth_proof.cpp:519 `pre.push_back(version)`),
// so a ring signature produced under the V1 generators cannot satisfy the V2
// leg — even though it authorizes the same opening over the same ring and the
// same 32-byte G2RM message. Built with T_make_ring_input over the V2 message,
// so the ONLY thing wrong is the proving version.
//
// ALT-LEG DISCIPLINE (learned the hard way): a key image depends only on the
// opening and the version, NOT on the signed message. op109's alt leg is already
// the V1 leg (alt_version flips V2->V1), so a naive V1 main leg carries the
// SAME image as the untouched alt leg and is refused one guard earlier, by
// `in.key_image != in.alt_key_image` (stealth_evaluator.cpp:2118) — a true but
// unhelpful refusal that proves nothing about the ring verify. The alt leg is
// therefore swapped to the ORIGINAL V2 main pair (a distinct image), which
// clears :2118 and lets the push reach the V2 verify at :2227.
BOOST_AUTO_TEST_CASE( poolswap_v1_ring_refused )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = T_g2_ready_pool( *this, dan, dan_private_key, "G2V1R" );
   set_expiration( db, trx );

   // Tag is reused to recover the same pseudo-output opening the swap was built
   // against, so the V1 ring provably authorizes the same value.
   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "g2-v1r", 50 );
   BOOST_REQUIRE_NO_THROW( sw.op.validate() );

   std::vector<fc::ecc::commitment_type> ring_cs( sw.op.input.ring.begin(),
                                                  sw.op.input.ring.end() );
   std::vector<fc::ecc::commitment_type> out_cs = { sw.op.output.commitment };
   fc::sha256 m2 = stealth_pool_message( sw.op.proof_version,
      sw.op.amount_to_sell.asset_id, sw.op.pool.instance.value,
      sw.op.amount_to_sell.amount.value, sw.op.min_to_receive.amount.value,
      sw.op.input.key_image, ring_cs, sw.op.input.pseudo_output, out_cs, sw.F );
   std::string ms2( (const char*)m2.data(), 32 );

   std::vector<std::vector<unsigned char>> Q;
   for( const auto& c : sw.op.input.ring )
      Q.push_back( std::vector<unsigned char>( c.begin(), c.end() ) );
   BIGNUM* bs5 = T_bn( p.blinds[5] );
   BIGNUM* bp5 = T_bn( T_blind_secret( "g2-v1r-pseudo" ) );
   stealth_ring_input v1rin = T_make_ring_input( GRAPHENE_STEALTH_PROOF_V1, Q, 5,
                                                 bs5, (uint64_t)p.each, bp5, ms2 );
   BN_free( bs5 ); BN_free( bp5 );
   // Same opening, same ring, same message — only the proving version differs.
   BOOST_REQUIRE( v1rin.pseudo_output == sw.op.input.pseudo_output );
   BOOST_REQUIRE( v1rin.key_image.size() == 33u );
   BOOST_REQUIRE_EQUAL( v1rin.ring_sig.size(), 32 + 96 * sw.op.input.ring.size() );
   BOOST_REQUIRE( v1rin.key_image != sw.op.input.key_image );

   stealth_pool_exchange_operation bad = sw.op;
   bad.input.key_image = v1rin.key_image;            // V1-proving main leg
   bad.input.ring_sig = v1rin.ring_sig;
   bad.input.alt_key_image = sw.op.input.key_image;  // V2 pair moved to the alt slot
   bad.input.alt_ring_sig = sw.op.input.ring_sig;
   BOOST_REQUIRE( bad.input.key_image != bad.input.alt_key_image );
   BOOST_REQUIRE_NO_THROW( bad.validate() ); // shape is legal; only the proof fails

   trx.operations = { bad };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "V1-proving ring was ACCEPTED on the op109 V2 path (G2RM version unbound)" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "Ring signature does not verify" )
                           != std::string::npos, e.to_detail_string() );
   }
   trx.clear();
   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value, 1000000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// ---- G2-3 wallet prover (Step 1, TDD RED): production dual-version pool-ring
// prover. Fixture style mirrors T_prove_ring:199 (deterministic 16-ring with
// known openings); PROVING goes through the production API in
// libraries/chain/stealth_prover.{hpp,cpp} (wallet-side, evaluators must never
// call it). RED = this TU fails to compile (no such header/symbol).
BOOST_AUTO_TEST_CASE( wallet_prover_pool_ring_dual )
{ try {
   const uint8_t V = GRAPHENE_STEALTH_PROOF_V2;
   const uint8_t VA = GRAPHENE_STEALTH_PROOF_V1;
   const size_t N = 16, S = 5;
   const uint64_t VVAL = 1000;
   // Deterministic 16-ring with known openings (distinct values keep every
   // member point distinct).
   std::vector<fc::ecc::commitment_type> Q;
   std::vector<fc::sha256> blinds;
   for( size_t i = 0; i < N; ++i )
   {
      auto B = T_blind_secret( "g2w-ring-b|" + std::to_string( i ) );
      blinds.push_back( B );
      BIGNUM* bb = T_bn( B );
      Q.push_back( T_commitment( T_commit( bb, VVAL + i ) ) );
      BN_free( bb );
   }
   // Fresh pseudo blind from the PRODUCTION sampler (fails to compile pre-G2-3).
   const fc::sha256 bP = graphene::chain::stealth_sample_blind();
   // Dry run under dummy messages to learn both images (+ shared pseudo),
   // mirroring the g2_build_swap/T_dual_dry_run pattern: G2RM binds the
   // images, so the real messages can only be built after this step.
   graphene::chain::stealth_pool_ring_proof dry;
   std::string err;
   const std::string dummy( 32, '\0' );
   BOOST_REQUIRE_MESSAGE(
      graphene::chain::stealth_prove_pool_ring(
         V, VA, Q, S, blinds[S], VVAL + S, bP, dummy, dummy, dry, err ),
      "production dry-run prove failed: " << err );
   BOOST_REQUIRE_EQUAL( dry.key_image.size(), 33u );
   BOOST_REQUIRE_EQUAL( dry.alt_key_image.size(), 33u );
   BOOST_REQUIRE_EQUAL( dry.ring_sig.size(), 32u + 96u * N );
   BOOST_REQUIRE_EQUAL( dry.alt_ring_sig.size(), 32u + 96u * N );
   // Independent G2RM messages over the dry-run images (built here from the
   // consensus helper, never trusted from the prover).
   const asset_id_type asset_a;
   const uint64_t pool = 7;
   const int64_t amount = (int64_t)( VVAL + S ), minv = amount - 50, F = 10;
   BIGNUM* bo = T_bn( T_blind_secret( "g2w-ring-out-b" ) );
   fc::ecc::commitment_type Cout = T_commitment( T_commit( bo, (uint64_t)( amount - F ) ) );
   BN_free( bo );
   std::vector<fc::ecc::commitment_type> outs = { Cout };
   fc::sha256 mh = stealth_pool_message( V, asset_a, pool, amount, minv,
      dry.key_image, Q, dry.pseudo_output, outs, F );
   fc::sha256 ma = stealth_pool_message( VA, asset_a, pool, amount, minv,
      dry.alt_key_image, Q, dry.pseudo_output, outs, F );
   const std::string msg( (const char*)mh.data(), 32 );
   const std::string msga( (const char*)ma.data(), 32 );
   // Real prove under the bound messages (same b_P: pseudo must be stable).
   graphene::chain::stealth_pool_ring_proof proof;
   BOOST_REQUIRE_MESSAGE(
      graphene::chain::stealth_prove_pool_ring(
         V, VA, Q, S, blinds[S], VVAL + S, bP, msg, msga, proof, err ),
      "production prove failed: " << err );
   BOOST_CHECK( proof.pseudo_output == dry.pseudo_output );
   BOOST_CHECK( proof.key_image == dry.key_image );
   BOOST_CHECK( proof.alt_key_image == dry.alt_key_image );
   // Main leg verifies under the consensus verifier.
   {
      stealth_ring_input in_main;
      in_main.ring = Q;
      in_main.key_image = proof.key_image;
      in_main.ring_sig = proof.ring_sig;
      in_main.pseudo_output = proof.pseudo_output;
      BOOST_CHECK_MESSAGE( stealth_verify_ring( V, in_main, msg, err ), err );
   }
   // Alt leg verifies under the other version (evaluator's alt_in pattern).
   {
      stealth_ring_input in_alt;
      in_alt.ring = Q;
      in_alt.key_image = proof.alt_key_image;
      in_alt.ring_sig = proof.alt_ring_sig;
      in_alt.pseudo_output = proof.pseudo_output;
      BOOST_CHECK_MESSAGE( stealth_verify_ring( VA, in_alt, msga, err ), err );
   }
   // Zeroization discipline: the hook image is the post-cleanse copy of the
   // prover's secret buffer — 32 zero bytes iff cleansing ran on it.
   {
      std::vector<unsigned char> cleansed =
         graphene::chain::stealth_prover_test_last_cleansed();
      BOOST_REQUIRE_EQUAL( cleansed.size(), 32u );
      BOOST_CHECK_MESSAGE( std::all_of( cleansed.begin(), cleansed.end(),
         []( unsigned char c ) { return c == 0; } ),
         "prover secret buffer was not cleansed" );
   }
} FC_CAPTURE_AND_RETHROW() }

// ---- G2-3 wallet prover (Step 2, TDD RED): BP+ m=1 + kernel scalar +
// Schnorr pin provers in stealth_prover.cpp. The test-side fold mirrors
// T_bp_prove:764 for the 592B blob; excess = b_P − b_out; Schnorr (T,s)
// for (P, amount, pool). RED = the Step-1 stubs refuse (false/empty) so
// every leg below fails; GREEN = the triple passes all three verifiers.
BOOST_AUTO_TEST_CASE( wallet_prover_pool_value_triple )
{ try {
   const int64_t amount = 5000;
   const uint64_t pool = 7;
   const int64_t F = 100;
   const uint64_t v_out = (uint64_t)( amount - F );
   // Openings from the production sampler (fresh per run, always < n).
   const fc::sha256 bP = graphene::chain::stealth_sample_blind();
   const fc::sha256 bOut = graphene::chain::stealth_sample_blind();
   BIGNUM* bpn = T_bn( bP );
   BIGNUM* bon = T_bn( bOut );
   const fc::ecc::commitment_type P =
      T_commitment( T_commit( bpn, (uint64_t)amount ) );
   const fc::ecc::commitment_type Cout =
      T_commitment( T_commit( bon, v_out ) );
   BN_free( bpn ); BN_free( bon );

   // (a) Schnorr pin (T, s) for (P, amount, pool) via the production prover.
   std::vector<char> T33;
   std::string s32;
   std::string err;
   BOOST_REQUIRE_MESSAGE(
      graphene::chain::stealth_prove_value_pin(
         P, amount, pool, bP, T33, s32, err ),
      "production pin prove failed: " << err );
   BOOST_REQUIRE_EQUAL( T33.size(), 33u );
   BOOST_REQUIRE_EQUAL( s32.size(), 32u );
   BOOST_CHECK_MESSAGE(
      stealth_verify_value_pin( P, amount, pool, T33, s32, err ), err );

   // (b) BP+ m=1 (exactly 592 bytes) for the output commitment.
   std::vector<char> bp;
   BOOST_REQUIRE_MESSAGE(
      graphene::chain::stealth_prove_bp_plus_m1( Cout, bOut, v_out, bp, err ),
      "production BP+ prove failed: " << err );
   BOOST_REQUIRE_EQUAL( bp.size(), 592u );
   BOOST_CHECK_MESSAGE(
      stealth_verify_bp_plus( 1, bp, { Cout }, err ), err );

   // (c) Kernel scalar binds the two blinds with the composite fee.
   const fc::sha256 excess =
      graphene::chain::stealth_compute_pool_excess( bP, bOut );
   BOOST_CHECK_MESSAGE(
      stealth_verify_excess( { P }, { Cout }, F, excess, err ), err );

   // Zeroization ran on the last prover's secret buffer too.
   {
      std::vector<unsigned char> cleansed =
         graphene::chain::stealth_prover_test_last_cleansed();
      BOOST_REQUIRE_EQUAL( cleansed.size(), 32u );
      BOOST_CHECK_MESSAGE( std::all_of( cleansed.begin(), cleansed.end(),
         []( unsigned char c ) { return c == 0; } ),
         "prover secret buffer was not cleansed" );
   }
} FC_CAPTURE_AND_RETHROW() }

// ---- G2-3 wallet (Step 3, TDD RED): database_api::get_stealth_outputs
// enumeration + sampler. RED = both symbols are undeclared (compile fail).
BOOST_AUTO_TEST_CASE( wallet_stealth_outputs_enumeration )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2ENUM", 0 );
   generate_block();
   set_expiration( db, trx );
   graphene::app::database_api api( db );
   // Sold asset: exactly the 16 seeded blinds, all unspent, all carrying
   // post-fork creation metadata (created_block + created_time set).
   {
      std::vector<blinded_balance_object> outs =
         api.get_stealth_outputs( p.asset_a, true );
      BOOST_REQUIRE_EQUAL( outs.size(), 16u );
      for( const auto& o : outs )
      {
         BOOST_CHECK( o.asset_id == p.asset_a );
         BOOST_CHECK( !o.spent );
         BOOST_CHECK_NE( o.created_block, 0u );
      }
      std::vector<blinded_balance_object> all =
         api.get_stealth_outputs( p.asset_a, false );
      BOOST_CHECK_EQUAL( all.size(), outs.size() );
   }
   // Counter asset holds no blinds yet (outputs appear only via swaps).
   {
      std::vector<blinded_balance_object> outs =
         api.get_stealth_outputs( p.asset_b, true );
      BOOST_CHECK_EQUAL( outs.size(), 0u );
   }
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// Sampler output must satisfy the exact checks the evaluator membership
// loop applies (asset, metadata-bearing, decoy policy at live depth).
BOOST_AUTO_TEST_CASE( wallet_sampler_matches_consensus )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2SAMP", 0 );
   generate_block();
   set_expiration( db, trx );
   // The only possible 16-ring here is the full set (pool holds exactly
   // 16 aged blinds of A): sampler must return all of them, real included.
   graphene::chain::stealth_sampled_ring smp =
      graphene::chain::stealth_sample_pool_ring(
         db, p.asset_a, p.commits[3] );
   BOOST_REQUIRE_EQUAL( smp.ring.size(), 16u );
   BOOST_REQUIRE( smp.real_index < smp.ring.size() );
   BOOST_CHECK( smp.ring[smp.real_index] == p.commits[3] );
   // Distinct members (evaluator refuses duplicates).
   {
      std::vector<fc::ecc::commitment_type> sorted = smp.ring;
      std::sort( sorted.begin(), sorted.end() );
      BOOST_CHECK( std::adjacent_find( sorted.begin(), sorted.end() )
                   == sorted.end() );
   }
   // Evaluator membership loop, replicated: every member indexed, asset
   // match, metadata-bearing; then the decoy-policy call at live depth.
   {
      const auto& bbi =
         db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
      std::vector<uint32_t> heights;
      std::vector<fc::time_point_sec> times;
      for( const auto& c : smp.ring )
      {
         auto itr = bbi.find( c );
         BOOST_REQUIRE_MESSAGE( itr != bbi.end(),
            "sampled member is not a live blinded balance" );
         BOOST_CHECK( itr->asset_id == p.asset_a );
         BOOST_CHECK_NE( itr->created_block, 0u );
         heights.push_back( itr->created_block );
         times.push_back( itr->created_time );
      }
      std::string err;
      BOOST_CHECK_MESSAGE(
         stealth_check_decoy_policy( heights, times, db.head_block_time(),
            db.head_block_num(), err, stealth_pool_depth( db, p.asset_a ) ),
         err );
   }
   // An unsatisfiable mix hold fails closed (nothing is that old).
   BOOST_CHECK_THROW(
      graphene::chain::stealth_sample_pool_ring(
         db, p.asset_a, p.commits[3],
         db.head_block_num() + 1000000 ),
      fc::exception );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// ---- G2-3 wallet (Step 4a, TDD RED): production op builder.
// stealth_prove_pool_exchange is declared (stealth_pool_builder.hpp) but
// NOT defined anywhere: RED = link failure (undefined reference).
// Round trip: fund → seed parity → build via the PRODUCTION builder →
// validate → push → exact reserve/supply/nullifier deltas.
BOOST_AUTO_TEST_CASE( wallet_poolswap_builder_roundtrip )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2BLD", 0 );
   generate_block(); // seal the fixture: later direct modifies (fee cap,
   // parity seeding) live in the pending session the build/push reads —
   // a generate_block AFTER them would reset pending and wipe them
   // (db_block.cpp:423 discipline).
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   // Float-rule floor for the 1-output fee leg, computed through the same
   // production functions the builder uses (parity level ~0 here, anchor
   // pinned): seed the UIA parity pool so the parity leg clears.
   {
      share_type parity_core =
         db.current_fee_schedule().calculate_fee(
            operation( stealth_pool_exchange_operation() ) ).amount;
      share_type anchor = stealth_cost_anchor_core( db, 1 );
      share_type gap = ( anchor > parity_core )
         ? ( anchor - parity_core ) : share_type( 0 );
      share_type need =
         stealth_gap_to_asset( db, p.asset_a, gap ) + share_type( 1000 );
      T_seed_pool_uia( *this, dan, p.asset_a( db ), need.value );
   }
   set_expiration( db, trx );

   const liquidity_pool_object& pool0 = p.pool( db );
   const int64_t bal_a0 = pool0.balance_a.value, bal_b0 = pool0.balance_b.value;
   const size_t nul_before =
      db.get_index_type<stealth_nullifier_index>().indices().size();
   const int64_t conf_a0 =
      p.asset_a( db ).dynamic_asset_data_id( db ).confidential_supply.value;
   const int64_t conf_b0 =
      p.asset_b( db ).dynamic_asset_data_id( db ).confidential_supply.value;

   const asset sell( p.each, p.asset_a );
   pool_exchange_amounts probe = calculate_pool_exchange_amounts(
      db, p.pool( db ), sell, asset( 1, p.asset_b ) );
   const int64_t v = probe.account_receives.amount.value;
   const asset minv( v - 50, p.asset_b );

   auto rk = fc::ecc::private_key::generate();
   graphene::chain::stealth_pool_swap_opening opening;
   opening.commitment = p.commits[5];
   opening.blind = p.blinds[5];
   opening.value = (uint64_t)p.each;
   opening.output_owner = authority( 1, public_key_type( rk.get_public_key() ), 1 );

   // PRODUCTION builder (undefined pre-Step-4: link RED).
   stealth_pool_exchange_operation op =
      graphene::chain::stealth_prove_pool_exchange(
         db, p.pool( db ), sell, minv, opening );
   BOOST_CHECK_NO_THROW( op.validate() );
   // Exact-cover fee (link-4 binding): fee == a − f_maker − pool_pays.
   pool_exchange_amounts ex = calculate_pool_exchange_amounts(
      db, p.pool( db ), sell, minv );
   BOOST_CHECK_EQUAL( op.fee.amount.value,
      p.each - ex.maker_market_fee.amount.value - ex.pool_pays.amount.value );
   BOOST_CHECK( op.fee.asset_id == p.asset_a );
   BOOST_CHECK_EQUAL( op.value_pin.size(), 65u );
   BOOST_CHECK_EQUAL( op.output.range_proof.size(), 592u );

   trx.operations = { op };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();

   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value,
                      bal_a0 + ex.pool_receives.amount.value );
   BOOST_CHECK_EQUAL( p.pool( db ).balance_b.value,
                      bal_b0 - ex.pool_pays.amount.value );
   {
      const auto& bbi =
         db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
      BOOST_CHECK( bbi.find( op.output.commitment ) != bbi.end() );
   }
   BOOST_CHECK_EQUAL(
      db.get_index_type<stealth_nullifier_index>().indices().size(),
      nul_before + 2u );
   BOOST_CHECK_EQUAL(
      p.asset_a( db ).dynamic_asset_data_id( db ).confidential_supply.value,
      conf_a0 - p.each - op.fee.amount.value );
   BOOST_CHECK_EQUAL(
      p.asset_b( db ).dynamic_asset_data_id( db ).confidential_supply.value,
      conf_b0 + ex.account_receives.amount.value );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// Floor abort: no parity seeding → the anchor leg prices the 1-output fee
// above the slippage cover → the builder aborts client-side (nothing moves).
BOOST_AUTO_TEST_CASE( wallet_poolswap_builder_floor_abort )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2FLOOR", 0 );
   generate_block();
   set_expiration( db, trx );
   const asset sell( p.each, p.asset_a );
   pool_exchange_amounts probe = calculate_pool_exchange_amounts(
      db, p.pool( db ), sell, asset( 1, p.asset_b ) );
   const int64_t v = probe.account_receives.amount.value;
   auto rk = fc::ecc::private_key::generate();
   graphene::chain::stealth_pool_swap_opening opening;
   opening.commitment = p.commits[5];
   opening.blind = p.blinds[5];
   opening.value = (uint64_t)p.each;
   opening.output_owner = authority( 1, public_key_type( rk.get_public_key() ), 1 );
   // Parity pool for A is empty (only CORE was seeded): cover (1 sat-scale)
   // sits below the anchor-priced floor → abort, never a refused op.
   BOOST_CHECK_THROW(
      graphene::chain::stealth_prove_pool_exchange(
         db, p.pool( db ), sell, asset( v - 50, p.asset_b ), opening ),
      fc::exception );
   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value, 1000000 );
   BOOST_CHECK_EQUAL( p.pool( db ).balance_b.value, 1000000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// Min abort: a floor-passing build with an unmeetable slippage floor
// aborts inside the shared helper (propagated, never a refused op).
BOOST_AUTO_TEST_CASE( wallet_poolswap_builder_min_abort )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2MINB", 0 );
   generate_block(); // seal first (db_block.cpp:423 pending-reset discipline)
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   {
      share_type parity_core =
         db.current_fee_schedule().calculate_fee(
            operation( stealth_pool_exchange_operation() ) ).amount;
      share_type anchor = stealth_cost_anchor_core( db, 1 );
      share_type gap = ( anchor > parity_core )
         ? ( anchor - parity_core ) : share_type( 0 );
      share_type need =
         stealth_gap_to_asset( db, p.asset_a, gap ) + share_type( 1000 );
      T_seed_pool_uia( *this, dan, p.asset_a( db ), need.value );
   }
   set_expiration( db, trx );
   const asset sell( p.each, p.asset_a );
   pool_exchange_amounts probe = calculate_pool_exchange_amounts(
      db, p.pool( db ), sell, asset( 1, p.asset_b ) );
   const int64_t v = probe.account_receives.amount.value;
   auto rk = fc::ecc::private_key::generate();
   graphene::chain::stealth_pool_swap_opening opening;
   opening.commitment = p.commits[5];
   opening.blind = p.blinds[5];
   opening.value = (uint64_t)p.each;
   opening.output_owner = authority( 1, public_key_type( rk.get_public_key() ), 1 );
   // The floor leg is cleared here (same pending state): a good floor builds
   // fine, so the throw below can only be the unmeetable min — this pins the
   // abort to the min leg, not the floor leg (cf. floor_abort's geometry).
   BOOST_CHECK_NO_THROW(
      graphene::chain::stealth_prove_pool_exchange(
         db, p.pool( db ), sell, asset( v - 50, p.asset_b ), opening ) );
   BOOST_CHECK_THROW(
      graphene::chain::stealth_prove_pool_exchange(
         db, p.pool( db ), sell, asset( v + 1000, p.asset_b ), opening ),
      fc::exception );
   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value, 1000000 );
   BOOST_CHECK_EQUAL( p.pool( db ).balance_b.value, 1000000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// Tamper: one flipped bit of P post-build fails closed at push (pin/ring
// binding); the untouched copy then still succeeds (refusal was pre-apply,
// no nullifier was written).
BOOST_AUTO_TEST_CASE( wallet_poolswap_builder_tamper_fails )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2TAMP", 0 );
   generate_block(); // seal first (db_block.cpp:423 pending-reset discipline)
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   {
      share_type parity_core =
         db.current_fee_schedule().calculate_fee(
            operation( stealth_pool_exchange_operation() ) ).amount;
      share_type anchor = stealth_cost_anchor_core( db, 1 );
      share_type gap = ( anchor > parity_core )
         ? ( anchor - parity_core ) : share_type( 0 );
      share_type need =
         stealth_gap_to_asset( db, p.asset_a, gap ) + share_type( 1000 );
      T_seed_pool_uia( *this, dan, p.asset_a( db ), need.value );
   }
   set_expiration( db, trx );
   const asset sell( p.each, p.asset_a );
   pool_exchange_amounts probe = calculate_pool_exchange_amounts(
      db, p.pool( db ), sell, asset( 1, p.asset_b ) );
   const int64_t v = probe.account_receives.amount.value;
   auto rk = fc::ecc::private_key::generate();
   graphene::chain::stealth_pool_swap_opening opening;
   opening.commitment = p.commits[5];
   opening.blind = p.blinds[5];
   opening.value = (uint64_t)p.each;
   opening.output_owner = authority( 1, public_key_type( rk.get_public_key() ), 1 );
   stealth_pool_exchange_operation honest =
      graphene::chain::stealth_prove_pool_exchange(
         db, p.pool( db ), sell, asset( v - 50, p.asset_b ), opening );
   stealth_pool_exchange_operation tampered = honest;
   tampered.input.pseudo_output.data()[0] ^= 0x01;
   trx.operations = { tampered };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "tampered-P poolswap was ACCEPTED" );
   }
   catch( const fc::exception& e ) { BOOST_CHECK( true ); (void)e; }
   trx.clear();
   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value, 1000000 );
   BOOST_CHECK_EQUAL( p.pool( db ).balance_b.value, 1000000 );
   // Pre-apply refusal: the honest copy still spends the same input.
   trx.operations = { honest };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   BOOST_CHECK_NE( p.pool( db ).balance_a.value, 1000000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// ---- G2-3 wallet (Step 4b, TDD RED): printer entries + delay coverage.
// RED = the overloads do not exist (generic fallback prints the raw op
// name — none of the substrings below match) and wallet_api has no
// stealth_pool_swap member (compile fail).
BOOST_AUTO_TEST_CASE( wallet_stealth_printer_entries )
{ try {
   // Offline wallet (null remote api): the new stealth entries perform no
   // remote lookups, so every leg below must print without a node.
   graphene::wallet::wallet_data wdata;
   graphene::wallet::wallet_api w( wdata, fc::api<graphene::app::login_api>() );
   graphene::wallet::detail::wallet_api_impl impl(
      w, wdata, fc::api<graphene::app::login_api>() );
   auto print = [&]( const operation& o ) {
      graphene::chain::operation_history_object hist;
      std::ostringstream ss;
      graphene::wallet::detail::operation_printer pr( ss, impl, hist );
      o.visit( pr );
      return ss.str();
   };
   {
      stealth_transfer_operation op;
      op.asset_id = asset_id_type();
      std::string s = print( operation( op ) );
      BOOST_CHECK_MESSAGE( s.find( "Stealth transfer" ) != std::string::npos, s );
   }
   {
      turnstile_reproof_operation op;
      std::string s = print( operation( op ) );
      BOOST_CHECK_MESSAGE( s.find( "Turnstile" ) != std::string::npos, s );
   }
   {
      stealth_explicit_spend_operation op;
      std::string s = print( operation( op ) );
      BOOST_CHECK_MESSAGE( s.find( "Stealth explicit spend" ) != std::string::npos, s );
   }
   {
      stealth_pool_exchange_operation op;
      op.amount_to_sell = asset( 1000 );
      op.min_to_receive = asset( 900, asset_id_type( 1 ) );
      std::string s = print( operation( op ) );
      BOOST_CHECK_MESSAGE( s.find( "Stealth pool swap" ) != std::string::npos, s );
   }
} FC_CAPTURE_AND_RETHROW() }

// Delay coverage: the op109 wallet path (stealth_pool_swap) validates
// shape BEFORE the delay choke (malformed ops never sleep) and invokes
// the choke exactly when broadcast=true (offline the later sign step
// throws for want of keys — the hook assertions still pin the ordering).
BOOST_AUTO_TEST_CASE( wallet_stealth_pool_swap_delay )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "G2DELAY", 0 );
   generate_block(); // seal first (db_block.cpp:423 pending-reset discipline)
   {
      share_type parity_core =
         db.current_fee_schedule().calculate_fee(
            operation( stealth_pool_exchange_operation() ) ).amount;
      share_type anchor = stealth_cost_anchor_core( db, 1 );
      share_type gap = ( anchor > parity_core )
         ? ( anchor - parity_core ) : share_type( 0 );
      share_type need =
         stealth_gap_to_asset( db, p.asset_a, gap ) + share_type( 1000 );
      T_seed_pool_uia( *this, dan, p.asset_a( db ), need.value );
   }
   set_expiration( db, trx );
   const asset sell( p.each, p.asset_a );
   pool_exchange_amounts probe = calculate_pool_exchange_amounts(
      db, p.pool( db ), sell, asset( 1, p.asset_b ) );
   const int64_t v = probe.account_receives.amount.value;
   auto rk = fc::ecc::private_key::generate();
   graphene::chain::stealth_pool_swap_opening opening;
   opening.commitment = p.commits[5];
   opening.blind = p.blinds[5];
   opening.value = (uint64_t)p.each;
   opening.output_owner = authority( 1, public_key_type( rk.get_public_key() ), 1 );
   stealth_pool_exchange_operation honest =
      graphene::chain::stealth_prove_pool_exchange(
         db, p.pool( db ), sell, asset( v - 50, p.asset_b ), opening );

   graphene::wallet::wallet_data wdata;
   graphene::wallet::wallet_api w( wdata, fc::api<graphene::app::login_api>() );
   w.set_unlocked_for_tests();
   int calls = 0;
   uint32_t slept = 0;
   w.set_blind_sleep_hook( [&]( uint32_t s ) { ++calls; slept = s; } );
   // Malformed op: validate throws BEFORE the choke (hook silent).
   {
      stealth_pool_exchange_operation bad;
      BOOST_CHECK_THROW( w.stealth_pool_swap( bad, true ), fc::exception );
      BOOST_CHECK_EQUAL( calls, 0 );
   }
   // Honest op, sign-only: no delay (hook silent; sign throws offline).
   {
      BOOST_CHECK_THROW( w.stealth_pool_swap( honest, false ), fc::exception );
      BOOST_CHECK_EQUAL( calls, 0 );
   }
   // Honest op, broadcast: choke fires once before the offline sign throw.
   {
      BOOST_CHECK_THROW( w.stealth_pool_swap( honest, true ), fc::exception );
      BOOST_CHECK_EQUAL( calls, 1 );
      BOOST_CHECK_EQUAL( slept, 3u );
   }
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// ---- G2-3 wallet (Step 5, TDD RED): malleability suite.
// Same ring re-targeted at a different pool / amount / counter-asset /
// output commitment must fail (all four refuse; reserves pinned). These
// run against PRODUCTION builder output, so they pin the builder's
// bindings end to end. RED = suite fails (builder output allegedly
// malleable); GREEN = all four refuse.
// Shared funded context: pool + seeded UIA parity fund + probe payout.
struct g2_wallet_ctx
{
   g2_pool pool;
   int64_t v_out = 0;
};
static g2_wallet_ctx T_wallet_funded_pool( database_fixture& f,
      const account_object& funder,
      const fc::ecc::private_key& funder_key, const std::string& tag )
{
   database& db = f.db;
   signed_transaction& trx = f.trx;
   g2_wallet_ctx c;
   c.pool = g2_fund_pool( f, funder, funder_key, tag, 0 );
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   f.generate_block(); // seal first (db_block.cpp:423 pending-reset discipline)
   {
      share_type parity_core =
         db.current_fee_schedule().calculate_fee(
            operation( stealth_pool_exchange_operation() ) ).amount;
      share_type anchor = stealth_cost_anchor_core( db, 1 );
      share_type gap = ( anchor > parity_core )
         ? ( anchor - parity_core ) : share_type( 0 );
      share_type need =
         stealth_gap_to_asset( db, c.pool.asset_a, gap ) + share_type( 1000 );
      T_seed_pool_uia( f, funder, c.pool.asset_a( db ), need.value );
   }
   set_expiration( db, trx );
   const asset sell( c.pool.each, c.pool.asset_a );
   pool_exchange_amounts probe = calculate_pool_exchange_amounts(
      db, c.pool.pool( db ), sell, asset( 1, c.pool.asset_b ) );
   c.v_out = probe.account_receives.amount.value;
   return c;
}

static stealth_pool_exchange_operation T_wallet_honest_swap(
      database& db, const g2_wallet_ctx& c, size_t input_idx,
      const std::string& tag, int64_t min_discount )
{
   auto rk = fc::ecc::private_key::generate();
   graphene::chain::stealth_pool_swap_opening opening;
   opening.commitment = c.pool.commits[input_idx];
   opening.blind = c.pool.blinds[input_idx];
   opening.value = (uint64_t)c.pool.each;
   opening.output_owner =
      authority( 1, public_key_type( rk.get_public_key() ), 1 );
   return graphene::chain::stealth_prove_pool_exchange(
      db, c.pool.pool( db ),
      asset( c.pool.each, c.pool.asset_a ),
      asset( c.v_out - min_discount, c.pool.asset_b ),
      opening );
}

BOOST_AUTO_TEST_CASE( wallet_poolswap_retarget_pool )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 800000000 ) );
   generate_block();
   // Second pool FIRST (pending txs — sealed by the helper's blocks and
   // surviving them; the helper's parity seeding is a direct modify and
   // must come last, since any later generate_block would reset pending
   // and wipe it per db_block.cpp:423).
   const price cer2 = price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) );
   const asset_id_type sid2 = create_user_issued_asset(
      "G2RPS2", dan, charge_market_fee, cer2, 2, 0 ).get_id();
   g2_wallet_ctx c = T_wallet_funded_pool( *this, dan, dan_private_key, "G2RP" );
   const liquidity_pool_id_type pool2_id = create_liquidity_pool(
      dan.get_id(), c.pool.asset_a, c.pool.asset_b, sid2, 0, 0 ).get_id();
   issue_uia( dan, asset( 3000000, c.pool.asset_a ) );
   issue_uia( dan, asset( 3000000, c.pool.asset_b ) );
   deposit_to_liquidity_pool( dan.get_id(), pool2_id,
      asset( 1000000, c.pool.asset_a ), asset( 1000000, c.pool.asset_b ) );
   set_expiration( db, trx );
   stealth_pool_exchange_operation op =
      T_wallet_honest_swap( db, c, 5, "g2-rp-sp", 50 );
   op.pool = pool2_id; // re-target at the sibling pool (pin binds pool1)
   trx.operations = { op };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "pool-retargeted swap was ACCEPTED" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE(
         e.to_detail_string().find( "value-pin" ) != std::string::npos,
         e.to_detail_string() );
   }
   trx.clear();
   BOOST_CHECK_EQUAL( c.pool.pool( db ).balance_a.value, 1000000 );
   BOOST_CHECK_EQUAL( c.pool.pool( db ).balance_b.value, 1000000 );
   BOOST_CHECK_EQUAL( pool2_id( db ).balance_a.value, 1000000 );
   BOOST_CHECK_EQUAL( pool2_id( db ).balance_b.value, 1000000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( wallet_poolswap_retarget_amount )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_wallet_ctx c = T_wallet_funded_pool( *this, dan, dan_private_key, "G2RA" );
   stealth_pool_exchange_operation op =
      T_wallet_honest_swap( db, c, 5, "g2-ra-sp", 50 );
   // Claim one unit more than proven (pin binds the true 1000).
   op.amount_to_sell.amount = c.pool.each + 1;
   trx.operations = { op };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "amount-retargeted swap was ACCEPTED" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE(
         e.to_detail_string().find( "value-pin" ) != std::string::npos,
         e.to_detail_string() );
   }
   trx.clear();
   BOOST_CHECK_EQUAL( c.pool.pool( db ).balance_a.value, 1000000 );
   BOOST_CHECK_EQUAL( c.pool.pool( db ).balance_b.value, 1000000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( wallet_poolswap_retarget_counterasset )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   // Third asset FIRST (pending tx; the helper's seeding must stay last —
   // any later generate_block would wipe it per db_block.cpp:423).
   const price cer3 = price( asset( 1, asset_id_type( 1 ) ), asset( 1 ) );
   const asset_id_type aid_c = create_user_issued_asset(
      "G2RCC", dan, charge_market_fee, cer3, 2, 0 ).get_id();
   g2_wallet_ctx c = T_wallet_funded_pool( *this, dan, dan_private_key, "G2RC" );
   set_expiration( db, trx );
   stealth_pool_exchange_operation op =
      T_wallet_honest_swap( db, c, 5, "g2-rc-sp", 50 );
   // Pay out to a third asset (pair gate binds the pool's B leg).
   op.min_to_receive = asset( op.min_to_receive.amount.value, aid_c );
   trx.operations = { op };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "counter-asset-retargeted swap was ACCEPTED" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE(
         e.to_detail_string().find( "Asset type mismatch" ) != std::string::npos,
         e.to_detail_string() );
   }
   trx.clear();
   BOOST_CHECK_EQUAL( c.pool.pool( db ).balance_a.value, 1000000 );
   BOOST_CHECK_EQUAL( c.pool.pool( db ).balance_b.value, 1000000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_CASE( wallet_poolswap_retarget_output )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_wallet_ctx c = T_wallet_funded_pool( *this, dan, dan_private_key, "G2RO" );
   stealth_pool_exchange_operation op =
      T_wallet_honest_swap( db, c, 5, "g2-ro-sp", 50 );
   // Re-target the output commitment (ring message binds the outputs).
   op.output.commitment.data()[0] ^= 0x01;
   trx.operations = { op };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "output-retargeted swap was ACCEPTED" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE(
         e.to_detail_string().find( "Ring signature does not verify" )
            != std::string::npos,
         e.to_detail_string() );
   }
   trx.clear();
   BOOST_CHECK_EQUAL( c.pool.pool( db ).balance_a.value, 1000000 );
   BOOST_CHECK_EQUAL( c.pool.pool( db ).balance_b.value, 1000000 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// ---- EE-1 (Rule R, spec 2026-10-10-stealth-entropy-economics §4) ----
// RED: stealth_subsidy_output_count is undeclared (compile failure).
//
// The classifier returns the output count the SUBSIDY gap may be computed on.
// It never touches the fee floor (stealth_cost_anchor_core) and callers pass
// subsidy_n = min(n_blind_outputs, classifier(op)) so the cap can only shrink
// the gap. EE-1b (review F-1): the model is the chain's OWN live-set counter —
// what the evaluators actually pass to stealth_pool_count_add — NOT the
// pre-Task-3 "every op consumes its inputs" reading of spec §1:
//
//   RING spends consume NOTHING: the coupled `pool_count_add(...,-1)` was
//   retired together with the whole-ring spent write
//   (stealth_evaluator.cpp:769-771), so ring members stay decoy-eligible and
//   only the new outputs join the count (:791). ΔD_a = +n_out.
//   EXPLICIT spends really do consume: `-spent_counted` at
//   confidential_evaluator.cpp:185 (op41) and stealth_evaluator.cpp:1924
//   (op108). ΔD_a = n_out - n_in.
//
//   op39 deposit         +n     -> n
//   op40  blind_transfer +n     -> n      (m-in/m-out GROWS D_a by m)
//   op104 stealth        +n     -> n      (m-in/m-out GROWS D_a by m)
//   op106 turnstile       0     -> 1      (-1/+1 nets zero; one new output)
//   op109 swap            0     -> 1      (rotates A->B; one counter output)
//   op41  blind->clear   -n     -> 0      (carries no outputs member at all)
//   op108 blind->blind   net   -> n when net > 0, else min(n_out, 1)
//   op108 exit leg       -n     -> 0
//   unknown op            -     -> 0, fail closed
BOOST_AUTO_TEST_CASE( subsidy_rule_table )
{ try {
   // --- op39 transfer_to_blind (deposit): the only net source, unsubsidized
   // per-output component is PRESERVED (growth).
   {
      transfer_to_blind_operation o1;
      o1.outputs.resize( 1 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( o1 ) ), 1u );
      transfer_to_blind_operation o8;
      o8.outputs.resize( 8 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( o8 ) ), 8u );
   }
   // --- op41 transfer_from_blind (exit): the op carries NO blind outputs
   // member at all, so n_out is 0 and the classifier returns 0 on every shape,
   // preserving the existing literal `0` passed at
   // confidential_evaluator.cpp:156-159 (require) and :186-190 (consume).
   {
      transfer_from_blind_operation o;
      o.inputs.resize( 1 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( o ) ), 0u );
   }
   // --- op40 blind_transfer: a ring spend CONSUMES NOTHING
   // (stealth_evaluator.cpp:769-771), so ΔD_a = +n_out and the classifier
   // ignores inputs entirely. 1-1-1 -> 1; 1-in-8-out -> 8; 8-in-8-out is NOT
   // consolidation under the chain's own counter (it grows D_a by 8) -> 8.
   {
      blind_transfer_operation o;
      o.inputs.resize( 1 );
      o.outputs.resize( 1 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( o ) ), 1u );
      blind_transfer_operation grow;
      grow.inputs.resize( 1 );
      grow.outputs.resize( 8 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( grow ) ), 8u );
      blind_transfer_operation consol;
      consol.inputs.resize( 8 );
      consol.outputs.resize( 8 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( consol ) ), 8u );
   }
   // --- op104 stealth_transfer: same live-set model as op40 (the ring spend
   // at stealth_evaluator.cpp:791 adds outputs.size() and nothing else).
   {
      stealth_transfer_operation o;
      o.inputs.resize( 1 );
      o.outputs.resize( 8 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( o ) ), 8u );
      stealth_transfer_operation consol;
      consol.inputs.resize( 8 );
      consol.outputs.resize( 8 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( consol ) ), 8u );
   }
   // --- op106 turnstile_reproof: exactly one migrated output (n_out = 1);
   // its counter nets zero (-1/+1 at :1069-1071), so 1 is correct under the
   // ring model and the explicit model alike.
   {
      turnstile_reproof_operation o;
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( o ) ), 1u );
   }
   // --- op108 stealth_explicit_spend: an explicit spend DOES consume
   // (-spent_counted at :1924), so it uses the net rule. net > 0 is real live-
   // set growth and keeps the full component; net <= 0 is circulation and
   // falls back to the base fee (the intentional conservatism of review F-2);
   // the exit leg has no outputs at all -> 0.
   {
      stealth_explicit_spend_operation grow;
      grow.inputs.resize( 1 );
      grow.outputs.resize( 4 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( grow ) ), 4u );
      stealth_explicit_spend_operation shrink;
      shrink.inputs.resize( 6 );
      shrink.outputs.resize( 4 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( shrink ) ), 1u );
      stealth_explicit_spend_operation flat;
      flat.inputs.resize( 4 );
      flat.outputs.resize( 4 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( flat ) ), 1u );
      stealth_explicit_spend_operation exit_leg;
      exit_leg.inputs.resize( 1 );
      exit_leg.outputs.resize( 0 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( exit_leg ) ), 0u );
   }
   // --- op109 stealth_pool_exchange: singular input/output (NOT vectors) --
   // 1-in/1-out -> circulation -> base fee only (1).
   {
      stealth_pool_exchange_operation o;
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( o ) ), 1u );
   }
   // --- Unknown ops fail CLOSED (0), never grant a subsidy.
   {
      transfer_operation plain;
      plain.amount = asset( 1, asset_id_type() );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( plain ) ), 0u );
      transfer_from_blind_operation exitop;
      transfer_to_blind_operation deposit;
      // A zero-output deposit is degenerate; classifier returns 0, and the
      // caller-side min() keeps the gap non-growing regardless.
      deposit.outputs.resize( 0 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( deposit ) ), 0u );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( exitop ) ), 0u );
   }
} FC_CAPTURE_AND_RETHROW() }

// ============================================================================
// EE-2: adversarial + regression suite for Rule R.
//
// The production behaviour under test (EE-1 bed7c6ef, EE-1b 529968a1) is
// ALREADY BUILT, so this suite is a regression/attack suite, not a TDD-red
// feature build: the RED evidence demanded by the brief is GUARD DELETION —
// mutate the load-bearing production line, watch the named case go RED, revert.
// Every case below names the line it pins in its guard-deletion note.
//
// Two invariants carry the whole mechanism and are what EE-2 exists to pin:
//
//   (FLOOR)  Both floor legs — stealth_require_blind_fee (stealth_evaluator.cpp
//            :1410) and stealth_consume_parity_subsidy (:1433) — compute the
//            cost anchor from the op's REAL n_blind_outputs. subsidy_n caps
//            the DISCOUNT only. If a caller ever passed the capped value as
//            n_blind_outputs, a user's required fee would silently drop.
//
//   (DISC)   The gap is anchor(min(n_blind_outputs, subsidy_n)) - parity, so
//            the classifier can only SHRINK it, never grow it.
//
// TEST-GENESIS FEE ARITHMETIC (everything below depends on it). The chain_test
// genesis sets fees.scale == 0, which maps EVERY schedule entry to 0, so:
//   parity_core  = 0 for every stealth op,
//   anchor(n)    = max(current leg 0, pinned 5 CORE + n * 5 CORE) = (n+1)*500000.
// Hence gap(n, subsidy_n) = (min(n, subsidy_n) + 1) * 500000 exactly, and
// every gap in this file is asserted as an exact integer, never a range.
// ============================================================================

// EE-2 test-only helper: one op39 deposit of `values` CORE total, split into
// one range-proven blind balance per value, all owned by `owner`.
//
// The shape is the wire shape transfer_to_blind_operation::validate() demands:
// outputs SORTED by commitment id, and ONE summed blinding factor (the sum of
// the output blinds) because the op commits the public amount, not the fee.
//
// The fee is TRANSPARENT and paid by `from` — that is what makes the float
// rule reachable for a deposit at all (a ring/explicit spend pays its fee out
// of the blind surplus, which is dust in these fixtures). Post-hardfork with an
// EMPTY parity pool the deposit must therefore pay the anchor for its own
// output count, and takes the cost path (no subsidy debit).
struct ee_bal
{
   fc::ecc::commitment_type commit;
   fc::sha256               blind;
   int64_t                  value = 0;
   authority                owner = authority();
};

static std::vector<ee_bal> T_ee_deposit( database_fixture& f, account_id_type from,
      const fc::ecc::private_key& from_key, const authority& owner,
      const std::string& tag, const std::vector<int64_t>& values, int64_t fee )
{
   database& db = f.db;
   signed_transaction& trx = f.trx;
   const asset_object& core = asset_id_type()( db );
   int64_t total = 0;
   for( int64_t v : values )
   {
      BOOST_REQUIRE( v > 0 );
      total += v;
   }
   transfer_to_blind_operation ttb;
   ttb.amount = core.amount( total );
   ttb.from = from;
   ttb.fee = core.amount( fee );
   std::vector<ee_bal> r;
   BIGNUM* acc = BN_new();
   BN_zero( acc );
   for( size_t i = 0; i < values.size(); ++i )
   {
      fc::sha256 B = T_blind_secret( tag + "-b|" + std::to_string( i ) );
      BIGNUM* b = T_bn( B );
      BN_mod_add( acc, acc, b, T_order(), T_ctx() );
      BN_free( b );
      blind_output o;
      o.owner = owner;
      o.commitment = fc::ecc::blind( B, values[i] );
      o.range_proof = fc::ecc::range_proof_sign( 0, o.commitment, B,
                          T_secret( tag + "-n|" + std::to_string( i ) ), 0, 0, values[i] );
      ttb.outputs.push_back( o );
      r.push_back( ee_bal{ o.commitment, B, values[i], owner } );
   }
   std::sort( ttb.outputs.begin(), ttb.outputs.end(),
              []( const blind_output& a, const blind_output& b ) {
                 return a.commitment < b.commitment;
              } );
   std::vector<char> b32( 32 );
   BN_bn2binpad( acc, (unsigned char*)b32.data(), 32 );
   ttb.blinding_factor = fc::sha256( b32.data(), 32 );
   BN_free( acc );
   set_expiration( db, trx );
   // Clear FIRST: a caller that catches a refusal leaves this trx dirty (the
   // push threw before the cleanup below), and a stale signature would make the
   // NEXT push fail with tx_irrelevant_sig instead of the guard under test.
   trx.clear_signatures();
   trx.operations.clear();
   trx.operations = { ttb };
   f.sign( trx, from_key );
   // PUSH_TX rethrows, so a caller that expects a refusal wraps this helper in
   // BOOST_CHECK_THROW; no assertion here (swallowing would hide which guard).
   PUSH_TX( db, trx );
   trx.clear_signatures();
   trx.operations.clear();
   return r;
}

// EE-2 test-only helper: generalized op104 (stealth_transfer) ring spend.
// Spends pool outputs `ins` (p.each each) into `outs` new V2 BP+ outputs plus
// `fee`. Mirrors t5_build_spend (1-in/2-out) with the SHAPE parameterised, so
// Rule R can be exercised at 1-in/8-out (growth) and m-in/m-out (the shape the
// pre-EE-1b reading would have called "consolidation"). Per input: a real dual-
// version ring signature over the full ring, bound to the SAME output set and
// fee (stealth_ring_message), excess = sum(in blinds) - sum(out blinds) so the
// conservation kernel closes.
static stealth_transfer_operation T_ee_build_spend( const asset_object& core,
      const t5_pool& p, const std::vector<size_t>& ins,
      const std::vector<int64_t>& outs, int64_t fee, uint8_t version,
      const std::string& tag )
{
   BOOST_REQUIRE( !ins.empty() && ins.size() <= 8 );
   BOOST_REQUIRE( !outs.empty() && outs.size() <= 8 );
   int64_t in_total = 0, out_total = 0;
   for( size_t s : ins )
      in_total += p.each;
   for( int64_t v : outs )
   {
      BOOST_REQUIRE( v > 0 );
      out_total += v;
   }
   BOOST_REQUIRE_EQUAL( in_total, out_total + fee );

   const uint8_t alt_v = ( version == GRAPHENE_STEALTH_PROOF_V1 )
                         ? GRAPHENE_STEALTH_PROOF_V2
                         : GRAPHENE_STEALTH_PROOF_V1;
   std::vector<fc::sha256> Bk( outs.size() );
   std::vector<stealth_blind_output> sout( outs.size() );
   std::vector<fc::ecc::commitment_type> out_cs;
   for( size_t i = 0; i < outs.size(); ++i )
   {
      Bk[i] = T_blind_secret( tag + "-o|" + std::to_string( i ) );
      sout[i].commitment = fc::ecc::blind( Bk[i], outs[i] );
      if( version == GRAPHENE_STEALTH_PROOF_V1 )
         sout[i].range_proof = fc::ecc::range_proof_sign( 0, sout[i].commitment, Bk[i],
                              T_secret( tag + "-n|" + std::to_string( i ) ), 0, 0, outs[i] );
      else
         sout[i].range_proof = T_bp_prove( sout[i].commitment, Bk[i], (uint64_t)outs[i] );
      auto rk = fc::ecc::private_key::generate();
      sout[i].owner = authority( 1, public_key_type( rk.get_public_key() ), 1 );
      out_cs.push_back( sout[i].commitment );
   }
   stealth_transfer_operation stop;
   stop.asset_id = core.get_id();
   stop.proof_version = version;
   stop.fee = core.amount( fee );
   stop.outputs = sout;
   // Fresh pseudo-output blinds, one per input. The ring kernel runs over the
   // PSEUDO-OUTPUTS (stealth_evaluator.cpp:730 passes in.pseudo_output), so the
   // excess is sum(pseudo blinds) - sum(output blinds) — NOT the input blinds
   // (op108's kernel is the other kernel and does use them).
   std::vector<fc::sha256> Bps( ins.size() );
   for( size_t k = 0; k < ins.size(); ++k )
      Bps[k] = T_blind_secret( tag + "-ps|" + std::to_string( k ) );
   {
      BIGNUM* acc = BN_new();
      BN_zero( acc );
      for( const auto& P : Bps )
      {
         BIGNUM* bp = T_bn( P );
         BN_mod_add( acc, acc, bp, T_order(), T_ctx() );
         BN_free( bp );
      }
      for( const auto& B : Bk )
      {
         BIGNUM* b = T_bn( B );
         BN_mod_sub( acc, acc, b, T_order(), T_ctx() );
         BN_free( b );
      }
      unsigned char eb[32];
      BN_bn2binpad( acc, eb, 32 );
      std::copy( eb, eb + 32, (char*)stop.excess.data() );
      BN_free( acc );
   }
   std::vector<std::vector<unsigned char>> Q;
   for( const auto& c : p.commits )
      Q.push_back( std::vector<unsigned char>( c.begin(), c.end() ) );
   for( size_t k = 0; k < ins.size(); ++k )
   {
      const size_t s = ins[k];
      BIGNUM* bs = T_bn( p.blinds[s] );
      BIGNUM* bprime = T_bn( Bps[k] );
      auto dry = T_dual_dry_run( version, alt_v, Q, s, bs, (uint64_t)p.each, bprime );
      auto Pv = T_commit( bprime, (uint64_t)p.each );
      BOOST_REQUIRE( dry.pseudo == Pv );
      fc::ecc::commitment_type pseudo_c = T_commitment( Pv );
      std::vector<char> img_c( dry.img_main.begin(), dry.img_main.end() );
      std::vector<char> img_a( dry.img_alt.begin(), dry.img_alt.end() );
      fc::sha256 m = stealth_ring_message( version, stop.asset_id, img_c, p.commits,
                                           pseudo_c, out_cs, stop.fee.amount );
      fc::sha256 ma = stealth_ring_message( alt_v, stop.asset_id, img_a, p.commits,
                                            pseudo_c, out_cs, stop.fee.amount );
      std::string ms( (const char*)m.data(), 32 );
      std::string msa( (const char*)ma.data(), 32 );
      stop.inputs.push_back( T_make_dual_ring_input( version, alt_v, Q, s, bs,
                            (uint64_t)p.each, bprime, ms, msa ) );
      BN_free( bs );
      BN_free( bprime );
   }
   return stop;
}

// EE-2 test-only helper: generalized op108 blind->blind explicit spend over
// arbitrary live blind balances (not just a t5_pool), TRUE recovery images
// per input, V2 BP+ outputs, excess = sum(in blinds) - sum(out blinds).
// Mirrors T_op108_blind_true (1-in/2-out) with the shape parameterised.
static stealth_explicit_spend_operation T_ee_op108_blind( const asset_object& core,
      const std::vector<ee_bal>& ins, const std::vector<int64_t>& outs,
      int64_t fee, const std::string& tag, const authority& out_owner )
{
   BOOST_REQUIRE( !ins.empty() && ins.size() <= 8 );
   BOOST_REQUIRE( !outs.empty() && outs.size() <= 8 );
   int64_t in_total = 0, out_total = 0;
   for( const auto& in : ins )
      in_total += in.value;
   for( int64_t v : outs )
   {
      BOOST_REQUIRE( v > 0 );
      out_total += v;
   }
   BOOST_REQUIRE_EQUAL( in_total, out_total + fee );

   stealth_explicit_spend_operation o;
   o.fee = core.amount( fee );
   o.asset_id = core.get_id();
   o.proof_version = GRAPHENE_STEALTH_PROOF_V2;
   for( const auto& in : ins )
   {
      stealth_spend_input si;
      si.commitment = in.commit;
      si.owner = in.owner; // op108 asserts input owner == the live balance's
      BIGNUM* bb = T_bn( in.blind );
      std::vector<unsigned char> Cvec( in.commit.begin(), in.commit.end() );
      std::vector<char> proof;
      T_prove_recovery( Cvec, bb, (uint64_t)in.value, core.get_id(),
                        si.key_image_v1, si.key_image_v2, proof );
      BN_free( bb );
      si.recovery_proof = stealth_recovery_proof( proof );
      o.inputs.push_back( si );
   }
   std::vector<fc::sha256> Bk( outs.size() );
   for( size_t i = 0; i < outs.size(); ++i )
   {
      Bk[i] = T_blind_secret( tag + "-o|" + std::to_string( i ) );
      stealth_blind_output so;
      {
         BIGNUM* b = T_bn( Bk[i] );
         so.commitment = T_commitment( T_commit( b, (uint64_t)outs[i] ) );
         BN_free( b );
      }
      so.range_proof = T_bp_prove( so.commitment, Bk[i], (uint64_t)outs[i] );
      so.owner = out_owner;
      o.outputs.push_back( so );
   }
   {
      BIGNUM* acc = BN_new();
      BN_zero( acc );
      for( const auto& in : ins )
      {
         BIGNUM* b = T_bn( in.blind );
         BN_mod_add( acc, acc, b, T_order(), T_ctx() );
         BN_free( b );
      }
      for( const auto& B : Bk )
      {
         BIGNUM* b = T_bn( B );
         BN_mod_sub( acc, acc, b, T_order(), T_ctx() );
         BN_free( b );
      }
      unsigned char eb[32];
      BN_bn2binpad( acc, eb, 32 );
      std::copy( eb, eb + 32, (char*)o.excess.data() );
      BN_free( acc );
   }
   return o;
}

// EE-2 test-only helper: op108 TRANSPARENT EXIT leg (no outputs) over one
// live blind balance, TRUE recovery images, conservation against op41's
// verify_sum kernel (in value == amount + fee), excess == the input blind.
static stealth_explicit_spend_operation T_ee_op108_exit( const asset_object& core,
      const ee_bal& in, account_id_type to, int64_t amount, int64_t fee )
{
   BOOST_REQUIRE_EQUAL( in.value, amount + fee );
   stealth_explicit_spend_operation o;
   o.fee = core.amount( fee );
   o.asset_id = core.get_id();
   o.to = to;
   o.amount = core.amount( amount );
   o.proof_version = GRAPHENE_STEALTH_PROOF_V2;
   o.excess = in.blind;
   stealth_spend_input si;
   si.commitment = in.commit;
   si.owner = in.owner;
   BIGNUM* bb = T_bn( in.blind );
   std::vector<unsigned char> Cvec( in.commit.begin(), in.commit.end() );
   std::vector<char> proof;
   T_prove_recovery( Cvec, bb, (uint64_t)in.value, core.get_id(),
                     si.key_image_v1, si.key_image_v2, proof );
   BN_free( bb );
   si.recovery_proof = stealth_recovery_proof( proof );
   o.inputs = { si };
   return o;
}

// EE-2 helper: run `f`, REQUIRE that it throws, and REQUIRE that the message
// names the guard under test. One place, so deleting a guard reports WHICH
// guard stopped firing instead of cascading BOOST_FAILs out of a catch block.
template<typename F>
static void T_ee_expect_refusal( F&& f, const std::string& needle,
                                 const std::string& what )
{
   std::string msg;
   bool threw = false;
   try
   {
      f();
   }
   catch( const fc::exception& e )
   {
      threw = true;
      msg = e.to_detail_string();
   }
   BOOST_REQUIRE_MESSAGE( threw, what );
   BOOST_CHECK_MESSAGE( msg.find( needle ) != std::string::npos, what + ": " + msg );
}

// EE-2 shared read: the parity pool balance for `aid` (0 when absent).
static int64_t T_ee_pool( database& db, asset_id_type aid )
{
   const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
   auto itr = st.parity_pool.find( aid );
   return ( itr == st.parity_pool.end() ) ? 0 : itr->second.value;
}

// ---------------------------------------------------------------------------
// Test 9 — subsidy_prefork_inert.
//
// Rule R and the whole G1c mechanism live INSIDE the two subsidy functions,
// which are stealth_passed()-gated (stealth_evaluator.cpp:1401 / :1423).
// Pre-fork both must be exact no-ops: no subsidy consumed, no pool movement,
// NO FLOOR — a blind op paying zero must still clear, even though the
// post-hardfork anchor for that same shape is 5 CORE per output. The contrast
// leg (identical op, post-fork, empty pool) is what makes the pin meaningful:
// without the gate the pre-fork leg would refuse.
//
// Legacy ops only: op39/op41 exist pre-fork (op40+ are refused outright by the
// V-03 pre-fork gate, already pinned by stealth_ops_are_refused_before_the_hardfork).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( subsidy_prefork_inert )
{ try {
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()( db ), dan, core.amount( 100000000 ) );
   set_expiration( db, trx );
   const account_id_type payer = dan_id;
   auto ok = fc::ecc::private_key::generate();
   const authority own( 1, public_key_type( ok.get_public_key() ), 1 );

   // A pre-fork fee of ZERO clears, even though the post-hardfork anchor for
   // the same shape is 10 CORE. That gap IS the float rule; pre-fork it must
   // not exist.
   const int64_t anchor1 = stealth_cost_anchor_core( db, 1 ).value;
   BOOST_REQUIRE_EQUAL( anchor1, (int64_t)( 10 * GRAPHENE_BLOCKCHAIN_PRECISION ) );

   // op41 conservation is exact at validate time (the input must commit
   // amount + fee), so the blind balance is worth exactly what the exit pays.
   std::vector<ee_bal> pre = T_ee_deposit( *this, payer, dan_private_key, own,
                                           "ee9-pre", { 900 }, 0 );
   BOOST_REQUIRE_EQUAL( pre.size(), 1u );
   BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), 0 );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK( st.parity_pool.find( core_id ) == st.parity_pool.end() );
      BOOST_CHECK( st.interval_granted.find( core_id ) == st.interval_granted.end() );
   }
   // Pre-fork withdrawal at fee 0 clears too (n = 0 -> anchor(0) = 5 CORE).
   {
      transfer_from_blind_operation x;
      x.to = payer;
      x.amount = core.amount( 900 );
      x.fee = core.amount( 0 );
      blind_input bi;
      bi.commitment = pre[0].commit;
      bi.owner = own;
      x.inputs = { bi };
      x.blinding_factor = pre[0].blind;
      set_expiration( db, trx );
      trx.operations = { x };
      sign( trx, ok );
      PUSH_TX( db, trx );
      trx.clear_signatures();
      trx.operations.clear();
   }
   BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), 0 );

   // --- the subsidy surface itself is inert pre-fork, called directly ---
   BOOST_CHECK( !stealth_parity_available( db, core_id, share_type( anchor1 ) ) );
   BOOST_CHECK_NO_THROW( stealth_require_blind_fee( db, share_type( 0 ), true, core_id,
                                                   8, share_type( 0 ), 0 ) );
   BOOST_CHECK_NO_THROW( stealth_require_blind_fee( db, share_type( 0 ), true, core_id,
                                                   8, share_type( 0 ), 8 ) );
   {
      const int64_t acc0 = core.dynamic_asset_data_id( db ).accumulated_fees.value;
      BOOST_CHECK_NO_THROW( stealth_consume_parity_subsidy( db, true, core_id, 8,
                                                           share_type( 0 ),
                                                           share_type( 0 ), 0 ) );
      BOOST_CHECK_NO_THROW( stealth_consume_parity_subsidy( db, true, core_id, 8,
                                                           share_type( 0 ),
                                                           share_type( 0 ), 8 ) );
      BOOST_CHECK_EQUAL( core.dynamic_asset_data_id( db ).accumulated_fees.value, acc0 );
      BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), 0 );
   }
   // Pre-fork, even an opted-in CORE routes nothing (the routing leg is gated
   // separately at stealth_parity_route_fee) — no pool is created pre-fork.
   {
      g1c_opt_in_parity( db, core_id );
      share_type inc = 1000000;
      BOOST_CHECK_EQUAL( stealth_parity_route_fee( db, core_id, inc ).value, 0 );
      BOOST_CHECK_EQUAL( inc.value, 1000000 );
      BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), 0 );
   }

    // --- contrast: the IDENTICAL deposit POST-fork with an empty pool floats
    // --- to cost. This is what makes the pre-fork acceptance above load-bearing.
    generate_blocks( HARDFORK_STEALTH_TIME );
    generate_block();
    set_expiration( db, trx );
    // C1-followup (cold-start A3): the pre-fork deposit above was never counted
    // (stealth_pool_count_add no-ops pre-fork), so depth here is 0 and every
    // deposit below would read cold (cold_n = 0, floor anchor(0)) — the
    // anchor1-1 leg would CLEAR instead of refusing. Seed to the floor first:
    // 11 singles at the exact anchor(1) cost, so the contrast pins the REAL-n
    // floor verbatim and the pool stays empty (cost path throughout).
    for( int i = 0; i < 11; ++i )
       BOOST_REQUIRE_EQUAL(
          T_ee_deposit( *this, payer, dan_private_key, own,
                        "ee9-seed|" + std::to_string( i ), { 500 }, anchor1 ).size(), 1u );
    BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core_id ), 11u );
    BOOST_CHECK_THROW(
      T_ee_deposit( *this, payer, dan_private_key, own, "ee9-post", { 1000 }, 0 ),
      fc::exception );
   BOOST_REQUIRE_EQUAL(
      T_ee_deposit( *this, payer, dan_private_key, own, "ee9-post2", { 1000 }, anchor1 ).size(),
      1u );
   // One unit short of the anchor refuses: post-fork the floor exists and is
   // anchor(REAL n) — never lower, and never the classifier's capped value.
   BOOST_CHECK_THROW(
      T_ee_deposit( *this, payer, dan_private_key, own, "ee9-post3", { 1000 }, anchor1 - 1 ),
      fc::exception );
   BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), 0 ); // still no pool: cost path
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 10 — subsidy_never_raises_fee.
//
// The behavioural complement of tooling/verify_stealth_cost_anchor_unchanged.py
// (which pins the anchor FUNCTION byte-for-byte). That tool cannot see the call
// sites, so this pins the consequence: for every op shape the required fee with
// an EMPTY pool is anchor(REAL n_blind_outputs) and nothing else.
//
// Two levels:
//   (a) function level — the floor leg ignores subsidy_n completely: paying
//       anchor(n)-1 throws and anchor(n) clears for EVERY subsidy_n in [0, n],
//       so no caller can lower a floor by choosing a smaller cap.
//   (b) op level — real op39 deposits at n = 1, 2 and 8 (transparent fee, so the
//       cost path is reachable at all) refuse one unit under the anchor and clear
//       exactly at it, with the pool still empty afterwards.
// Plus the monotonicity identity: Rule R's capped gap never exceeds the pre-EE-1
// (uncapped) gap, for every op shape the classifier knows.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( subsidy_never_raises_fee )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()( db ), dan, core.amount( 100000000 ) );
   generate_block(); // seal: direct writes below must survive block replay
   // An 8-output V1 deposit carries 8 legacy range proofs; the genesis tx size
   // limit would reject it before the float rule ever runs.
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      p.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   const authority own( 1, dan_id, 1 );
   BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), 0 ); // EMPTY pool fixture

   // --- (a) the floor leg is independent of subsidy_n ----------------------
   for( uint32_t n : { 0u, 1u, 2u, 3u, 8u } )
   {
      const share_type anchor = stealth_cost_anchor_core( db, n );
      BOOST_REQUIRE_EQUAL( anchor.value,
                          (int64_t)( 5 * GRAPHENE_BLOCKCHAIN_PRECISION ) * (int64_t)( n + 1 ) );
      // subsidy_n <= n by construction (every call site passes min(n, classifier)),
      // so 1 is not a shape an exit (n == 0) can ever produce.
      const std::vector<uint32_t> subs =
         ( n == 0 ) ? std::vector<uint32_t>{ 0u } : std::vector<uint32_t>{ 0u, 1u, n };
      for( uint32_t sub : subs )
      {
         BOOST_CHECK_THROW(
            stealth_require_blind_fee( db, anchor - 1, true, core_id, n,
                                       share_type( 0 ), sub ),
            fc::exception );
         BOOST_CHECK_NO_THROW(
            stealth_require_blind_fee( db, anchor, true, core_id, n,
                                       share_type( 0 ), sub ) );
      }
   }
   // --- monotonicity: Rule R's capped gap <= the pre-EE-1 (uncapped) gap ---
   {
      const share_type parity = share_type( 200000 );
      auto check = [&]( const operation& op, uint32_t n ) {
         const uint32_t sub = stealth_subsidy_output_count( op );
         BOOST_REQUIRE_MESSAGE( sub <= n, "classifier above the op's own n" );
         const share_type capped = stealth_parity_gap_core( db, n, parity, sub );
         const share_type uncapped = stealth_parity_gap_core( db, n, parity, n );
         BOOST_CHECK_MESSAGE( capped.value <= uncapped.value,
            "Rule R raised the gap above the pre-EE-1 (uncapped) gap" );
      };
      transfer_to_blind_operation dep; dep.outputs.resize( 8 );
      check( operation( dep ), 8u );
      stealth_transfer_operation ring; ring.inputs.resize( 8 ); ring.outputs.resize( 8 );
      check( operation( ring ), 8u );
      blind_transfer_operation bt; bt.inputs.resize( 3 ); bt.outputs.resize( 3 );
      check( operation( bt ), 3u );
      stealth_explicit_spend_operation net0; net0.inputs.resize( 8 ); net0.outputs.resize( 3 );
      check( operation( net0 ), 3u );
      stealth_pool_exchange_operation swap;
      check( operation( swap ), 1u );
      turnstile_reproof_operation turn;
      check( operation( turn ), 1u );
      transfer_from_blind_operation exitop; exitop.inputs.resize( 2 );
      check( operation( exitop ), 0u );
   }
    // --- (b) op level: the floor is anchor(REAL n) --------------------------
    // C1-followup (cold-start A3): levels (a) and monotonicity above are pure
    // function calls, so depth here is still 0 and every deposit below would
    // read cold (floor anchor(0), so anchor(n)-1 would CLEAR instead of
    // refusing). Seed to the floor first: 11 singles at the exact anchor(1)
    // cost, so the loop pins the REAL-n floor verbatim and the pool stays
    // empty (cost path throughout). Level (a) is untouched.
    {
       const share_type seed_anchor = stealth_cost_anchor_core( db, 1 );
       BOOST_REQUIRE_EQUAL( seed_anchor.value, 1000000 );
       for( int i = 0; i < 11; ++i )
          BOOST_REQUIRE_EQUAL(
             T_ee_deposit( *this, dan_id, dan_private_key, own,
                           "ee10-seed|" + std::to_string( i ), { 100 },
                           seed_anchor.value ).size(), 1u );
       BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core_id ), 11u );
    }
    for( uint32_t n : { 1u, 2u, 8u } )
   {
      const share_type anchor = stealth_cost_anchor_core( db, n );
      const std::vector<int64_t> vals( n, 100 );
      // One unit under the anchor: refused, pool still empty.
      BOOST_CHECK_THROW(
         T_ee_deposit( *this, dan_id, dan_private_key, own,
                       "ee10-lo|" + std::to_string( n ), vals, anchor.value - 1 ),
         fc::exception );
      BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), 0 );
      // Exactly at the anchor: clears, still debits nothing (cost path).
      BOOST_REQUIRE_EQUAL(
         T_ee_deposit( *this, dan_id, dan_private_key, own,
                       "ee10-ok|" + std::to_string( n ), vals, anchor.value ).size(),
         (size_t)n );
      BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), 0 );
   }
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 1 — subsidy_floor_leg_receives_real_n.  THE LOAD-BEARING REGRESSION.
//
// op108 is the only call site where the cap can bite (its classifier falls back
// to 1 when n_out <= n_in), so it is the only place the floor and the cap can
// disagree. Two ops differing ONLY in n_blind_outputs — 2-in/2-out (n = 2,
// subsidy_n = 1) and 2-in/1-out (n = 1, subsidy_n = 1) — therefore share the
// SAME capped subsidy (anchor(1) - parity) and must still carry DIFFERENT
// required fees (anchor(2) vs anchor(1)).
//
// Both floor legs are pinned:
//   REQUIRE (:1410)  empty pool -> the 2-output op paying the CAPPED anchor
//                    (1 CORE) refuses; its 1-output twin at the same fee clears.
//   CONSUME (:1433)  funded pool -> the same 2-output op paying anchor(1) is
//                    DEBITED the gap (parity path), while the same op paying
//                    anchor(2) is not (cost path). If the floor leg ever read
//                    subsidy_n, both would be cost paths and neither would be
//                    debited.
//
// GUARD DELETION (observed RED): change either floor leg from
//   stealth_cost_anchor_core( db, n_blind_outputs )
// to stealth_cost_anchor_core( db, subsidy_n ) -> the empty-pool refusal
// disappears (require) and both funded-pool ops become cost paths (consume).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( subsidy_floor_leg_receives_real_n )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()( db ), dan, core.amount( 100000000 ) );
   generate_block(); // seal before the direct writes below
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      p.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   auto ok = fc::ecc::private_key::generate();
   const authority own( 1, public_key_type( ok.get_public_key() ), 1 );

   const int64_t anchor1 = stealth_cost_anchor_core( db, 1 ).value;
   const int64_t anchor2 = stealth_cost_anchor_core( db, 2 ).value;
   BOOST_REQUIRE_EQUAL( anchor1, 1000000 );
   BOOST_REQUIRE_EQUAL( anchor2, 1500000 );

   // Ten 1-CORE blind balances. The parity pool is NEVER seeded in the first
   // phase, so every deposit takes the cost path (pays anchor(1) of its own
   // transparent fee) and nothing is ever funded.
   std::vector<ee_bal> b;
   for( int i = 0; i < 10; ++i )
   {
      auto r = T_ee_deposit( *this, dan_id, dan_private_key, own,
                             "ee1-d|" + std::to_string( i ), { anchor1 }, anchor1 );
      BOOST_REQUIRE_EQUAL( r.size(), 1u );
      b.push_back( r[0] );
   }
   BOOST_REQUIRE_EQUAL( T_ee_pool( db, core_id ), 0 );

   auto push_op108 = [&]( const std::vector<ee_bal>& ins,
                          const std::vector<int64_t>& outs, int64_t fee,
                          const std::string& tag ) {
      stealth_explicit_spend_operation o = T_ee_op108_blind( core, ins, outs, fee, tag, own );
      set_expiration( db, trx );
      trx.clear_signatures();
      trx.operations.clear();
      trx.operations = { o };
      sign( trx, ok );
      PUSH_TX( db, trx );
      trx.clear_signatures();
      trx.operations.clear();
   };

   // --- PHASE 1: EMPTY pool. Only the floor decides. ----------------------
   // 2-in/2-out paying anchor(1) — the anchor its CAPPED subsidy leg would
   // suggest — must refuse: its real floor is anchor(2).
   T_ee_expect_refusal(
      [&]() { push_op108( { b[0], b[1] }, { 500000, 500000 }, anchor1, "ee1-a" ); },
      "Blind fee below cost level",
      "2-output op paying the CAPPED anchor(1) must refuse (its floor is anchor(2))" );
   // Nothing moved: the refusal happened before apply.
   BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), 0 );
   {
      const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
      BOOST_CHECK( bbi.find( b[0].commit ) != bbi.end() );
      BOOST_CHECK( bbi.find( b[1].commit ) != bbi.end() );
   }
   // Same op at its REAL floor (anchor(2)) clears.
   push_op108( { b[0], b[1] }, { 250000, 250000 }, anchor2, "ee1-b" );
   // ... and the 1-output twin at the SAME 1 CORE fee clears: the two ops
   // differ only in n_blind_outputs and their required fees differ with it.
   push_op108( { b[2], b[3] }, { anchor1 }, anchor1, "ee1-c" );
   BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), 0 ); // cost path: pool untouched
   {
      const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
      BOOST_CHECK( bbi.find( b[0].commit ) == bbi.end() );
      BOOST_CHECK( bbi.find( b[2].commit ) == bbi.end() );
   }

   // --- PHASE 2: FUNDED pool. The consume floor leg decides. --------------
   // Seed exactly the one subsidy the next op draws (anchor(1) = 1 CORE).
   generate_block();
   g1c_seed_pool( db, dan_id, core, anchor1 );
   BOOST_REQUIRE_EQUAL( T_ee_pool( db, core_id ), anchor1 );
   const int64_t acc_before = core.dynamic_asset_data_id( db ).accumulated_fees.value;
   // n = 2, subsidy_n = 1, paid = anchor(1) < anchor(2): PARITY path -> the
   // pool is debited the capped gap exactly.
   push_op108( { b[4], b[5] }, { 500000, 500000 }, anchor1, "ee1-d" );
   BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), 0 );
   BOOST_CHECK_EQUAL( core.dynamic_asset_data_id( db ).accumulated_fees.value,
                      acc_before + anchor1 );
   // Same shape at its REAL floor (anchor(2)): COST path -> no debit, no credit.
   g1c_seed_pool( db, dan_id, core, anchor1 );
   BOOST_REQUIRE_EQUAL( T_ee_pool( db, core_id ), anchor1 );
   const int64_t acc1 = core.dynamic_asset_data_id( db ).accumulated_fees.value;
   push_op108( { b[6], b[7] }, { 250000, 250000 }, anchor2, "ee1-e" );
   BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), anchor1 );
   BOOST_CHECK_EQUAL( core.dynamic_asset_data_id( db ).accumulated_fees.value, acc1 );
   // The shape arithmetic this case rests on, pinned explicitly: the CAPPED gap
   // is the same for a 1-output and a 2-output op (both capped to 1), while the
   // UNCAPPED gap — i.e. the floor — differs by exactly one output's component.
   BOOST_CHECK_EQUAL(
      stealth_parity_gap_core( db, 2, share_type( 0 ), 1 ).value, anchor1 );
   BOOST_CHECK_EQUAL(
      stealth_parity_gap_core( db, 1, share_type( 0 ), 1 ).value, anchor1 );
   BOOST_CHECK_EQUAL(
      stealth_parity_gap_core( db, 2, share_type( 0 ), 2 ).value, anchor2 );
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 2 — subsidy_exit_cap_enforced.
//
// S-1 (owner ruling, encoded not re-litigated): exit ops draw a BASE-FEE-SIZED
// gap, never a per-output one. For op41 and for op108's exit leg that means
// n_blind_outputs = 0, so the exact gap is anchor(0) - parity_core and the
// exact floor is anchor(0) — 5 CORE, half of what a single output would cost.
//
// Pins both halves on real ops:
//   floor   (empty pool)   fee anchor(0)-1 refuses, anchor(0) clears, for op41
//                         and for the op108 exit leg;
//   subsidy (funded pool)  fee 0 (parity) is debited exactly anchor(0).
//
// GUARD DELETION (observed RED): the exit cap is enforced by the LITERAL 0 the
// call site passes as n_blind_outputs (confidential_evaluator.cpp require/consume
// for op41) — the classifier's own 0 is redundant behind it. Changing that
// literal to 1 turns every anchor(0) assertion here RED (floor doubles, and the
// exit leg's own op41-conservation/fee split follows it).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( subsidy_exit_cap_enforced )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()( db ), dan, core.amount( 100000000 ) );
   generate_block();
   db.modify( db.get_global_properties(), []( global_property_object& p ) {
      p.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   auto ok = fc::ecc::private_key::generate();
   const authority own( 1, public_key_type( ok.get_public_key() ), 1 );
   const int64_t anchor0 = stealth_cost_anchor_core( db, 0 ).value;
   const int64_t anchor1 = stealth_cost_anchor_core( db, 1 ).value;
   BOOST_REQUIRE_EQUAL( anchor0, 500000 );
   BOOST_REQUIRE_EQUAL( anchor1, 1000000 );

   // op41 inputs must commit amount + fee EXACTLY (validate-time verify_sum),
   // so every (amount, fee) shape needs its own balance.
   auto deposit_exit_fuel = [&]( const std::string& tag, int64_t amount, int64_t fee ) {
      auto r = T_ee_deposit( *this, dan_id, dan_private_key, own, tag,
                             { amount + fee }, anchor1 );
      BOOST_REQUIRE_EQUAL( r.size(), 1u );
      generate_block(); // seal BEFORE grandfathering (T_grandfather note)
      // Post-fork balances refuse the legacy legs by design; the exit-cap leg
      // needs a pre-fork-shaped balance so the FEE rule decides, not the
      // created_block gate (same discipline as parity_pool_routing_and_float).
      T_grandfather( db, core_id, r[0].commit );
      return r[0];
   };
   auto op41_exit = [&]( const ee_bal& in, int64_t amount, int64_t fee ) {
      transfer_from_blind_operation x;
      x.to = dan_id;
      x.amount = core.amount( amount );
      x.fee = core.amount( fee );
      blind_input bi;
      bi.commitment = in.commit;
      bi.owner = own;
      x.inputs = { bi };
      x.blinding_factor = in.blind;
      set_expiration( db, trx );
      trx.clear_signatures();
      trx.operations.clear();
      trx.operations = { x };
      sign( trx, ok );
      PUSH_TX( db, trx );
      trx.clear_signatures();
      trx.operations.clear();
   };

   // --- PHASE 1: EMPTY pool. The exit FLOOR is anchor(0), not anchor(1). ---
   BOOST_REQUIRE_EQUAL( T_ee_pool( db, core_id ), 0 );
   {
      const ee_bal lo = deposit_exit_fuel( "ee2-lo", 900, anchor0 - 1 );
      T_ee_expect_refusal(
         [&]() { op41_exit( lo, 900, anchor0 - 1 ); },
         "Blind fee below cost level",
         "op41 one unit under the base-fee anchor must refuse" );
      BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), 0 );
      op41_exit( deposit_exit_fuel( "ee2-at", 900, anchor0 ), 900, anchor0 );
   }
   // Same for the op108 exit leg (0 outputs by construction).
   {
      const ee_bal lo = deposit_exit_fuel( "ee2-108lo", 900, anchor0 - 1 );
      auto push_exit = [&]( int64_t fee ) {
         stealth_explicit_spend_operation o = T_ee_op108_exit( core, lo, dan_id, 900, fee );
         set_expiration( db, trx );
         trx.clear_signatures();
         trx.operations.clear();
         trx.operations = { o };
         sign( trx, ok );
         PUSH_TX( db, trx );
         trx.clear_signatures();
         trx.operations.clear();
      };
      T_ee_expect_refusal( [&]() { push_exit( anchor0 - 1 ); },
                           "Blind fee below cost level",
                           "op108 exit one unit under the base-fee anchor must refuse" );
      stealth_explicit_spend_operation o2 = T_ee_op108_exit( core,
         deposit_exit_fuel( "ee2-108at", 900, anchor0 ), dan_id, 900, anchor0 );
      set_expiration( db, trx );
      trx.clear_signatures();
      trx.operations.clear();
      trx.operations = { o2 };
      sign( trx, ok );
      PUSH_TX( db, trx );
      trx.clear_signatures();
      trx.operations.clear();
      BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), 0 );
   }

   // --- PHASE 2: FUNDED pool. The exit SUBSIDY is base-fee sized. ---------
   // parity_core is 0 in this genesis, so the exact gap is anchor(0) itself.
   generate_block();
   g1c_seed_pool( db, dan_id, core, 3 * anchor1 );
   BOOST_REQUIRE_EQUAL( T_ee_pool( db, core_id ), 3 * anchor1 );
   {
      const ee_bal sub = deposit_exit_fuel( "ee2-sub", 900, 0 );
      // The funding deposit pays ITS OWN anchor(1), so it is a cost-path op:
      // the pool is not debited (a grant is only drawn when the user pays
      // BELOW the floor). The pool starts this leg at exactly the 3 CORE seed.
      const int64_t pool0 = T_ee_pool( db, core_id );
      BOOST_REQUIRE_EQUAL( pool0, 3 * anchor1 );
      const int64_t acc0 = core.dynamic_asset_data_id( db ).accumulated_fees.value;
      op41_exit( sub, 900, 0 ); // parity level: pool covers the gap
      BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), pool0 - anchor0 );
      BOOST_CHECK_EQUAL( core.dynamic_asset_data_id( db ).accumulated_fees.value,
                         acc0 + anchor0 );
      // Strictly a base-fee-sized gap: never the per-output one.
      BOOST_CHECK_EQUAL( stealth_parity_gap_core( db, 0, share_type( 0 ), 0 ).value, anchor0 );
      BOOST_CHECK( stealth_parity_gap_core( db, 0, share_type( 0 ), 0 ).value
                   < stealth_parity_gap_core( db, 1, share_type( 0 ), 1 ).value );
   }
   // The op108 exit leg draws the same base-fee-sized gap.
   {
      const ee_bal sub = deposit_exit_fuel( "ee2-108sub", 900, 0 );
      const int64_t pool0 = T_ee_pool( db, core_id );
      BOOST_REQUIRE_EQUAL( pool0, 3 * anchor1 - anchor0 );
      const int64_t acc0 = core.dynamic_asset_data_id( db ).accumulated_fees.value;
      stealth_explicit_spend_operation o = T_ee_op108_exit( core, sub, dan_id, 900, 0 );
      set_expiration( db, trx );
      trx.clear_signatures();
      trx.operations.clear();
      trx.operations = { o };
      sign( trx, ok );
      PUSH_TX( db, trx );
      trx.clear_signatures();
      trx.operations.clear();
      BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), pool0 - anchor0 );
      BOOST_CHECK_EQUAL( core.dynamic_asset_data_id( db ).accumulated_fees.value,
                         acc0 + anchor0 );
   }
   // And an exit that pays the full anchor takes the COST path: no debit.
   {
      const ee_bal cost = deposit_exit_fuel( "ee2-cost", 900, anchor0 );
      const int64_t pool0 = T_ee_pool( db, core_id );
      const int64_t acc0 = core.dynamic_asset_data_id( db ).accumulated_fees.value;
      op41_exit( cost, 900, anchor0 );
      BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), pool0 );
      BOOST_CHECK_EQUAL( core.dynamic_asset_data_id( db ).accumulated_fees.value, acc0 );
   }
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 3 — subsidy_growth_preserved.
//
// Rule R must not over-correct: a 1-in/8-out ring spend GROWS the live set by
// eight (ring spends consume nothing, stealth_evaluator.cpp:791), so it must
// still draw the FULL eight-output gap — anchor(8) - parity = 4.5 CORE here —
// not the circulation-sized base-fee component.
//
// GUARD DELETION (observed RED): cap the op104 classifier arm at 1 (the
// pre-EE-1b reading) -> the debit drops to anchor(1) and the exact-pool
// assertion goes RED.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( subsidy_growth_preserved )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   const asset_id_type core_id = core.get_id();
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "ee3", 16, true );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core_id ), 16u );
    // C1-followup (cold-start A3): t5_fund_pool seeded n_out*1 CORE + 5 CORE =
    // 21 CORE, but its 16 zero-fee deposits no longer all draw anchor(1). The
    // first 11 land at depth < 11, so cold_n = 0 and each draws anchor(0) =
    // 0.5 CORE; only the last 5 draw anchor(1). Pool: 21 - (11*0.5 + 5*1) =
    // 10.5 CORE (pre-cold: 21 - 16*1 = 5 CORE) — still enough for the 4.5 CORE
    // eight-output grant without seeding anything else.
    const int64_t pool0 = T_ee_pool( db, core_id );
    BOOST_REQUIRE_EQUAL( pool0, 10500000 );
   const int64_t acc0 = core.dynamic_asset_data_id( db ).accumulated_fees.value;
   const int64_t anchor8 = stealth_cost_anchor_core( db, 8 ).value;
   BOOST_REQUIRE_EQUAL( anchor8, 4500000 );
   // The capped-and-uncapped gaps for this shape, pinned before the push.
   BOOST_REQUIRE_EQUAL( stealth_parity_gap_core( db, 8, share_type( 0 ), 8 ).value, anchor8 );

   // 1000 -> 8 x 124 outputs + 8 fee (conservation closes exactly).
   stealth_transfer_operation stop = T_ee_build_spend( core, p, { 5 },
      { 124, 124, 124, 124, 124, 124, 124, 124 }, 8, GRAPHENE_STEALTH_PROOF_V2, "ee3-sp" );
   BOOST_REQUIRE_EQUAL( stop.outputs.size(), 8u );
   BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( stop ) ), 8u );
   set_expiration( db, trx );
   trx.operations = { stop };
   PUSH_TX( db, trx );
   trx.clear();
   generate_block();

   // FULL eight-output gap: the pool paid exactly anchor(8) and the issuer was
   // credited the same amount (supply-neutral).
   BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), pool0 - anchor8 );
   BOOST_CHECK_EQUAL( core.dynamic_asset_data_id( db ).accumulated_fees.value,
                      acc0 + anchor8 );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_REQUIRE_EQUAL( st.interval_granted.find( core_id )->second.value, anchor8 );
   }
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 4 — subsidy_ring_consolidation_not_capped.
//
// Reviewer C-2: no existing test exercises a MULTI-OUTPUT ring op against a
// seeded pool. A 2-in/2-out ring spend is "consolidation" under the pre-Task-3
// reading of spec §1 (every op consumes its inputs, so ΔD_a = 0) but is real
// live-set GROWTH under the chain's own counter: the whole-ring spent write and
// its coupled pool_count_add(...,-1) were retired together
// (stealth_evaluator.cpp:769-771), so the spend ADDS two outputs and removes
// nothing. It must therefore draw the m=2 subsidy, not the base fee.
//
// GUARD DELETION (observed RED): same op104 classifier mutation as test 3 ->
// anchor(2) collapses to anchor(1) and the exact debit assertion goes RED.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( subsidy_ring_consolidation_not_capped )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   const asset_id_type core_id = core.get_id();
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "ee4", 16, true );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core_id ), 16u );
   const int64_t pool0 = T_ee_pool( db, core_id );
   BOOST_REQUIRE( pool0 >= 1500000 );
   const int64_t acc0 = core.dynamic_asset_data_id( db ).accumulated_fees.value;
   const int64_t anchor2 = stealth_cost_anchor_core( db, 2 ).value;
   BOOST_REQUIRE_EQUAL( anchor2, 1500000 );

   // 2 x 1000 -> 2 x 990 outputs + 20 fee.
   stealth_transfer_operation stop = T_ee_build_spend( core, p, { 5, 6 },
      { 990, 990 }, 20, GRAPHENE_STEALTH_PROOF_V2, "ee4-sp" );
   BOOST_REQUIRE_EQUAL( stop.inputs.size(), 2u );
   BOOST_REQUIRE_EQUAL( stop.outputs.size(), 2u );
   BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( stop ) ), 2u );
   const int64_t depth0 = (int64_t)stealth_pool_depth( db, core_id );
   set_expiration( db, trx );
   trx.operations = { stop };
   PUSH_TX( db, trx );
   trx.clear();
   generate_block();

   BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), pool0 - anchor2 );
   BOOST_CHECK_EQUAL( core.dynamic_asset_data_id( db ).accumulated_fees.value,
                      acc0 + anchor2 );
   // The live set GREW by m: the ring spend removed nothing and added m outputs
   // (this is the counter EE-1b's classifier reads).
   BOOST_CHECK_EQUAL( (int64_t)stealth_pool_depth( db, core_id ), depth0 + 2 );
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 5 — subsidy_explicit_spend_net_split.
//
// op108 is the one op whose ΔD_a is n_out - n_in (it really does consume its
// metadata-bearing inputs, -spent_counted at stealth_evaluator.cpp:1924), so it
// is the only shape where the classifier's two branches disagree. Pins BOTH:
//   net >  0  1-in/4-out  -> full per-output component, gap = anchor(4)
//   net <= 0  4-in/1-out  -> circulation,           gap = anchor(1)
//
// GUARD DELETION (observed RED): drop the `n_out > n_in` growth branch in
// net_rule (always base fee) -> the 4-output gap collapses to anchor(1).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( subsidy_explicit_spend_net_split )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   const asset_id_type core_id = core.get_id();
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "ee5", 5, false );
   g1c_seed_pool( db, dan_id, core, 10 * 1000000 );
   const int64_t anchor1 = stealth_cost_anchor_core( db, 1 ).value;
   const int64_t anchor4 = stealth_cost_anchor_core( db, 4 ).value;
   BOOST_REQUIRE_EQUAL( anchor1, 1000000 );
   BOOST_REQUIRE_EQUAL( anchor4, 2500000 );

   auto push = [&]( const std::vector<size_t>& ins, const std::vector<int64_t>& outs,
                    const std::string& tag ) {
      std::vector<ee_bal> bals;
      for( size_t s : ins )
         bals.push_back( ee_bal{ p.commits[s], p.blinds[s], p.each, p.owners[s] } );
      stealth_explicit_spend_operation o = T_ee_op108_blind( core, bals, outs, 0, tag,
                                                             p.owners[ins[0]] );
      set_expiration( db, trx );
      trx.clear_signatures();
      trx.operations.clear();
      trx.operations = { o };
      // Every input carries its OWN owner authority, so every owner signs.
      for( size_t s : ins )
         sign( trx, p.keys[s] );
      PUSH_TX( db, trx );
      trx.clear_signatures();
      trx.operations.clear();
   };
   {
      stealth_explicit_spend_operation grow;
      grow.inputs.resize( 1 ); grow.outputs.resize( 4 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( grow ) ), 4u );
      stealth_explicit_spend_operation shrink;
      shrink.inputs.resize( 4 ); shrink.outputs.resize( 1 );
      BOOST_CHECK_EQUAL( stealth_subsidy_output_count( operation( shrink ) ), 1u );
   }

   // net > 0: one 1000 input into four 250 outputs (fee 0, parity level).
   {
      const int64_t pool0 = T_ee_pool( db, core_id );
      push( { 0 }, { 250, 250, 250, 250 }, "ee5-a" );
      BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), pool0 - anchor4 );
   }
   // net <= 0: four 1000 inputs into one 4000 output.
   {
      const int64_t pool0 = T_ee_pool( db, core_id );
      push( { 1, 2, 3, 4 }, { 4000 }, "ee5-b" );
      BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), pool0 - anchor1 );
   }
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 6 — subsidy_op109_admitted_funded.
//
// op109 is ADMITTED to the mechanism on the circulation rule (Rule R, F-02):
// with a funded pool its user fee may sit at the parity level, the pool is
// debited the grant, and the issuer's accumulated_fees takes the same amount
// (supply neutrality). Zero market fee on this pool, so the parity_pool delta
// is PURELY the subsidy — no routing noise to subtract.
//
// GUARD DELETION (observed RED): remove the op109 consume call
// (stealth_evaluator.cpp:2303) -> the pool delta assertion goes RED.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( subsidy_op109_admitted_funded )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "EE6", 0 );
   generate_block(); // seal before the direct writes below (db_block.cpp:423)
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   const asset_id_type aid_a = p.asset_a;
   const int64_t anchor1_core = stealth_cost_anchor_core( db, 1 ).value;
   int64_t gap_sub = 0;
   {
      const share_type parity_core = db.current_fee_schedule().calculate_fee(
         operation( stealth_pool_exchange_operation() ) ).amount;
      BOOST_REQUIRE_EQUAL( parity_core.value, 0 ); // test genesis scale == 0
      share_type gap = stealth_parity_gap_core( db, 1, parity_core, 1 );
      BOOST_REQUIRE_EQUAL( gap.value, anchor1_core );
      const share_type need = stealth_gap_to_asset( db, aid_a, gap ) + share_type( 1000 );
      T_seed_pool_uia( *this, dan, aid_a( db ), need.value );
      gap_sub = stealth_gap_to_asset( db, aid_a, gap ).value;
   }
   set_expiration( db, trx );
   const int64_t pool0 = T_ee_pool( db, aid_a );
   const int64_t acc0 = aid_a( db ).dynamic_asset_data_id( db ).accumulated_fees.value;
   BOOST_REQUIRE_EQUAL( pool0, gap_sub + 1000 );

   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "ee6-sp", 50 );
   BOOST_REQUIRE_EQUAL( sw.expect.maker_market_fee.amount.value, 0 );
   BOOST_REQUIRE_EQUAL( sw.expect.taker_market_fee.amount.value, 0 );
   // The user sat at the PARITY level: f_tx is dust, far below anchor(1).
   BOOST_REQUIRE( sw.f_tx < gap_sub );
   trx.operations = { sw.op };
   PUSH_TX( db, trx );
   trx.clear();
   generate_block();

   // Exact debit and exact issuer credit, plus the counter-asset untouched.
   BOOST_CHECK_EQUAL( T_ee_pool( db, aid_a ), pool0 - gap_sub );
   BOOST_CHECK_EQUAL( aid_a( db ).dynamic_asset_data_id( db ).accumulated_fees.value,
                      acc0 + sw.f_tx + gap_sub );
   BOOST_CHECK_EQUAL( T_ee_pool( db, p.asset_b ), 0 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 7 — subsidy_op109_empty_pool_refuses.  The path no test exercised
// (reviewer Q-12).
//
// op109's tx fee is KERNEL-PINNED (f_tx = a - f_maker - pool_pays, Lemmas 3+4),
// so it can never be raised to the anchor. With an empty parity pool the float
// rule therefore has exactly one legal answer: refuse. The pool must not move,
// the reserves must not move, and no nullifier may be recorded.
//
// Also pins the bootstrap property this refusal creates: on a ZERO-market-fee
// pool the swap's own routing contribution is 0 while its anchor gap is
// strictly positive, so such a pair can never fund its own subsidy and MUST be
// funded from elsewhere (a routed-fee pool or an external contribution).
//
// GUARD DELETION (observed RED): delete the FC_ASSERT at
// stealth_evaluator.cpp:1411 -> the under-funded swap is ACCEPTED and the
// refusal assertions go RED (free subsidy, pool pays nothing).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( subsidy_op109_empty_pool_refuses )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "EE7", 0 );
   generate_block();
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   const asset_id_type aid_a = p.asset_a;
   // EMPTY pool: never seeded, and this pool charges 0% market fee so nothing
   // routes on its own either.
   BOOST_REQUIRE_EQUAL( T_ee_pool( db, aid_a ), 0 );

   const int64_t anchor1_core = stealth_cost_anchor_core( db, 1 ).value;
   const share_type parity_core = db.current_fee_schedule().calculate_fee(
      operation( stealth_pool_exchange_operation() ) ).amount;
   const share_type gap = stealth_parity_gap_core( db, 1, parity_core, 1 );
   BOOST_REQUIRE_EQUAL( gap.value, anchor1_core );
   const int64_t gap_asset = stealth_gap_to_asset( db, aid_a, gap ).value;
   BOOST_REQUIRE( gap_asset > 0 );

   const liquidity_pool_object& pool0 = p.pool( db );
   const int64_t bal_a0 = pool0.balance_a.value, bal_b0 = pool0.balance_b.value;
   const int64_t conf_a0 = aid_a( db ).dynamic_asset_data_id( db ).confidential_supply.value;
   const size_t nul0 = db.get_index_type<stealth_nullifier_index>().indices().size();

   g2_swap sw = g2_build_swap( db, p, 5, GRAPHENE_STEALTH_PROOF_V2, "ee7-sp", 50 );
   // Bootstrap property: the pair's own market fee is ZERO while the anchor gap
   // it must be subsidized against is strictly positive — it cannot self-fund.
   BOOST_REQUIRE_EQUAL( sw.expect.maker_market_fee.amount.value, 0 );
   BOOST_REQUIRE_EQUAL( sw.expect.taker_market_fee.amount.value, 0 );
   BOOST_REQUIRE( gap_asset > sw.f_tx );
   BOOST_REQUIRE( sw.f_tx < anchor1_core );

   set_expiration( db, trx );
   trx.operations = { sw.op };
   T_ee_expect_refusal(
      [&]() { PUSH_TX( db, trx ); },
      "Blind fee below cost level",
      "empty-pool swap under the anchor must refuse at the require gate" );
   trx.clear();

   // Nothing moved: no pool debit, no reserve trade, no blind-supply change,
   // no nullifier (the require gate fires in do_evaluate, before apply).
   BOOST_CHECK_EQUAL( T_ee_pool( db, aid_a ), 0 );
   BOOST_CHECK_EQUAL( p.pool( db ).balance_a.value, bal_a0 );
   BOOST_CHECK_EQUAL( p.pool( db ).balance_b.value, bal_b0 );
   BOOST_CHECK_EQUAL( aid_a( db ).dynamic_asset_data_id( db ).confidential_supply.value,
                      conf_a0 );
   BOOST_CHECK_EQUAL( db.get_index_type<stealth_nullifier_index>().indices().size(), nul0 );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 8 — subsidy_op109_drain_between_consume_fails_closed.
//
// require() and consume() are separate calls in do_evaluate / do_apply, and the
// consume leg re-derives availability instead of trusting require: the
// FC_ASSERT( stealth_parity_available(...) ) mirror at stealth_evaluator.cpp
// :1439. There is no block-level way to interleave a drain between them, so the
// test drives the two functions directly against real sealed state — the same
// entry points the evaluators call, with the same (n, subsidy_n) pair.
//
// Two distinct drains, because they fail for different reasons and only the
// second is caught by a downstream assert as well:
//   (a) POOL DRAINED (balance 0 < gap): the availability mirror must fire.
//   (b) PER-BLOCK CAP EXHAUSTED (50 units used, pool still funded): nothing
//       downstream would notice — the underflow assert at :1450 passes because
//       the money IS there — so the mirror is the ONLY guard.
//
// GUARD DELETION (observed RED): remove the :1439 assert. Leg (a) then fails
// late with "Parity pool underflow at apply time"; leg (b) is ACCEPTED
// outright — a grant paid out with no cap unit consumed.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( subsidy_op109_drain_between_consume_fails_closed )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   const asset_id_type core_id = core.get_id();
   transfer( account_id_type()( db ), dan, core.amount( 200000000 ) );
   generate_block(); // seal before the direct writes below
   const int64_t anchor1 = stealth_cost_anchor_core( db, 1 ).value;
   BOOST_REQUIRE_EQUAL( anchor1, 1000000 );

   // An op109-shaped pair: n_blind_outputs = 1, subsidy_n = 1, parity 0, user
   // at the parity level (core_fee_paid = 0). gap == anchor(1).
   const uint32_t n = 1, subsidy_n = 1;
   const share_type parity = share_type( 0 );
   const share_type paid = share_type( 0 );
   BOOST_REQUIRE_EQUAL( stealth_parity_gap_core( db, n, parity, subsidy_n ).value, anchor1 );

   auto status = [&]() -> stealth_status_object& {
      return const_cast<stealth_status_object&>(
         *db.get_index_type<stealth_status_index>().indices().begin() );
   };

   // --- leg (a): pool drained between require and consume ------------------
   // The drain is done with a REAL successful grant of a larger shape (n = 8),
   // which is how a pool actually empties in production (a debit paired with
   // the issuer credit, so supply stays balanced) — a direct deletion of pool
   // state would silently break verify_asset_supplies.
   g1c_seed_pool( db, dan_id, core, 5 * anchor1 );
   BOOST_REQUIRE_EQUAL( T_ee_pool( db, core_id ), 5 * anchor1 );
   const int64_t acc0 = core.dynamic_asset_data_id( db ).accumulated_fees.value;
   // require() admits this op: the pool still covers its 1-CORE gap.
   BOOST_CHECK_NO_THROW( stealth_require_blind_fee( db, paid, true, core_id,
                                                   n, parity, subsidy_n ) );
   // Another op drains it below this op's gap (anchor(8) = 4.5 CORE).
   const int64_t drain_gap = stealth_parity_gap_core( db, 8, parity, 8 ).value;
   BOOST_REQUIRE_EQUAL( drain_gap, 4500000 );
   stealth_consume_parity_subsidy( db, true, core_id, 8, parity, paid, 8 );
   BOOST_REQUIRE_EQUAL( T_ee_pool( db, core_id ), 5 * anchor1 - drain_gap );
   BOOST_REQUIRE( T_ee_pool( db, core_id ) < anchor1 ); // no longer covered
   BOOST_CHECK( !stealth_parity_available( db, core_id, share_type( anchor1 ) ) );
   BOOST_CHECK_EQUAL( core.dynamic_asset_data_id( db ).accumulated_fees.value,
                      acc0 + drain_gap );
   T_ee_expect_refusal(
      [&]() { stealth_consume_parity_subsidy( db, true, core_id, n, parity, paid, subsidy_n ); },
      "Parity subsidy no longer available at apply time",
      "consume must fail closed against a drained pool" );
   // Fail-closed means nothing moved: no second debit, no second credit.
   BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), 5 * anchor1 - drain_gap );
   BOOST_CHECK_EQUAL( core.dynamic_asset_data_id( db ).accumulated_fees.value,
                      acc0 + drain_gap );

   // --- leg (b): per-block cap exhausted, pool STILL funded ---------------
   // Nothing downstream would notice this one: the underflow assert at :1450
   // passes because the money IS there, so the availability mirror is the ONLY
   // guard between a grant and a cap overrun.
   g1c_seed_pool( db, dan_id, core, 5 * anchor1 );
   BOOST_REQUIRE_EQUAL( T_ee_pool( db, core_id ), 5 * anchor1 );
   BOOST_CHECK_NO_THROW( stealth_require_blind_fee( db, paid, true, core_id,
                                                   n, parity, subsidy_n ) );
   BOOST_REQUIRE_EQUAL( stealth_subsidy_output_count(
                         operation( stealth_pool_exchange_operation() ) ), 1u );
   // Exactly what 50 grants into the pending block would have written.
   db.modify( status(), [&]( stealth_status_object& o ) {
      o.parity_block_num = db.head_block_num() + 1;
      o.parity_subsidized_count = GRAPHENE_STEALTH_PARITY_MAX_SUBSIDIZED_PER_BLOCK;
   } );
   BOOST_REQUIRE( T_ee_pool( db, core_id ) >= anchor1 ); // the pool is NOT the blocker
   {
      const int64_t pool0 = T_ee_pool( db, core_id );
      const int64_t acc1 = core.dynamic_asset_data_id( db ).accumulated_fees.value;
      T_ee_expect_refusal(
         [&]() { stealth_consume_parity_subsidy( db, true, core_id, n, parity, paid, subsidy_n ); },
         "Parity subsidy no longer available at apply time",
         "consume must fail closed when the per-block cap is exhausted" );
      BOOST_CHECK_EQUAL( T_ee_pool( db, core_id ), pool0 );
      BOOST_CHECK_EQUAL( core.dynamic_asset_data_id( db ).accumulated_fees.value, acc1 );
   }
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// EE-3fix helpers — G2's market-fee leg vs. the burn-rate denominator.
// ---------------------------------------------------------------------------

/// External parity-pool contribution: the bootstrap shape a routed-fee pair
/// cannot bootstrap ITSELF out of (see subsidy_op109_empty_pool_refuses — a
/// zero-market-fee pool can never pay its own anchor gap). Money moves payer ->
/// accumulated_fees -> parity_pool, the same split the legacy router makes at
/// db_market.cpp:2696, but paid through a NON-opted-in asset so NO
/// interval_routed entry is written: an external gift is not routed fee
/// inflow, and the EE-3fix fix must not invent one.
///
/// SEALED-STATE ONLY (db_block.cpp:423), same discipline as T_seed_pool_uia:
/// call with no push in flight.
static void T_seed_pool_external( database_fixture& f, const account_object& payer,
                                  const asset_object& uia, int64_t need )
{
   database& db = f.db;
   const auto& opt = uia.options.extensions.value.parity_fee_share_enabled;
   BOOST_REQUIRE_MESSAGE( !opt.valid() || !*opt,
      "T_seed_pool_external: asset is opted in, so the LEGACY router would "
      "register interval inflow and this helper would no longer measure what "
      "it claims to measure" );
   const int64_t have = T_ee_pool( db, uia.get_id() );
   if( have >= need )
      return;
   const int64_t fee = need - have;
   BOOST_REQUIRE_MESSAGE(
      db.get_balance( payer.get_id(), uia.get_id() ).amount.value >= fee,
      "T_seed_pool_external: payer lacks the UIA balance to seed the parity pool" );
   db.adjust_balance( payer.get_id(), uia.amount( -fee ) );
   db.pay_market_fees( nullptr, uia, uia.amount( fee ), true, uia.amount( fee ) );
   db.modify( uia.dynamic_asset_data_id( db ), [&]( asset_dynamic_data_object& o ) {
      BOOST_REQUIRE( o.accumulated_fees.value >= fee );
      o.accumulated_fees -= share_type( fee );
   } );
   db.modify( *db.get_index_type<stealth_status_index>().indices().begin(),
              [&]( stealth_status_object& o ) {
      auto itr = o.parity_pool.find( uia.get_id() );
      if( itr == o.parity_pool.end() )
         o.parity_pool[ uia.get_id() ] = share_type( fee );
      else
         itr->second += share_type( fee );
   } );
   BOOST_REQUIRE_EQUAL( T_ee_pool( db, uia.get_id() ), need );
}

/// Push the scheduled consensus maintenance tick past the end of this test.
/// database::_maintenance calls stealth_parity_maintenance (db_maint.cpp),
/// which ROLLS the interval counters over and recomputes the alarms — correct
/// behaviour, but it would clear interval_routed out from under the assertions
/// below and make them depend on where the fixture's block clock happens to
/// sit. Both EE-3fix cases drive stealth_parity_maintenance explicitly, so the
/// interval under test stays exactly the one the swap wrote. SEALED STATE ONLY.
static void T_defer_maintenance( database& db )
{
   const fc::time_point_sec far =
      db.head_block_time() + fc::seconds( 5 * 365 * 24 * 3600 );
   db.modify( db.get_dynamic_global_properties(),
              [&]( dynamic_global_property_object& p ) { p.next_maintenance_time = far; } );
}

// ---------------------------------------------------------------------------
// Test 10 — subsidy_op109_funding_registers_burn_denominator.  EE-3fix, the
// F-01 (Important) brick.
//
// The burn alarm in stealth_parity_maintenance is a per-asset RATIO of this
// interval's grants to this interval's ROUTED inflow: routed == 0 while any
// grant exists reads as pct = 100, trips burn_critical, and
// stealth_parity_available then refuses every later subsidy. The legacy router
// (stealth_parity_route_fee) maintains BOTH counters; the G2 router
// (g2_route_market_fee_to_parity, design §5) credited parity_pool and forgot
// interval_routed, so a G2-only-funded asset tripped the alarm on its FIRST
// grant and every subsidy after it halted until some later interval happened
// to carry legacy routing.
//
// The pool here is funded EXTERNALLY (no legacy opt-in, so no interval inflow
// from the seed) and the swap routes 4x its grant, which is the ratio a
// healthy G2 pair runs at. Before the fix the denominator reads 0 -> pct 100.
//
// GUARD DELETION (observed RED): delete the interval_routed upsert from
// g2_route_market_fee_to_parity (stealth_evaluator.cpp, the db.modify block
// just above stealth_pool_exchange_evaluator::do_evaluate) -> the
// interval_routed lookup below goes RED and burn_critical reads true on a
// 4:1 routed:granted interval.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( subsidy_op109_funding_registers_burn_denominator )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();

   // (0) The legacy router, UNCHANGED: it registers BOTH counters. Pinned
   // first so the G2 leg below is read against a known-good shape, and on the
   // fixture's own CORE funding so it costs no extra setup.
   {
      const asset_object& core = asset_id_type()( db );
      g1c_opt_in_parity( db, core.get_id() );
      db.adjust_balance( dan_id, core.amount( -1000000 ) );
      db.pay_market_fees( nullptr, core, core.amount( 1000000 ), true, core.amount( 1000000 ) );
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      auto pitr = st.parity_pool.find( core.get_id() );
      auto ritr = st.interval_routed.find( core.get_id() );
      BOOST_REQUIRE( pitr != st.parity_pool.end() );
      BOOST_REQUIRE( ritr != st.interval_routed.end() );
      BOOST_CHECK_EQUAL( pitr->second.value, 50000 ); // 5% of the routed fee
      BOOST_CHECK_EQUAL( ritr->second.value, 50000 ); // ...and it registers it
   }

   // 80% market fee on 5e6-unit outputs: the ratio under test is grant:routed
   // and the grant is the ~1e6-unit cost anchor, so the routed leg has to be
   // the same order of magnitude for the number to mean anything.
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "EE3F", 8000, 5000000 );
   generate_block();
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   BOOST_REQUIRE_EQUAL( db.get_global_properties().parameters.get_market_fee_network_percent(), 0 );
   const asset_id_type aid_a = p.asset_a;

   // op109's grant on this pair: the anchor gap (parity is 0 at test genesis).
   const int64_t anchor1_core = stealth_cost_anchor_core( db, 1 ).value;
   const share_type parity_core = db.current_fee_schedule().calculate_fee(
      operation( stealth_pool_exchange_operation() ) ).amount;
   const share_type gap = stealth_parity_gap_core( db, 1, parity_core, 1 );
   BOOST_REQUIRE_EQUAL( gap.value, anchor1_core );
   const int64_t gap_asset = stealth_gap_to_asset( db, aid_a, gap ).value;
   BOOST_REQUIRE_EQUAL( gap_asset, anchor1_core ); // the fixture's CER is 1:1
   T_seed_pool_external( *this, dan, aid_a( db ), gap_asset + 1000 );
   BOOST_REQUIRE_EQUAL( T_ee_pool( db, aid_a ), gap_asset + 1000 );

   // Flush the fixture's own interval (its blind deposits take CORE grants)
   // so the ratio measured below is THIS swap's alone. The second call
   // recomputes over the now-empty interval.
   T_defer_maintenance( db );
   stealth_parity_maintenance( db );
   stealth_parity_maintenance( db );
   BOOST_REQUIRE_EQUAL( stealth_current_alarms( db ).burn_rate_pct, 0u );
   BOOST_REQUIRE( !stealth_current_alarms( db ).burn_critical );

   set_expiration( db, trx );
   g2_swap sw = g2_build_swap( db, p, 0, GRAPHENE_STEALTH_PROOF_V2, "ee3fix-sp", 50 );
   const int64_t f_maker = sw.expect.maker_market_fee.amount.value;
   BOOST_TEST_MESSAGE( "ee3fix maker=" << f_maker
                    << " taker=" << sw.expect.taker_market_fee.amount.value
                    << " f_tx=" << sw.f_tx );
   BOOST_REQUIRE_EQUAL( f_maker, 4 * gap_asset ); // the routed:granted ratio under test
   trx.operations = { sw.op };
   PUSH_TX( db, trx );
   trx.clear();
   generate_block();

   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      auto ritr = st.interval_routed.find( aid_a );
      BOOST_REQUIRE( ritr != st.interval_routed.end() ); // <-- THE FIX
      BOOST_CHECK_EQUAL( ritr->second.value, f_maker );
      auto gitr = st.interval_granted.find( aid_a );
      BOOST_REQUIRE( gitr != st.interval_granted.end() );
      BOOST_CHECK_EQUAL( gitr->second.value, gap_asset );
      // The money never moved: the pool gained exactly the routed fee and paid
      // exactly the grant back out of it.
      BOOST_CHECK_EQUAL( T_ee_pool( db, aid_a ), 1000 + f_maker );
      auto bitr = st.interval_routed.find( p.asset_b );
      BOOST_REQUIRE( bitr != st.interval_routed.end() );
      BOOST_CHECK_EQUAL( bitr->second.value, sw.expect.taker_market_fee.amount.value );
   }
   stealth_parity_maintenance( db );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.alarms.burn_rate_pct, 25u ); // 1e6 granted / 4e6 routed
      BOOST_CHECK( !st.alarms.burn_warn );
      BOOST_CHECK( !st.alarms.burn_critical );
      BOOST_CHECK( st.interval_routed.empty() );  // the interval is rolled over
      BOOST_CHECK( st.interval_granted.empty() );
   }
   // The consequence the fix exists for: the subsidy is still on offer.
   BOOST_CHECK( stealth_parity_available( db, aid_a, share_type( gap_asset ) ) );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

// ---------------------------------------------------------------------------
// Test 11 — subsidy_op109_burn_critical_still_fires_on_excess.  EE-3fix's
// negative case: registering the denominator must NOT read as softening the
// alarm. Two independent ways the ratio must still fire, both with the fix in
// place and the router registering the denominator exactly as Test 10 shows:
//
//   (a) GENUINE EXCESS: a swap whose routed maker fee is below its grant
//       (80% of a 1e6 sell = 800k routed vs 1e6 granted -> 125%) must arm
//       burn_critical and halt the next subsidy, even though interval_routed
//       is now populated. The alarm is a RATIO, not a presence flag.
//   (b) NO INFLOW AT ALL: the zero-market-fee pair must still fund NOTHING on
//       the G2 path (interval_routed gets no entry — no invented funding) and
//       an externally funded grant over it reads as the full 100% burn it is.
//       This is also the bootstrap property subsidy_op109_empty_pool_refuses
//       pins from the refusal side: a zero-fee pair cannot self-fund.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE( subsidy_op109_burn_critical_still_fires_on_excess )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   transfer( account_id_type()( db ), dan, asset_id_type()( db ).amount( 500000000 ) );
   generate_block();
   // 10% market fee on 5e6-unit outputs over a DEEP pool: routed enough to
   // fund the pool, far short of the grant (a), and shallow enough that f_tx
   // stays under the cost anchor so the swap really takes the PARITY path. A
   // shallow pool would hand f_tx (3.4e6 here) past the anchor and the swap
   // would take the cost path instead — no grant, no interval, no ratio.
   g2_pool p = g2_fund_pool( *this, dan, dan_private_key, "EE3X", 1000, 5000000 );
   generate_block();
   const asset_id_type aid_a = p.asset_a;
   const int64_t anchor1_core = stealth_cost_anchor_core( db, 1 ).value;
   const share_type parity_core = db.current_fee_schedule().calculate_fee(
      operation( stealth_pool_exchange_operation() ) ).amount;
   const share_type gap = stealth_parity_gap_core( db, 1, parity_core, 1 );
   BOOST_REQUIRE_EQUAL( gap.value, anchor1_core );
   const int64_t gap_asset = stealth_gap_to_asset( db, aid_a, gap ).value;
   issue_uia( dan, asset( 10000000, aid_a ) );
   issue_uia( dan, asset( 40000000, p.asset_b ) );
   deposit_to_liquidity_pool( dan.get_id(), p.pool, asset( 29000000, aid_a ),
                              asset( 29000000, p.asset_b ) );
   // Deep pool -> the tx fee converts through the A fee pool at a size the
   // fixture's 10 BTS does not cover. CORE, not A; moves no parity counter.
   fund_fee_pool( dan, aid_a( db ), 20000000 );
   generate_block(); // seal before the direct writes below (db_block.cpp:423)
   db.modify( db.get_global_properties(), []( global_property_object& gp ) {
      gp.parameters.maximum_transaction_size = 1024 * 1024;
   } );
   // Two grants' worth, so both legs below can take the parity path.
   T_seed_pool_external( *this, dan, aid_a( db ), 2 * gap_asset + 1000 );
   T_defer_maintenance( db );
   stealth_parity_maintenance( db );
   stealth_parity_maintenance( db );
   BOOST_REQUIRE( !stealth_current_alarms( db ).burn_critical );

   // --- (a) routed 500k against granted 1e6 -> 200% ------------------------
   set_expiration( db, trx );
   g2_swap sw = g2_build_swap( db, p, 0, GRAPHENE_STEALTH_PROOF_V2, "ee3x-sp", 50 );
   const int64_t f_maker = sw.expect.maker_market_fee.amount.value;
   BOOST_REQUIRE_EQUAL( f_maker, gap_asset / 2 );   // 10% of a 5000000 sell
   BOOST_REQUIRE( sw.f_tx < gap_asset );            // ... so the parity path runs
   BOOST_REQUIRE( f_maker * 80 < gap_asset * 100 );  // over the critical line
   trx.operations = { sw.op };
   PUSH_TX( db, trx );
   trx.clear();
   generate_block();
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      auto ritr = st.interval_routed.find( aid_a );
      BOOST_REQUIRE( ritr != st.interval_routed.end() ); // the fix is in place
      BOOST_CHECK_EQUAL( ritr->second.value, f_maker );
      BOOST_REQUIRE( st.interval_granted.find( aid_a ) != st.interval_granted.end() );
      BOOST_CHECK_EQUAL( st.interval_granted.find( aid_a )->second.value, gap_asset );
   }
   stealth_parity_maintenance( db );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.alarms.burn_rate_pct, 200u );
      BOOST_CHECK( st.alarms.burn_warn );
      BOOST_CHECK( st.alarms.burn_critical );
   }
   // And the halt is real: the next subsidy is refused on this asset.
   BOOST_CHECK( !stealth_parity_available( db, aid_a, share_type( gap_asset ) ) );
   // Idle interval rolls the alarm back over (nothing granted, nothing routed).
   stealth_parity_maintenance( db );
   BOOST_REQUIRE( !stealth_current_alarms( db ).burn_critical );

   // --- (b1) the same pair repriced to a ZERO market fee routes NOTHING -----
   // No fee, no entry: the fix registers what the router ROUTES, never a
   // synthetic inflow that would mask real burn. This is the bootstrap
   // property subsidy_op109_empty_pool_refuses pins from the refusal side —
   // a fee-less pair can never fund itself, and the fix invents nothing.
   db.modify( aid_a( db ), []( asset_object& o ) { o.options.market_fee_percent = 0; } );
   db.modify( p.asset_b( db ), []( asset_object& o ) { o.options.market_fee_percent = 0; } );
   set_expiration( db, trx );
   g2_swap qw = g2_build_swap( db, p, 1, GRAPHENE_STEALTH_PROOF_V2, "ee3x-zero", 50 );
   BOOST_REQUIRE_EQUAL( qw.expect.maker_market_fee.amount.value, 0 );
   BOOST_REQUIRE_EQUAL( qw.expect.taker_market_fee.amount.value, 0 );
   trx.operations = { qw.op };
   PUSH_TX( db, trx );
   trx.clear();
   generate_block();
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK( st.interval_routed.find( aid_a ) == st.interval_routed.end() );
      BOOST_CHECK( st.interval_routed.find( p.asset_b ) == st.interval_routed.end() );
      BOOST_CHECK( st.interval_granted.find( aid_a ) == st.interval_granted.end() );
   }

   // --- (b2) a grant with NO routed inflow at all still reads as 100% ------
   // Driven through the same entry point the evaluators call, with the (n,
   // subsidy_n) pair op109 uses — no block-level way to interleave a grant
   // into an otherwise fee-less interval.
   stealth_consume_parity_subsidy( db, true, aid_a, 1, parity_core,
                                   share_type( 0 ), 1 );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_REQUIRE( st.interval_granted.find( aid_a ) != st.interval_granted.end() );
      BOOST_CHECK_EQUAL( st.interval_granted.find( aid_a )->second.value, gap_asset );
      BOOST_CHECK( st.interval_routed.find( aid_a ) == st.interval_routed.end() );
   }
   stealth_parity_maintenance( db );
   {
      const auto& st = *db.get_index_type<stealth_status_index>().indices().begin();
      BOOST_CHECK_EQUAL( st.alarms.burn_rate_pct, 100u );
      BOOST_CHECK( st.alarms.burn_warn );
      BOOST_CHECK( st.alarms.burn_critical ); // a grant with no inflow is a full burn
   }
   BOOST_CHECK( !stealth_parity_available( db, aid_a, share_type( gap_asset ) ) );
   verify_asset_supplies( db );
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()
