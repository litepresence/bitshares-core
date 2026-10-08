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
#include <graphene/chain/transaction_evaluation_state.hpp>
#include <graphene/app/database_api.hpp>
#include <graphene/wallet/wallet.hpp>

#include <fc/crypto/digest.hpp>
#include <fc/io/raw.hpp>
#include <fc/reflect/variant.hpp>

#include <algorithm>
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
      generate_block();
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
     // Task 6 (R7 C-02): the real spent input is NOT removed — the evaluator
     // cannot identify it without breaking ring privacy (and removing all
     // members would steal honest decoys). Spent inputs stay indexed but are
     // spent-FLAGGED: re-spend is blocked by the nullifier set (proven by the
     // double-spend rejection above) AND by the ring-membership exclusion
     // below, so flagged outputs are never decoy-eligible again.
     {
        const auto& idx = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
        BOOST_CHECK( idx.find( so1.commitment ) != idx.end() );
        BOOST_CHECK( idx.find( so2.commitment ) != idx.end() );
        BOOST_CHECK( idx.find( commits[s] ) != idx.end() ); // retained (spent-flagged)
     }
     // Honest pool counter (Task 6 rework): 16 funded, all 16 ring members
     // consumed (real input unidentifiable — the whole set is spent-flagged
     // and excluded from future rings), 2 outputs created -> 2 fresh
     // decoy candidates. Each ring spend consumes its ring: availability
     // yields to privacy, and the floor gate (not this counter) enforces it.
     BOOST_CHECK_EQUAL( stealth_pool_depth( db, core.get_id() ), 2u );
    BN_free( bs ); BN_free( bprime );
} FC_CAPTURE_AND_RETHROW() }

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
// explicit-spend legs must refuse it (spent flag); one opening must not spend
// once per proof version (dual-image linkage); amount/fee asset confusion
// must fail in consensus, not just relay validate. The supply identity
// (confidential_supply == test-ledger sum over live unspent blinds, all
// values test-known) pins that refused re-spends move nothing.
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
   BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception ); // ...consensus refuses
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
   BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
   trx.clear_signatures(); trx.operations.clear();
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live );
   BOOST_CHECK_EQUAL( t5_supply( db, core ), 15 * p.each + 600 + 390 );
} FC_CAPTURE_AND_RETHROW() }

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
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
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
   // nullified this opening's alternate image AND spent-flagged every ring
   // member (Task 6 exclusion), so consensus must refuse — at the spent
   // ring-member gate (before the nullifier check). Top the pool back over
   // the floor first (the honest spend consumed its ring: 16 - 16 + 2), with
   // cost-path deposits and a direct pool top-up — no time jump, so no
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
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 16u );
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
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "spent" ) != std::string::npos,
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
    BOOST_CHECK( idx.find( p.commits[5] ) != idx.end() ); // retained (spent-flagged)
    // Honest pool counter (Task 6 rework): 16 funded, all 16 ring members
    // consumed, 2 outputs created -> 2 fresh decoy candidates.
    BOOST_CHECK_EQUAL( stealth_pool_depth( db, core.get_id() ), 2u );
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
   generate_block();
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

// R9C F-08 disclosure pin (mimo-2.6 F-08 HIGH): ring spends consume
// their decoys — after spend A consumes ring R, the DECOY owner's
// explicit spend refuses via the spent flag. This documents CURRENT
// semantics (any output can be rendered unspendable by a third party
// that includes it as a decoy); it does NOT change them. The
// nullifier-set redesign stays a design-owner option (recorded at
// stealth_transfer_evaluator::do_apply, never implemented here).
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
   // is refused: her output died as someone else's decoy (F-08).
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
      BOOST_FAIL( "decoy-owner explicit spend must refuse (spent flag, F-08)" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "spent" ) != std::string::npos,
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
      BOOST_CHECK_EQUAL( stealth_parity_gap_core( db, 0, share_type( 0 ) ).value,
                         stealth_cost_anchor_core( db, 0 ).value );
      BOOST_CHECK_EQUAL(
         stealth_parity_gap_core( db, 0, stealth_cost_anchor_core( db, 0 ) ).value, 0 );
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
   generate_block();

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
   BOOST_CHECK_EQUAL( stealth_parity_gap_core( db, 0, share_type( 499000 ) ).value, 1000 );
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
   generate_block();

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
   generate_block();
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
   generate_block();
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
      BOOST_CHECK_EQUAL( eitr->second, 2u ); // 3 created - 1 spent
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

// Task 6 (R7 C-02): spent outputs are excluded from ring membership. A ring
// that reuses even one spent-flagged output refuses at the membership gate —
// spent flags are chain-visible, so admitting spent members would shrink the
// plausible-real set to the unspent remainder (privacy leak, not just hygiene).
BOOST_AUTO_TEST_CASE( spent_ring_member_excluded )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()(db);
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "t6-spent", 16, true );
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 16u );
   // Honest spend consumes the whole 16-ring (Task 6 accounting: 16 - 16 + 2).
   stealth_transfer_operation first = t5_build_spend( core, p, 5,
      GRAPHENE_STEALTH_PROOF_V1, "t6-spent-1", 600, 390, 10 );
   trx.operations = { first };
   PUSH_TX( db, trx ); trx.clear();
   generate_block();
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 2u );
   // Top the pool back over the floor with fresh cost-path deposits (fee 1M
   // = the n=1 anchor: no subsidy involvement either way). No time jump:
   // the spent-membership gate fires before any age/policy math, and jumping
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
   BOOST_REQUIRE_EQUAL( stealth_pool_depth( db, core.get_id() ), 18u );
   // Re-arm the subsidy path deterministically (direct pool top-up: no blocks,
   // no maintenance, no burn recompute) so the attempt below reaches the
   // spent-membership gate instead of the fee gate.
   g1c_seed_pool( db, dan_id, core, 5000000 );
   // Second spend reusing one spent member (first in the ring, so the
   // membership loop meets it before any policy math) must refuse there.
   stealth_transfer_operation second = t5_build_spend( core, p, 5,
      GRAPHENE_STEALTH_PROOF_V1, "t6-spent-2", 600, 390, 10 );
   trx.operations = { second };
   try
   {
      PUSH_TX( db, trx );
      BOOST_FAIL( "ring reusing a spent member must reject" );
   }
   catch( const fc::exception& e )
   {
      BOOST_CHECK_MESSAGE( e.to_detail_string().find( "spent" ) != std::string::npos,
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

// Task 6: ring-sampler rule conformance (BLIND_DEFAULTS_CONTRACT.md §5).
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
   // the metadata/spent gates are op-level, pinned by their own tests).
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
   BOOST_REQUIRE_EQUAL( stealth_parity_gap_core( db, 0, share_type( 490000 ) ).value, 10000 );
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
   generate_block(); // seal: the halt flag below is a direct modify
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
   BOOST_CHECK_EQUAL( stealth_parity_gap_core( db, 0, share_type( 500000 ) ).value, 100000 );
   // Scale 200%: BOTH legs double — anchor 1200000 (not the raw 600000 a
   // scale-blind read would pin), parity 1000000, gap 200000. G3-01 pin:
   // without the fix the anchor would sit at 600000 while parity cleared
   // at 1000000, a 400000 windfall subsidy per op.
   BOOST_CHECK_EQUAL( parity_at( 2 * GRAPHENE_100_PERCENT ).value, 1000000 );
   BOOST_CHECK_EQUAL( stealth_cost_anchor_core( db, 0 ).value, 1200000 );
   BOOST_CHECK_NE( stealth_cost_anchor_core( db, 0 ).value, 600000 );
   BOOST_CHECK_EQUAL( stealth_parity_gap_core( db, 0, share_type( 1000000 ) ).value, 200000 );
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
      share_type gap = stealth_parity_gap_core( db, 1, share_type( 0 ) );
      BOOST_REQUIRE( gap.value > 0 ); // real gap: anchor above zero-fee parity
      BOOST_CHECK_NO_THROW( stealth_require_blind_fee( db, share_type( 0 ), false,
                                                       core_id, 1, share_type( 0 ) ) );
      const auto& st0 = *db.get_index_type<stealth_status_index>().indices().begin();
      auto pit = st0.parity_pool.find( core_id );
      share_type before = ( pit == st0.parity_pool.end() ) ? share_type( 0 ) : pit->second;
      BOOST_CHECK_NO_THROW( stealth_consume_parity_subsidy( db, false, core_id, 1,
                                                            share_type( 0 ), share_type( 0 ) ) );
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
// Defect (spec 2026-10-08-f08-representation-proof-recovery-design.md §1): a
// ring spend spent-flags EVERY ring member, so a stranger can brick any stealth
// output for one fee by including it as a decoy; the turnstile
// (stealth_evaluator.cpp:885) then refuses it forever. Recovery: the turnstile
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
//   BOUND images (either present -> refuse, message names "nullifier"), then
//   allow despite spent. Absent extension: current behavior byte-identical.
// ===========================================================================

/// Test-only representation prover (wallets own proving; consensus never
/// proves). Mirrors T_prove_ring structure. Random nonces via BN_rand_range
/// are test-only and fine here (no consensus path touches this function).
static void T_prove_recovery( const std::vector<unsigned char>& C_bytes,
                              const BIGNUM* b, uint64_t v,
                              asset_id_type asset,
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
   std::string pre = "BTS-STEALTH-RECOVERY-v1";
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

/// Attach the (not-yet-existing) R15 recovery extension. Aggregate field
/// order { I1, I2, proof } is the wire contract Task 2 must implement.
static void T_set_recovery_v2( turnstile_reproof_operation& t,
                               const fc::ecc::commitment_type& I1,
                               const fc::ecc::commitment_type& I2,
                               const std::vector<char>& proof )
{
   t.extensions.insert( turnstile_recovery_v2_extension{ I1, I2, proof } );
}

/// Simulate decoy consumption: the whole-ring spent write at
/// stealth_evaluator.cpp:750-752, isolated so these cases exercise the
/// recovery GUARD, not decoy mechanics (already covered by
/// r9c_decoy_owner_explicit_spend_refused).
static void T_r15_mark_decoyed( database& db, const fc::ecc::commitment_type& c )
{
   const auto& bbi = db.get_index_type<blinded_balance_index>().indices().get<by_commitment>();
   auto itr = bbi.find( c );
   BOOST_REQUIRE( itr != bbi.end() );
   db.modify( *itr, []( blinded_balance_object& b ) { b.spent = true; } );
}

/// Turnstile for pool output #s: 1000 -> 990 new blind output + 10 fee.
static turnstile_reproof_operation T_r15_turnstile( const asset_object& core,
                                                    const t5_pool& p, size_t s,
                                                    const std::string& tag )
{
   BOOST_REQUIRE( p.each == 1000 );
   turnstile_reproof_operation t;
   t.asset_id = core.get_id();
   t.old_commitment = p.commits[s];
   t.owner = p.owners[s];
   t.new_proof_version = GRAPHENE_STEALTH_PROOF_V2;
   stealth_blind_output no;
   auto Bn = T_blind_secret( tag );
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
   return t;
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

// Spec §7.1: decoyed (spent, no nullifier) output with a valid proof recovers.
BOOST_AUTO_TEST_CASE( r15_recovery_decoyed_succeeds )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-a", 16, true );
   const size_t s = 3;

   T_r15_mark_decoyed( db, p.commits[s] );

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-a-bn" );
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

   T_r15_mark_decoyed( db, p.commits[s] );

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
   BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
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

   T_r15_mark_decoyed( db, p.commits[s] );
   BOOST_REQUIRE( p.commits.size() > 9 );

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-d-bn" );
   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   BOOST_REQUIRE( I1 != I2 ); // versions MUST produce different bytes
   T_set_recovery_v2( t, I2, I1, proof ); // swapped
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
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

   T_r15_mark_decoyed( db, p.commits[sb] );

   // Prove over A's opening, submit against B's (decoyed) commitment.
   turnstile_reproof_operation t = T_r15_turnstile( core, p, sb, "r15-e-bn" );
   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, sa, core.get_id(), I1, I2, proof );
   T_set_recovery_v2( t, I1, I2, proof );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[sb] );
   BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
   trx.clear_signatures(); trx.operations.clear();
} FC_CAPTURE_AND_RETHROW() }

// Spec §7.6: without the extension nothing changes — a decoyed output still
// refuses with the EXACT pre-R15 message, and an unspent output still
// migrates normally.
BOOST_AUTO_TEST_CASE( r15_no_extension_unchanged )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-f", 16, true );

   // (a) decoyed + no extension: refused, pre-R15 message pinned.
   {
      const size_t s = 7;
      T_r15_mark_decoyed( db, p.commits[s] );
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-f-bn-a" );
      BOOST_REQUIRE( t.extensions.empty() );
      set_expiration( db, trx );
      trx.operations = { t };
      sign( trx, p.keys[s] );
      try {
         PUSH_TX( db, trx );
         BOOST_FAIL( "without the extension a decoyed output must still be refused" );
      } catch( const fc::exception& e ) {
         BOOST_CHECK_MESSAGE( e.to_detail_string().find(
            "Turnstile old commitment already spent (stealth transfer)" ) != std::string::npos,
            e.to_detail_string() );
      }
      trx.clear_signatures(); trx.operations.clear();
   }
   // (b) unspent + no extension: normal migration still works.
   {
      const size_t s = 2;
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-f-bn-b" );
      BOOST_REQUIRE( t.extensions.empty() );
      set_expiration( db, trx );
      trx.operations = { t };
      sign( trx, p.keys[s] );
      BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
      trx.clear_signatures(); trx.operations.clear();
   }
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

   T_r15_mark_decoyed( db, p.commits[s] );

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-g-bn" );
   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
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

// Spec §7.8: recovery preserves confidential_supply accounting exactly — the
// 1000-value input becomes a 990 output with the 10 fee leaving supply, no
// mint and no burn beyond the explicit fee (do_apply: supply -= fee).
BOOST_AUTO_TEST_CASE( r15_supply_conservation )
{ try {
   generate_blocks( HARDFORK_STEALTH_TIME );
   generate_block();
   set_expiration( db, trx );
   ACTORS( (dan) );
   const asset_object& core = asset_id_type()( db );
   t5_pool p = t5_fund_pool( *this, dan, dan_private_key, "r15-h", 16, true );
   const size_t s = 9;

   T_r15_mark_decoyed( db, p.commits[s] );
   const int64_t live = t5_supply( db, core );

   turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-h-bn" );
   fc::ecc::commitment_type I1, I2; std::vector<char> proof;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, proof );
   T_set_recovery_v2( t, I1, I2, proof );
   set_expiration( db, trx );
   trx.operations = { t };
   sign( trx, p.keys[s] );
   BOOST_CHECK_NO_THROW( PUSH_TX( db, trx ) );
   trx.clear_signatures(); trx.operations.clear();
   generate_block();
   BOOST_CHECK_EQUAL( t5_supply( db, core ), live - 10 );
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

   T_r15_mark_decoyed( db, p.commits[s] );

   fc::ecc::commitment_type I1, I2; std::vector<char> good;
   T_r15_prove_true( p, s, core.get_id(), I1, I2, good );
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
      BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
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
      BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
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
      BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
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
      BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
      trx.clear_signatures(); trx.operations.clear();
   }
   {
      fc::ecc::commitment_type zero_I1; zero_I1.fill( 0 );
      turnstile_reproof_operation t = T_r15_turnstile( core, p, s, "r15-m-bn-d2" );
      T_set_recovery_v2( t, zero_I1, I2, good );
      set_expiration( db, trx );
      trx.operations = { t };
      sign( trx, p.keys[s] );
      BOOST_CHECK_THROW( PUSH_TX( db, trx ), fc::exception );
      trx.clear_signatures(); trx.operations.clear();
   }
} FC_CAPTURE_AND_RETHROW() }

BOOST_AUTO_TEST_SUITE_END()
