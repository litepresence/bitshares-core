/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License (see stealth_proof.cpp for the full text).
 *
 * Wallet-side G2 provers. See stealth_prover.hpp: EVALUATORS MUST NEVER
 * CALL THIS FILE (non-deterministic randomness per proof would fork
 * consensus).
 */

#include <graphene/chain/stealth_prover.hpp>
#include <graphene/chain/stealth_proof.hpp>

#include <graphene/protocol/stealth.hpp>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <memory>
#include <mutex>

// ---------------------------------------------------------------------------
// WPC-05 (REPAIR-135): ctgrind/dudect instrumentation hooks.
//
// Compile-time gated — NEVER defined in a production build. Enable with
// -DGRAPHENE_CTGRIND plus the Valgrind memcheck headers (apt: valgrind),
// then run the prover entry points under Memcheck/ctgrind:
//   GRAPHENE_CTGRIND_SECRET marks secret input bytes undefined (the
//   ctgrind "this is secret" declaration): any branch, index, or syscall
//   consuming them is reported as an uninitialised-value use — which IS
//   the secret-dependent-control-flow finding (WPC rules 2/3/16).
//   GRAPHENE_CTGRIND_PUBLIC marks outputs defined at a prover's exit:
//   proofs are wire data, so without this the run drowns in syscall
//   false positives on proof bytes derived from tainted scalars.
//
// Differential runs (ctgrind error scan + dudect p-values archived to
// build/logs/) are a PRE-ACTIVATION gate requiring external tooling; this
// environment has no valgrind headers/binary, so here the hooks are
// compile-verified only (see task-r9-i7-report.md).
// ---------------------------------------------------------------------------
#ifdef GRAPHENE_CTGRIND
#  include <valgrind/valgrind.h>
#  include <valgrind/memcheck.h>
#  define GRAPHENE_CTGRIND_SECRET( p, n )  VALGRIND_MAKE_MEM_UNDEFINED( (p), (n) )
#  define GRAPHENE_CTGRIND_PUBLIC( p, n )  VALGRIND_MAKE_MEM_DEFINED( (p), (n) )
#else
#  define GRAPHENE_CTGRIND_SECRET( p, n )  ((void)0)
#  define GRAPHENE_CTGRIND_PUBLIC( p, n )  ((void)0)
#endif

namespace graphene { namespace chain {

namespace {

// ---------------------------------------------------------------------------
// Local EC context (per-call setup: proving is one-shot wallet work, never
// a consensus hot path; per-call groups are thread-safe by construction).
// ---------------------------------------------------------------------------

struct prover_ctx
{
   EC_GROUP* g = nullptr;
   BN_CTX*   bctx = nullptr;
   BIGNUM*   order = nullptr;
   bool ok = false;
   prover_ctx()
   {
      g = EC_GROUP_new_by_curve_name( NID_secp256k1 );
      bctx = BN_CTX_new();
      order = BN_new();
      if( g && bctx && order &&
          EC_GROUP_get_order( g, order, bctx ) == 1 )
         ok = true;
   }
   ~prover_ctx()
   {
      // Order is public; the group holds no secrets.
      if( order ) BN_free( order );
      if( bctx ) BN_CTX_free( bctx );
      if( g ) EC_GROUP_free( g );
   }
};

// Last-cleansed secret image for the test hook (copy taken AFTER the
// cleanse, so nonzero bytes prove the cleanse did not run on that buffer).
thread_local std::vector<unsigned char> t_last_cleansed;

// WPC-02 (REPAIR-134): entropy-gate status provider. Defaults to
// RAND_status(); only the test hook (stealth_prover_test_set_rand_status,
// outside this namespace) ever swaps it, and only inside the unit suite.
int (*g_rand_status)() = &RAND_status;

#ifdef GRAPHENE_CTGRIND
// WPC-05: declare a secret scalar held in an opaque BIGNUM (OpenSSL 1.1+
// hides the limbs, so they cannot be marked directly). Round-trip the
// canonical 32-byte encoding through an UNDEFINED buffer instead: the
// V-bits propagate through BN_bin2bn's arithmetic into the limbs, and
// every later branch/index on them is reported. Value is unchanged
// (secrets here are already reduced mod n < 2^256, so a 32-byte pad is
// lossless).
void ctgrind_taint_bn( const BIGNUM* b )
{
   if( !b ) return;
   unsigned char t[32];
   BN_bn2binpad( b, t, 32 );
   GRAPHENE_CTGRIND_SECRET( t, 32 );
   BN_bin2bn( t, 32, const_cast<BIGNUM*>( b ) );
   stealth_cleanse_secret( t, 32 );
}
#endif

void cleanse_and_snapshot( unsigned char buf[32] )
{
   stealth_cleanse_secret( buf, 32 );
   t_last_cleansed.assign( buf, buf + 32 );
}

// Fresh nonzero scalar mod n from RAND_bytes (bounded retries; false on
// RNG failure — fail-closed, never fall back to weak randomness).
bool rand_scalar_nonzero( BIGNUM* out, const BIGNUM* order, BN_CTX* ctx )
{
   unsigned char buf[32];
   for( int i = 0; i < 16; ++i )
   {
      if( RAND_bytes( buf, 32 ) != 1 )
      {
         stealth_cleanse_secret( buf, 32 );
         return false;
      }
      BN_bin2bn( buf, 32, out );
      stealth_cleanse_secret( buf, 32 );
      BN_mod( out, out, order, ctx );
      if( !BN_is_zero( out ) )
         return true;
   }
   return false;
}

// Any scalar mod n (zero allowed — simulation nonces only).
bool rand_scalar( BIGNUM* out, const BIGNUM* order, BN_CTX* ctx )
{
   unsigned char buf[32];
   if( RAND_bytes( buf, 32 ) != 1 )
   {
      stealth_cleanse_secret( buf, 32 );
      return false;
   }
   BN_bin2bn( buf, 32, out );
   stealth_cleanse_secret( buf, 32 );
   BN_mod( out, out, order, ctx );
   return true;
}

bool compress_point( const EC_GROUP* g, const EC_POINT* p,
                     std::vector<unsigned char>& out33 )
{
   out33.assign( 33, 0 );
   size_t len = EC_POINT_point2oct( g, p, POINT_CONVERSION_COMPRESSED,
                                    out33.data(), out33.size(), nullptr );
   return len == 33;
}

EC_POINT* open_point( const EC_GROUP* g, const unsigned char* data, size_t len )
{
   EC_POINT* p = EC_POINT_new( g );
   if( !p ) return nullptr;
   if( EC_POINT_oct2point( (EC_GROUP*)g, p, data, len, nullptr ) != 1 )
   {
      EC_POINT_free( p );
      return nullptr;
   }
   return p;
}

// One ring leg (single version). Mirrors the test-side ring prover's
// equations exactly (L/R/M legs, stealth_challenge transcript, close at
// the real member); randomness comes from RAND_bytes.
bool prove_leg( const prover_ctx& pc,
                uint8_t version,
                const std::vector<EC_POINT*>& Q,
                size_t s,
                const BIGNUM* b_s, const BIGNUM* v_s,
                const BIGNUM* b_prime,
                const std::string& msg32,
                std::vector<unsigned char>& image_out,
                std::vector<unsigned char>& pseudo_out,
                std::vector<char>& sig_out,
                std::string& err )
{
#ifdef GRAPHENE_CTGRIND
   // WPC-05: declare the secret openings. b_s (real input blind) and
   // b_prime (pseudo-output blind) are secret; v_s is the swap amount,
   // public on the op109 wire, so it stays defined (no false positives).
   ctgrind_taint_bn( b_s );
   ctgrind_taint_bn( b_prime );
#endif
   const size_t n = Q.size();
   EC_GROUP* g = pc.g;
   BN_CTX* ctx = pc.bctx;
   const BIGNUM* order = pc.order;

   // Version-domain bases + value base (public accessors, shared with the
   // verifiers — no parallel constant set to diverge).
   std::vector<unsigned char> J1b = stealth_J1_point( version );
   std::vector<unsigned char> J2b = stealth_J2_point( version );
   std::vector<unsigned char> Hb = stealth_H_point();
   EC_POINT* J1 = ( J1b.size() == 33 ) ? open_point( g, J1b.data(), 33 ) : nullptr;
   EC_POINT* J2 = ( J2b.size() == 33 ) ? open_point( g, J2b.data(), 33 ) : nullptr;
   EC_POINT* H = ( Hb.size() == 33 ) ? open_point( g, Hb.data(), 33 ) : nullptr;
   EC_POINT* I = EC_POINT_new( g );
   EC_POINT* L = EC_POINT_new( g );
   EC_POINT* R = EC_POINT_new( g );
   EC_POINT* T = EC_POINT_new( g );
   EC_POINT* M = EC_POINT_new( g );
   EC_POINT* P = EC_POINT_new( g );
   if( !J1 || !J2 || !H || !I || !L || !R || !T || !M || !P )
   {
      err = "ec alloc fail";
      goto fail;
   }

   // Key image I = b_s*J1 + v_s*J2.
   if( EC_POINT_mul( g, I, nullptr, J1, b_s, ctx ) != 1 ||
       EC_POINT_mul( g, T, nullptr, J2, v_s, ctx ) != 1 ||
       EC_POINT_add( g, I, I, T, ctx ) != 1 )
   {
      err = "image ec fail";
      goto fail;
   }
   // Pseudo-output P = b'*G + v*H (SAME value as the real member).
   if( EC_POINT_mul( g, P, b_prime, nullptr, nullptr, ctx ) != 1 ||
       EC_POINT_mul( g, T, nullptr, H, v_s, ctx ) != 1 ||
       EC_POINT_add( g, P, P, T, ctx ) != 1 )
   {
      err = "pseudo ec fail";
      goto fail;
   }
   if( !compress_point( g, I, image_out ) ||
       !compress_point( g, P, pseudo_out ) )
   {
      err = "compress fail";
      goto fail;
   }

   {
      // D_i = P - Q_i per member (verifier recomputes the same).
      std::vector<EC_POINT*> Dv( n, nullptr );
      for( size_t k = 0; k < n; ++k )
      {
         Dv[k] = EC_POINT_new( g );
         if( !Dv[k] || EC_POINT_copy( Dv[k], P ) != 1 )
         {
            err = "ec fail";
            for( auto d : Dv ) if( d ) EC_POINT_free( d );
            goto fail;
         }
         EC_POINT* Qk = EC_POINT_new( g );
         if( !Qk || EC_POINT_copy( Qk, Q[k] ) != 1 ||
             EC_POINT_invert( g, Qk, ctx ) != 1 ||
             EC_POINT_add( g, Dv[k], Dv[k], Qk, ctx ) != 1 )
         {
            err = "ec fail";
            if( Qk ) EC_POINT_free( Qk );
            for( auto d : Dv ) if( d ) EC_POINT_free( d );
            goto fail;
         }
         EC_POINT_free( Qk );
      }

      std::vector<BIGNUM*> c( n ), rb( n ), rv( n ), rd( n );
      for( size_t i = 0; i < n; ++i )
      {
         c[i] = BN_new(); rb[i] = BN_new(); rv[i] = BN_new(); rd[i] = BN_new();
         if( !c[i] || !rb[i] || !rv[i] || !rd[i] )
         {
            err = "bn alloc fail";
            for( auto x : c ) if( x ) BN_clear_free( x );
            for( auto x : rb ) if( x ) BN_clear_free( x );
            for( auto x : rv ) if( x ) BN_clear_free( x );
            for( auto x : rd ) if( x ) BN_clear_free( x );
            for( auto d : Dv ) if( d ) EC_POINT_free( d );
            goto fail;
         }
      }

      // Fresh signing nonces (production randomness; the test prover uses
      // deterministic labels here — same equations, weaker discipline).
      BIGNUM* a_b = BN_new();
      BIGNUM* a_v = BN_new();
      BIGNUM* a_d = BN_new();
      bool nonces_ok = a_b && a_v && a_d &&
         rand_scalar_nonzero( a_b, order, ctx ) &&
         rand_scalar_nonzero( a_v, order, ctx ) &&
         rand_scalar_nonzero( a_d, order, ctx );
      if( !nonces_ok )
      {
         err = "rng fail";
         if( a_b ) BN_clear_free( a_b );
         if( a_v ) BN_clear_free( a_v );
         if( a_d ) BN_clear_free( a_d );
         for( auto x : c ) BN_clear_free( x );
         for( auto x : rb ) BN_clear_free( x );
         for( auto x : rv ) BN_clear_free( x );
         for( auto x : rd ) BN_clear_free( x );
         for( auto d : Dv ) EC_POINT_free( d );
         goto fail;
      }
      if( EC_POINT_mul( g, L, a_b, nullptr, nullptr, ctx ) != 1 ||
          EC_POINT_mul( g, T, nullptr, H, a_v, ctx ) != 1 ||
          EC_POINT_add( g, L, L, T, ctx ) != 1 ||
          EC_POINT_mul( g, R, nullptr, J1, a_b, ctx ) != 1 ||
          EC_POINT_mul( g, T, nullptr, J2, a_v, ctx ) != 1 ||
          EC_POINT_add( g, R, R, T, ctx ) != 1 ||
          EC_POINT_mul( g, M, a_d, nullptr, nullptr, ctx ) != 1 )
      {
         err = "commit ec fail";
         BN_clear_free( a_b ); BN_clear_free( a_v ); BN_clear_free( a_d );
         for( auto x : c ) BN_clear_free( x );
         for( auto x : rb ) BN_clear_free( x );
         for( auto x : rv ) BN_clear_free( x );
         for( auto x : rd ) BN_clear_free( x );
         for( auto d : Dv ) EC_POINT_free( d );
         goto fail;
      }

      std::vector<unsigned char> Lc, Rc, Mc;
      if( !compress_point( g, L, Lc ) || !compress_point( g, R, Rc ) ||
          !compress_point( g, M, Mc ) )
      {
         err = "compress fail";
         BN_clear_free( a_b ); BN_clear_free( a_v ); BN_clear_free( a_d );
         for( auto x : c ) BN_clear_free( x );
         for( auto x : rb ) BN_clear_free( x );
         for( auto x : rv ) BN_clear_free( x );
         for( auto x : rd ) BN_clear_free( x );
         for( auto d : Dv ) EC_POINT_free( d );
         goto fail;
      }
      {
         fc::sha256 cc = stealth_challenge( msg32, Lc, Rc, Mc );
         BN_bin2bn( (const unsigned char*)cc.data(), 32, c[(s+1)%n] );
         BN_mod( c[(s+1)%n], c[(s+1)%n], order, ctx );
      }

      // Simulate every non-real member with fresh randomness.
      size_t i = (s+1) % n;
      size_t guard = 0;
      bool sim_ok = true;
      while( i != s && guard++ <= n )
      {
         if( !rand_scalar( rb[i], order, ctx ) ||
             !rand_scalar( rv[i], order, ctx ) ||
             !rand_scalar( rd[i], order, ctx ) )
         {
            sim_ok = false;
            break;
         }
         if( EC_POINT_mul( g, L, rb[i], nullptr, nullptr, ctx ) != 1 ||
             EC_POINT_mul( g, T, nullptr, H, rv[i], ctx ) != 1 ||
             EC_POINT_add( g, L, L, T, ctx ) != 1 ||
             EC_POINT_mul( g, T, nullptr, Q[i], c[i], ctx ) != 1 ||
             EC_POINT_add( g, L, L, T, ctx ) != 1 ||
             EC_POINT_mul( g, R, nullptr, J1, rb[i], ctx ) != 1 ||
             EC_POINT_mul( g, T, nullptr, J2, rv[i], ctx ) != 1 ||
             EC_POINT_add( g, R, R, T, ctx ) != 1 ||
             EC_POINT_mul( g, T, nullptr, I, c[i], ctx ) != 1 ||
             EC_POINT_add( g, R, R, T, ctx ) != 1 ||
             EC_POINT_mul( g, M, rd[i], nullptr, nullptr, ctx ) != 1 ||
             EC_POINT_mul( g, T, nullptr, Dv[i], c[i], ctx ) != 1 ||
             EC_POINT_add( g, M, M, T, ctx ) != 1 )
         {
            sim_ok = false;
            break;
         }
         std::vector<unsigned char> lc, rc, mc;
         if( !compress_point( g, L, lc ) || !compress_point( g, R, rc ) ||
             !compress_point( g, M, mc ) )
         {
            sim_ok = false;
            break;
         }
         fc::sha256 nx = stealth_challenge( msg32, lc, rc, mc );
         BN_bin2bn( (const unsigned char*)nx.data(), 32, c[(i+1)%n] );
         BN_mod( c[(i+1)%n], c[(i+1)%n], order, ctx );
         i = (i+1) % n;
      }
      if( !sim_ok || i != s )
      {
         err = sim_ok ? "ring walk fail" : "rng/ec fail in simulation";
         BN_clear_free( a_b ); BN_clear_free( a_v ); BN_clear_free( a_d );
         for( auto x : c ) BN_clear_free( x );
         for( auto x : rb ) BN_clear_free( x );
         for( auto x : rv ) BN_clear_free( x );
         for( auto x : rd ) BN_clear_free( x );
         for( auto d : Dv ) EC_POINT_free( d );
         goto fail;
      }
      // Close at the real member: rb = a_b − c*b_s, rv = a_v − c*v,
      // rd = a_d − c*(b′ − b_s).
      {
         BIGNUM* t = BN_new();
         BIGNUM* bd = BN_new();
         if( !t || !bd )
         {
            err = "bn alloc fail";
            if( t ) BN_clear_free( t );
            if( bd ) BN_clear_free( bd );
            BN_clear_free( a_b ); BN_clear_free( a_v ); BN_clear_free( a_d );
            for( auto x : c ) BN_clear_free( x );
            for( auto x : rb ) BN_clear_free( x );
            for( auto x : rv ) BN_clear_free( x );
            for( auto x : rd ) BN_clear_free( x );
            for( auto d : Dv ) EC_POINT_free( d );
            goto fail;
         }
         BN_mod_sub( bd, b_prime, b_s, order, ctx );
         BN_mod_mul( t, c[s], b_s, order, ctx );
         BN_mod_sub( rb[s], a_b, t, order, ctx );
         BN_mod_mul( t, c[s], v_s, order, ctx );
         BN_mod_sub( rv[s], a_v, t, order, ctx );
         BN_mod_mul( t, c[s], bd, order, ctx );
         BN_mod_sub( rd[s], a_d, t, order, ctx );
         BN_clear_free( t );
         BN_clear_free( bd );
      }
      // Zeroization snapshot: post-cleanse copy of this leg's ephemeral
      // signing nonce bytes (hook asserts all zeros).
      {
         unsigned char ad32[32];
         BN_bn2binpad( a_d, ad32, 32 );
         cleanse_and_snapshot( ad32 );
      }
      BN_clear_free( a_b ); BN_clear_free( a_v ); BN_clear_free( a_d );

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
      stealth_cleanse_secret( buf, 32 );
      for( auto x : c ) BN_clear_free( x );
      for( auto x : rb ) BN_clear_free( x );
      for( auto x : rv ) BN_clear_free( x );
      for( auto x : rd ) BN_clear_free( x );
      for( auto d : Dv ) EC_POINT_free( d );
   }

   EC_POINT_free( J1 ); EC_POINT_free( J2 ); EC_POINT_free( H );
   EC_POINT_free( I ); EC_POINT_free( L ); EC_POINT_free( R );
   EC_POINT_free( T ); EC_POINT_free( M ); EC_POINT_free( P );
#ifdef GRAPHENE_CTGRIND
   // WPC-05: key images, pseudo-output and signatures are wire data —
   // mark them defined at exit so downstream public comparisons and the
   // syscall checks do not false-positive on tainted scalar arithmetic.
   GRAPHENE_CTGRIND_PUBLIC( image_out.data(), image_out.size() );
   GRAPHENE_CTGRIND_PUBLIC( pseudo_out.data(), pseudo_out.size() );
   GRAPHENE_CTGRIND_PUBLIC( sig_out.data(), sig_out.size() );
#endif
   return true;

fail:
   if( J1 ) EC_POINT_free( J1 );
   if( J2 ) EC_POINT_free( J2 );
   if( H ) EC_POINT_free( H );
   if( I ) EC_POINT_free( I );
   if( L ) EC_POINT_free( L );
   if( R ) EC_POINT_free( R );
   if( T ) EC_POINT_free( T );
   if( M ) EC_POINT_free( M );
   if( P ) EC_POINT_free( P );
   return false;
}

} // anonymous namespace

bool stealth_prover_entropy_ready()
{
   // One RAND_poll() attempt at first prover use (seeds from the OS if the
   // CSPRNG is unseeded); every call then reads the status provider, so a
   // gate that closes is never cached open and a gate that opens again
   // recovers (WPC-02).
   static std::once_flag poll_once;
   std::call_once( poll_once, []{ (void)RAND_poll(); } );
   return g_rand_status() == 1;
}

stealth_rand_status_fn stealth_prover_test_set_rand_status( stealth_rand_status_fn fn )
{
   const stealth_rand_status_fn prev = g_rand_status;
   g_rand_status = fn ? fn : &RAND_status;
   return prev;
}

fc::sha256 stealth_sample_blind()
{
   FC_ASSERT( stealth_prover_entropy_ready(),
              "prover RNG unseeded — refusing to sample a blind (WPC-02)" );
   prover_ctx pc;
   FC_ASSERT( pc.ok, "prover EC init failed" );
   BIGNUM* b = BN_new();
   FC_ASSERT( b != nullptr, "prover BN alloc failed" );
   bool ok = rand_scalar_nonzero( b, pc.order, pc.bctx );
   unsigned char buf[32];
   if( ok )
      BN_bn2binpad( b, buf, 32 );
   BN_clear_free( b );
   FC_ASSERT( ok, "prover RNG failed: refusing to sample a blind" );
   fc::sha256 out;
   std::copy( buf, buf + 32, (char*)out.data() );
   stealth_cleanse_secret( buf, 32 );
#ifdef GRAPHENE_CTGRIND
   // WPC-05: a fresh blinding factor is secret by definition — declare it
   // so every consumer inherits the taint through the ctgrind run.
   GRAPHENE_CTGRIND_SECRET( out.data(), 32 );
#endif
   return out;
}

bool stealth_prove_pool_ring( uint8_t version, uint8_t alt_version,
   const std::vector<fc::ecc::commitment_type>& ring,
   size_t real_index,
   const fc::sha256& blind_s, uint64_t value_s,
   const fc::sha256& blind_P,
   const std::string& msg_main32, const std::string& msg_alt32,
   stealth_pool_ring_proof& out, std::string& err )
{
   using protocol::GRAPHENE_STEALTH_PROOF_V1;
   using protocol::GRAPHENE_STEALTH_PROOF_V2;
   using protocol::GRAPHENE_STEALTH_RING_TARGET;
   using protocol::GRAPHENE_STEALTH_RING_MAX;

   const size_t n = ring.size();
   if( ( version != GRAPHENE_STEALTH_PROOF_V1 &&
         version != GRAPHENE_STEALTH_PROOF_V2 ) ||
       ( alt_version != GRAPHENE_STEALTH_PROOF_V1 &&
         alt_version != GRAPHENE_STEALTH_PROOF_V2 ) ||
       alt_version == version )
   {
      err = "versions must be distinct V1/V2";
      return false;
   }
   // G2 consensus floors rings at TARGET (no thin-pool emergency leg);
   // the prover refuses sizes consensus would refuse so wallets cannot
   // build unspendable proofs.
   if( n < GRAPHENE_STEALTH_RING_TARGET || n > GRAPHENE_STEALTH_RING_MAX )
   {
      err = "ring size out of bounds (G2 needs 16..32)";
      return false;
   }
   if( real_index >= n )
   {
      err = "real index out of range";
      return false;
   }
   if( msg_main32.size() != 32 || msg_alt32.size() != 32 )
   {
      err = "messages must be 32 bytes";
      return false;
   }
   // WPC-02: refuse before any RAND_bytes draw if the CSPRNG is unseeded.
   if( !stealth_prover_entropy_ready() )
   {
      err = "prover RNG unseeded (entropy gate, WPC-02)";
      return false;
   }

   prover_ctx pc;
   if( !pc.ok )
   {
      err = "prover EC init failed";
      return false;
   }

   // Openings as scalars (caller's blinds are wallet secret state; only
   // local BN copies exist here and all are BN_clear_free'd below).
   BIGNUM* b_s = BN_new();
   BIGNUM* b_prime = BN_new();
   BIGNUM* v_s = BN_new();
   if( !b_s || !b_prime || !v_s )
   {
      err = "bn alloc fail";
      if( b_s ) BN_clear_free( b_s );
      if( b_prime ) BN_clear_free( b_prime );
      if( v_s ) BN_clear_free( v_s );
      return false;
   }
   BN_bin2bn( (const unsigned char*)blind_s.data(), 32, b_s );
   BN_mod( b_s, b_s, pc.order, pc.bctx );
   BN_bin2bn( (const unsigned char*)blind_P.data(), 32, b_prime );
   BN_mod( b_prime, b_prime, pc.order, pc.bctx );
   BN_set_word( v_s, (BN_ULONG)value_s );

   // Ring points (fail-closed on any bad/off-curve/identity member).
   std::vector<EC_POINT*> Q( n, nullptr );
   for( size_t k = 0; k < n; ++k )
   {
      Q[k] = open_point( pc.g, (const unsigned char*)ring[k].data(), 33 );
      if( !Q[k] )
      {
         err = "bad ring point";
         for( auto q : Q ) if( q ) EC_POINT_free( q );
         BN_clear_free( b_s ); BN_clear_free( b_prime ); BN_clear_free( v_s );
         return false;
      }
   }

   std::vector<unsigned char> img, pseudo, imga, pseudoa;
   std::vector<char> sig, siga;
   bool ok = prove_leg( pc, version, Q, real_index, b_s, v_s, b_prime,
                        msg_main32, img, pseudo, sig, err );
   if( ok )
      ok = prove_leg( pc, alt_version, Q, real_index, b_s, v_s, b_prime,
                      msg_alt32, imga, pseudoa, siga, err );
   for( auto q : Q ) EC_POINT_free( q );
   BN_clear_free( b_s ); BN_clear_free( b_prime ); BN_clear_free( v_s );
   if( !ok )
      return false;
   if( pseudo != pseudoa )
   {
      err = "internal: pseudo mismatch across legs";
      return false;
   }
   out.key_image.assign( img.begin(), img.end() );
   out.alt_key_image.assign( imga.begin(), imga.end() );
   if( pseudo.size() != 33 )
   {
      err = "internal: bad pseudo size";
      return false;
   }
   std::copy( pseudo.begin(), pseudo.end(), out.pseudo_output.begin() );
   out.ring_sig = sig;
   out.alt_ring_sig = siga;
   return true;
}

// ---------------------------------------------------------------------------
// Step 2: BP+ m=1 + kernel scalar + Schnorr pin provers.
// ---------------------------------------------------------------------------

namespace {

// Owned OpenSSL handles (the test-side provers leak everything; production
// must free every allocation on every path — success included).
struct clear_bn_deleter
{
   void operator()( BIGNUM* b ) const { if( b ) BN_clear_free( b ); }
};
using own_bn = std::unique_ptr<BIGNUM, clear_bn_deleter>;
struct free_pt_deleter
{
   void operator()( EC_POINT* p ) const { if( p ) EC_POINT_free( p ); }
};
using own_pt = std::unique_ptr<EC_POINT, free_pt_deleter>;

own_bn new_bn() { return own_bn( BN_new() ); }
own_bn new_bn_word( BN_ULONG w )
{
   own_bn b = new_bn();
   if( b ) BN_set_word( b.get(), w );
   return b;
}

// Transcript squeeze mirroring the test prover exactly (stealth_bp_hash
// reduces mod n itself — no second reduction here, byte-identical logic).
own_bn bp_hash_scalar( const std::string& domain,
   const std::vector<std::vector<unsigned char>>& items )
{
   fc::sha256 h = stealth_bp_hash( domain, items );
   own_bn b = new_bn();
   if( b ) BN_bin2bn( (const unsigned char*)h.data(), 32, b.get() );
   return b;
}

bool bp_bytes33( EC_POINT* p, const EC_GROUP* g, std::vector<unsigned char>& out )
{
   out.assign( 33, 0 );
   return EC_POINT_point2oct( g, p, POINT_CONVERSION_COMPRESSED,
                              out.data(), out.size(), nullptr ) == 33;
}

void bp_bin32( unsigned char out[32], const BIGNUM* b )
{
   BN_bn2binpad( b, out, 32 );
}

// Canonical-minimal ULEB128 (the G2VP/G2RM pool field). Independent
// reimplementation of the header-documented encoding (same wire as the
// consensus pool_varint); any divergence fails closed at verify time.
std::string bp_uleb128( uint64_t v )
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

// G2VP challenge e = H("G2VP" || P || amount LE64 || pool ULEB128 || T)
// mod n (scalar_from_sha semantics). Byte-identical to the test-side
// T_g2vp_challenge and to the consensus verifier's preimage.
bool g2vp_challenge( BIGNUM* e_out, const fc::ecc::commitment_type& P,
                     int64_t amount, uint64_t pool,
                     const std::vector<unsigned char>& T33,
                     const BIGNUM* order, BN_CTX* ctx )
{
   if( T33.size() != 33 ) return false;
   std::string pre = "G2VP";
   pre.append( (const char*)P.data(), 33 );
   for( int i = 0; i < 8; ++i )
      pre.push_back( (char)( (uint64_t)amount >> (8*i) ) );
   pre.append( bp_uleb128( pool ) );
   pre.append( (const char*)T33.data(), 33 );
   fc::sha256 h = fc::sha256::hash( pre.data(), pre.size() );
   BN_bin2bn( (const unsigned char*)h.data(), 32, e_out );
   BN_mod( e_out, e_out, order, ctx );
   return true;
}

// One BP+ m=1 attempt (production fold of T_bp_prove_attempt, chained
// transcript only — the flat pre-R9C mode stays test-only). Every
// deterministic Bp_scalar(label) becomes fresh RAND_bytes; all state is
// RAII-owned. True with proof_out set on success.
bool bp_prove_attempt( const prover_ctx& pc,
                       const fc::ecc::commitment_type& C,
                       const fc::sha256& blind, uint64_t value,
                       std::vector<char>& proof_out )
{
#ifdef GRAPHENE_CTGRIND
   // WPC-05: the blinding factor is the only secret here — `value` is
   // public (v_out = amount − composite fee, both plaintext on the op109
   // wire), so its bit decomposition stays defined (no false positives).
   GRAPHENE_CTGRIND_SECRET( blind.data(), 32 );
#endif
   EC_GROUP* g = pc.g;
   BN_CTX* ctx = pc.bctx;
   const BIGNUM* order = pc.order;
   const size_t MN = 64, ROUNDS = 6;
   bool ok = true;
   auto mod_add = [&]( BIGNUM* r, const BIGNUM* a, const BIGNUM* b )
      { BN_mod_add( r, a, b, order, ctx ); };
   auto mod_sub = [&]( BIGNUM* r, const BIGNUM* a, const BIGNUM* b )
      { BN_mod_sub( r, a, b, order, ctx ); };
   auto mod_mul = [&]( BIGNUM* r, const BIGNUM* a, const BIGNUM* b )
      { BN_mod_mul( r, a, b, order, ctx ); };
   auto rand_nz = [&]( BIGNUM* out ) -> bool
      { return rand_scalar_nonzero( out, order, ctx ); };

   // Scalars gamma (blind mod n) and bit vectors aL/aR.
   own_bn gamma = new_bn();
   if( !gamma ) return false;
   BN_bin2bn( (const unsigned char*)blind.data(), 32, gamma.get() );
   BN_mod( gamma.get(), gamma.get(), order, ctx );
   std::vector<own_bn> aL( MN ), aR( MN );
   for( size_t i = 0; i < MN; ++i )
   {
      aL[i] = new_bn(); aR[i] = new_bn();
      if( !aL[i] || !aR[i] ) return false;
      if( ( value >> i ) & 1ULL ) BN_set_word( aL[i].get(), 1 );
      own_bn one = new_bn_word( 1 );
      if( !one ) return false;
      mod_sub( aR[i].get(), aL[i].get(), one.get() );
   }

   // Generators.
   own_pt G0( open_point( g, stealth_G_point().data(), 33 ) );
   std::vector<unsigned char> Hb = stealth_H_point();
   own_pt H0( ( Hb.size() == 33 ) ? open_point( g, Hb.data(), 33 ) : nullptr );
   if( !G0 || !H0 ) return false;
   std::vector<own_pt> Gv( MN ), Hv( MN );
   for( size_t i = 0; i < MN; ++i )
   {
      std::vector<unsigned char> gb = stealth_BP_G( i );
      std::vector<unsigned char> hb = stealth_BP_H( i );
      Gv[i] = own_pt( ( gb.size() == 33 ) ? open_point( g, gb.data(), 33 ) : nullptr );
      Hv[i] = own_pt( ( hb.size() == 33 ) ? open_point( g, hb.data(), 33 ) : nullptr );
      if( !Gv[i] || !Hv[i] ) return false;
   }
   std::vector<unsigned char> Vb( C.begin(), C.end() );

   // A = sum(aL*G + aR*H) + alpha*G.
   own_bn alpha = new_bn();
   if( !alpha || !rand_nz( alpha.get() ) ) return false;
   own_pt A( EC_POINT_new( g ) ), T( EC_POINT_new( g ) ), U( EC_POINT_new( g ) );
   if( !A || !T || !U ) return false;
   EC_POINT_set_to_infinity( g, A.get() );
   for( size_t i = 0; i < MN && ok; ++i )
   {
      ok &= ( EC_POINT_mul( g, T.get(), nullptr, Gv[i].get(), aL[i].get(), ctx ) == 1 &&
              EC_POINT_mul( g, U.get(), nullptr, Hv[i].get(), aR[i].get(), ctx ) == 1 &&
              EC_POINT_add( g, T.get(), T.get(), U.get(), ctx ) == 1 &&
              EC_POINT_add( g, A.get(), A.get(), T.get(), ctx ) == 1 );
   }
   own_pt At( EC_POINT_new( g ) );
   ok &= ( At && EC_POINT_mul( g, At.get(), alpha.get(), nullptr, nullptr, ctx ) == 1 &&
           EC_POINT_add( g, A.get(), A.get(), At.get(), ctx ) == 1 );
   std::vector<unsigned char> Ab;
   if( !ok || !bp_bytes33( A.get(), g, Ab ) ) return false;

   // Challenges y, z (+ R9C chained state seeded by z).
   own_bn y = bp_hash_scalar( "G1BPy", { Vb, Ab } );
   if( !y || BN_is_zero( y.get() ) ) return false;
   unsigned char yb[32]; bp_bin32( yb, y.get() );
   own_bn z = bp_hash_scalar( "G1BPz", { std::vector<unsigned char>( yb, yb + 32 ) } );
   if( !z || BN_is_zero( z.get() ) ) return false;
   own_bn z2 = new_bn();
   if( !z2 ) return false;
   mod_mul( z2.get(), z.get(), z.get() );
   unsigned char zb0[32]; bp_bin32( zb0, z.get() );
   std::vector<unsigned char> tstate( zb0, zb0 + 32 );

   // d[i] = z^2 * 2^i; y_powers[0..MN+1].
   std::vector<own_bn> d( MN ), ypw( MN + 2 );
   for( size_t i = 0; i < MN; ++i ) { d[i] = new_bn(); if( !d[i] ) return false; }
   for( size_t i = 0; i < MN + 2; ++i ) { ypw[i] = new_bn(); if( !ypw[i] ) return false; }
   BN_copy( d[0].get(), z2.get() );
   {
      own_bn two = new_bn_word( 2 );
      if( !two ) return false;
      for( size_t i = 1; i < MN; ++i ) mod_mul( d[i].get(), d[i-1].get(), two.get() );
   }
   BN_set_word( ypw[0].get(), 1 );
   for( size_t i = 1; i < MN + 2; ++i ) mod_mul( ypw[i].get(), ypw[i-1].get(), y.get() );

   // aL1 = aL - z; aR1 = aR + z + d[i]*y^{MN-i}.
   std::vector<own_bn> aL1( MN ), aR1( MN );
   for( size_t i = 0; i < MN; ++i )
   {
      aL1[i] = new_bn(); aR1[i] = new_bn();
      own_bn t = new_bn();
      if( !aL1[i] || !aR1[i] || !t ) return false;
      mod_sub( aL1[i].get(), aL[i].get(), z.get() );
      mod_mul( t.get(), d[i].get(), ypw[MN-i].get() );
      mod_add( aR1[i].get(), aR[i].get(), z.get() );
      mod_add( aR1[i].get(), aR1[i].get(), t.get() );
   }

   // alpha1 = alpha + z^2 * y^{MN+1} * gamma.
   own_bn alpha1 = new_bn();
   {
      own_bn t = new_bn();
      if( !alpha1 || !t ) return false;
      mod_mul( t.get(), z2.get(), ypw[MN+1].get() );
      mod_mul( t.get(), t.get(), gamma.get() );
      mod_add( alpha1.get(), alpha.get(), t.get() );
   }

   // Fold views (raw) over owned generator/vector state (stashed per round
   // so lifetimes extend; the test version aliases and leaks instead).
   std::vector<EC_POINT*> Gp( MN ), Hp( MN );
   for( size_t i = 0; i < MN; ++i ) { Gp[i] = Gv[i].get(); Hp[i] = Hv[i].get(); }
   std::vector<BIGNUM*> ap( MN ), bpv( MN );
   for( size_t i = 0; i < MN; ++i ) { ap[i] = aL1[i].get(); bpv[i] = aR1[i].get(); }
   std::vector<std::vector<own_bn>> keep_bns;
   std::vector<std::vector<own_pt>> keep_pts;
   keep_bns.reserve( ROUNDS * 2 + 2 );
   keep_pts.reserve( ROUNDS + 1 );
   own_bn yinv = new_bn();
   if( !yinv || !BN_mod_inverse( yinv.get(), y.get(), order, ctx ) ) return false;
   std::vector<own_bn> yinvpw( MN );
   for( size_t i = 0; i < MN; ++i ) { yinvpw[i] = new_bn(); if( !yinvpw[i] ) return false; }
   BN_set_word( yinvpw[0].get(), 1 );
   for( size_t i = 1; i < MN; ++i ) mod_mul( yinvpw[i].get(), yinvpw[i-1].get(), yinv.get() );

   std::vector<std::vector<unsigned char>> Lb( ROUNDS ), Rb( ROUNDS );
   size_t nprime = MN;
   int round = 0;
   std::vector<own_bn> ch( ROUNDS );

   auto wip = [&]( const std::vector<BIGNUM*>& a, size_t a0,
                   const std::vector<BIGNUM*>& b, size_t b0,
                   size_t n, const BIGNUM* yy ) {
      own_bn res = new_bn(), yp = new_bn(), t = new_bn();
      if( !res || !yp || !t ) return own_bn();
      BN_zero( res.get() );
      BN_set_word( yp.get(), 1 );
      for( size_t i = 0; i < n; ++i )
      {
         mod_mul( yp.get(), yp.get(), yy );
         mod_mul( t.get(), a[a0+i], b[b0+i] );
         mod_mul( t.get(), t.get(), yp.get() );
         mod_add( res.get(), res.get(), t.get() );
      }
      return res;
   };

   while( nprime > 1 && ok )
   {
      nprime /= 2;
      own_bn cL = wip( ap, 0, bpv, nprime, nprime, y.get() );
      std::vector<own_bn> ahi( nprime );
      for( size_t i = 0; i < nprime; ++i )
      {
         ahi[i] = new_bn();
         if( !ahi[i] ) return false;
         mod_mul( ahi[i].get(), ap[nprime+i], ypw[nprime].get() );
      }
      std::vector<BIGNUM*> ahiv( nprime );
      for( size_t i = 0; i < nprime; ++i ) ahiv[i] = ahi[i].get();
      own_bn cR = wip( ahiv, 0, bpv, 0, nprime, y.get() );
      own_bn dL = new_bn(), dR = new_bn();
      if( !cL || !cR || !dL || !dR ) return false;
      if( !rand_nz( dL.get() ) || !rand_nz( dR.get() ) ) return false;

      // L = sum(a_lo*yinv^n * G_hi + b_hi * H_lo) + cL*H + dL*G.
      own_pt L( EC_POINT_new( g ) );
      if( !L ) return false;
      EC_POINT_set_to_infinity( g, L.get() );
      for( size_t i = 0; i < nprime && ok; ++i )
      {
         own_bn t = new_bn();
         if( !t ) return false;
         mod_mul( t.get(), ap[i], yinvpw[nprime].get() );
         ok &= ( EC_POINT_mul( g, T.get(), nullptr, Gp[nprime+i], t.get(), ctx ) == 1 &&
                 EC_POINT_add( g, L.get(), L.get(), T.get(), ctx ) == 1 &&
                 EC_POINT_mul( g, T.get(), nullptr, Hp[i], bpv[nprime+i], ctx ) == 1 &&
                 EC_POINT_add( g, L.get(), L.get(), T.get(), ctx ) == 1 );
      }
      ok &= ( EC_POINT_mul( g, T.get(), nullptr, H0.get(), cL.get(), ctx ) == 1 &&
              EC_POINT_add( g, L.get(), L.get(), T.get(), ctx ) == 1 &&
              EC_POINT_mul( g, T.get(), dL.get(), nullptr, nullptr, ctx ) == 1 &&
              EC_POINT_add( g, L.get(), L.get(), T.get(), ctx ) == 1 );
      // R = sum(a_hi*y^n * G_lo + b_lo * H_hi) + cR*H + dR*G.
      own_pt R( EC_POINT_new( g ) );
      if( !R ) return false;
      EC_POINT_set_to_infinity( g, R.get() );
      for( size_t i = 0; i < nprime && ok; ++i )
      {
         own_bn t = new_bn();
         if( !t ) return false;
         mod_mul( t.get(), ap[nprime+i], ypw[nprime].get() );
         ok &= ( EC_POINT_mul( g, T.get(), nullptr, Gp[i], t.get(), ctx ) == 1 &&
                 EC_POINT_add( g, R.get(), R.get(), T.get(), ctx ) == 1 &&
                 EC_POINT_mul( g, T.get(), nullptr, Hp[nprime+i], bpv[i], ctx ) == 1 &&
                 EC_POINT_add( g, R.get(), R.get(), T.get(), ctx ) == 1 );
      }
      ok &= ( EC_POINT_mul( g, T.get(), nullptr, H0.get(), cR.get(), ctx ) == 1 &&
              EC_POINT_add( g, R.get(), R.get(), T.get(), ctx ) == 1 &&
              EC_POINT_mul( g, T.get(), dR.get(), nullptr, nullptr, ctx ) == 1 &&
              EC_POINT_add( g, R.get(), R.get(), T.get(), ctx ) == 1 );
      if( !ok ) return false;
      if( !bp_bytes33( L.get(), g, Lb[round] ) ||
          !bp_bytes33( R.get(), g, Rb[round] ) ) return false;

      own_bn challenge = bp_hash_scalar( "G1BPr", { tstate, Lb[round], Rb[round] } );
      if( !challenge || BN_is_zero( challenge.get() ) ) return false;
      {
         unsigned char cb[32]; bp_bin32( cb, challenge.get() );
         tstate.assign( cb, cb + 32 );
         stealth_cleanse_secret( cb, 32 );
      }
      own_bn challenge_inv = new_bn();
      if( !challenge_inv ||
          !BN_mod_inverse( challenge_inv.get(), challenge.get(), order, ctx ) )
         return false;
      ch[round] = std::move( challenge );
      const BIGNUM* chv = ch[round].get();

      // Fold generators and vectors (ownership stashed; views rebound).
      own_bn gt = new_bn();
      if( !gt ) return false;
      mod_mul( gt.get(), yinvpw[nprime].get(), chv );
      std::vector<own_pt> G2( nprime ), H2( nprime );
      for( size_t i = 0; i < nprime && ok; ++i )
      {
         G2[i] = own_pt( EC_POINT_new( g ) );
         H2[i] = own_pt( EC_POINT_new( g ) );
         if( !G2[i] || !H2[i] ) return false;
         ok &= ( EC_POINT_mul( g, T.get(), nullptr, Gp[i], challenge_inv.get(), ctx ) == 1 &&
                 EC_POINT_mul( g, U.get(), nullptr, Gp[nprime+i], gt.get(), ctx ) == 1 &&
                 EC_POINT_add( g, G2[i].get(), T.get(), U.get(), ctx ) == 1 &&
                 EC_POINT_mul( g, T.get(), nullptr, Hp[i], chv, ctx ) == 1 &&
                 EC_POINT_mul( g, U.get(), nullptr, Hp[nprime+i], challenge_inv.get(), ctx ) == 1 &&
                 EC_POINT_add( g, H2[i].get(), T.get(), U.get(), ctx ) == 1 );
      }
      if( !ok ) return false;
      own_bn at = new_bn();
      if( !at ) return false;
      mod_mul( at.get(), challenge_inv.get(), ypw[nprime].get() );
      std::vector<own_bn> ap2( nprime ), bp2( nprime );
      for( size_t i = 0; i < nprime; ++i )
      {
         ap2[i] = new_bn(); bp2[i] = new_bn();
         own_bn t1 = new_bn(), t2 = new_bn();
         if( !ap2[i] || !bp2[i] || !t1 || !t2 ) return false;
         mod_mul( t1.get(), ap[i], chv );
         mod_mul( t2.get(), ap[nprime+i], at.get() );
         mod_add( ap2[i].get(), t1.get(), t2.get() );
         mod_mul( t1.get(), bpv[i], challenge_inv.get() );
         mod_mul( t2.get(), bpv[nprime+i], chv );
         mod_add( bp2[i].get(), t1.get(), t2.get() );
      }
      // alpha1 += dL*ch^2 + dR*chi^2.
      {
         own_bn e2 = new_bn(), ei2 = new_bn(), t = new_bn();
         if( !e2 || !ei2 || !t ) return false;
         mod_mul( e2.get(), chv, chv );
         mod_mul( ei2.get(), challenge_inv.get(), challenge_inv.get() );
         mod_mul( t.get(), dL.get(), e2.get() );
         mod_add( alpha1.get(), alpha1.get(), t.get() );
         mod_mul( t.get(), dR.get(), ei2.get() );
         mod_add( alpha1.get(), alpha1.get(), t.get() );
      }
      for( size_t i = 0; i < nprime; ++i )
      {
         Gp[i] = G2[i].get();
         Hp[i] = H2[i].get();
         ap[i] = ap2[i].get();
         bpv[i] = bp2[i].get();
      }
      Gp.resize( nprime ); Hp.resize( nprime );
      ap.resize( nprime ); bpv.resize( nprime );
      keep_pts.push_back( std::move( G2 ) );
      keep_pts.push_back( std::move( H2 ) );
      keep_bns.push_back( std::move( ap2 ) );
      keep_bns.push_back( std::move( bp2 ) );
      ++round;
   }
   if( !ok || nprime != 1 ) return false;

   // Final round: r, s, d_, eta (fresh production randomness).
   own_bn r = new_bn(), s = new_bn(), d_ = new_bn(), eta = new_bn();
   if( !r || !s || !d_ || !eta ) return false;
   if( !rand_nz( r.get() ) || !rand_nz( s.get() ) ||
       !rand_nz( d_.get() ) || !rand_nz( eta.get() ) ) return false;
   // A1 = r*G' + s*H' + d_*G + (r*y*b' + s*y*a')*H.
   own_pt A1( EC_POINT_new( g ) );
   if( !A1 ) return false;
   EC_POINT_set_to_infinity( g, A1.get() );
   {
      own_bn t1 = new_bn(), t2 = new_bn(), t3 = new_bn();
      if( !t1 || !t2 || !t3 ) return false;
      mod_mul( t1.get(), r.get(), y.get() ); mod_mul( t1.get(), t1.get(), bpv[0] );
      mod_mul( t2.get(), s.get(), y.get() ); mod_mul( t2.get(), t2.get(), ap[0] );
      mod_add( t3.get(), t1.get(), t2.get() );
      ok &= ( EC_POINT_mul( g, T.get(), nullptr, Gp[0], r.get(), ctx ) == 1 &&
              EC_POINT_add( g, A1.get(), A1.get(), T.get(), ctx ) == 1 &&
              EC_POINT_mul( g, T.get(), nullptr, Hp[0], s.get(), ctx ) == 1 &&
              EC_POINT_add( g, A1.get(), A1.get(), T.get(), ctx ) == 1 &&
              EC_POINT_mul( g, T.get(), d_.get(), nullptr, nullptr, ctx ) == 1 &&
              EC_POINT_add( g, A1.get(), A1.get(), T.get(), ctx ) == 1 &&
              EC_POINT_mul( g, T.get(), nullptr, H0.get(), t3.get(), ctx ) == 1 &&
              EC_POINT_add( g, A1.get(), A1.get(), T.get(), ctx ) == 1 );
   }
   // B = eta*G + (r*y*s)*H.
   own_pt B( EC_POINT_new( g ) );
   if( !B ) return false;
   EC_POINT_set_to_infinity( g, B.get() );
   {
      own_bn t = new_bn();
      if( !t ) return false;
      mod_mul( t.get(), r.get(), y.get() ); mod_mul( t.get(), t.get(), s.get() );
      ok &= ( EC_POINT_mul( g, T.get(), eta.get(), nullptr, nullptr, ctx ) == 1 &&
              EC_POINT_add( g, B.get(), B.get(), T.get(), ctx ) == 1 &&
              EC_POINT_mul( g, T.get(), nullptr, H0.get(), t.get(), ctx ) == 1 &&
              EC_POINT_add( g, B.get(), B.get(), T.get(), ctx ) == 1 );
   }
   if( !ok ) return false;
   std::vector<unsigned char> A1b, Bb;
   if( !bp_bytes33( A1.get(), g, A1b ) || !bp_bytes33( B.get(), g, Bb ) )
      return false;
   own_bn e = bp_hash_scalar( "G1BPf", { tstate, A1b, Bb } );
   if( !e || BN_is_zero( e.get() ) ) return false;
   own_bn e2 = new_bn(), r1 = new_bn(), s1 = new_bn(), d1 = new_bn();
   if( !e2 || !r1 || !s1 || !d1 ) return false;
   {
      own_bn t = new_bn();
      if( !t ) return false;
      mod_mul( e2.get(), e.get(), e.get() );
      mod_mul( t.get(), ap[0], e.get() ); mod_add( r1.get(), t.get(), r.get() );
      mod_mul( t.get(), bpv[0], e.get() ); mod_add( s1.get(), t.get(), s.get() );
      mod_mul( t.get(), d_.get(), e.get() ); mod_add( d1.get(), t.get(), eta.get() );
      mod_mul( t.get(), alpha1.get(), e2.get() ); mod_add( d1.get(), d1.get(), t.get() );
   }
   // Verifier requires strict-canonical nonzero responses.
   if( BN_is_zero( r1.get() ) || BN_is_zero( s1.get() ) || BN_is_zero( d1.get() ) )
      return false;

   // Zeroization snapshot: post-cleanse copy of a final-round nonce.
   {
      unsigned char r32[32];
      bp_bin32( r32, r.get() );
      cleanse_and_snapshot( r32 );
   }

   // Wire: m || A || A1 || B || r1 || s1 || d1 || L/R pairs (592B for m=1).
   proof_out.clear();
   proof_out.push_back( (char)1 );
   proof_out.insert( proof_out.end(), Ab.begin(), Ab.end() );
   proof_out.insert( proof_out.end(), A1b.begin(), A1b.end() );
   proof_out.insert( proof_out.end(), Bb.begin(), Bb.end() );
   unsigned char buf[32];
   bp_bin32( buf, r1.get() ); proof_out.insert( proof_out.end(), (char*)buf, (char*)buf + 32 );
   bp_bin32( buf, s1.get() ); proof_out.insert( proof_out.end(), (char*)buf, (char*)buf + 32 );
   bp_bin32( buf, d1.get() ); proof_out.insert( proof_out.end(), (char*)buf, (char*)buf + 32 );
   stealth_cleanse_secret( buf, 32 );
   for( size_t j = 0; j < ROUNDS; ++j )
   {
      proof_out.insert( proof_out.end(), Lb[j].begin(), Lb[j].end() );
      proof_out.insert( proof_out.end(), Rb[j].begin(), Rb[j].end() );
   }
#ifdef GRAPHENE_CTGRIND
   // WPC-05: the range proof is wire data — public at the prover's exit.
   GRAPHENE_CTGRIND_PUBLIC( proof_out.data(), proof_out.size() );
#endif
   return true;
}

} // anonymous namespace

bool stealth_prove_bp_plus_m1( const fc::ecc::commitment_type& C,
   const fc::sha256& blind, uint64_t value,
   std::vector<char>& proof_out, std::string& err )
{
   // WPC-02: refuse before any RAND_bytes draw if the CSPRNG is unseeded.
   if( !stealth_prover_entropy_ready() )
   {
      err = "prover RNG unseeded (entropy gate, WPC-02)";
      return false;
   }
   prover_ctx pc;
   if( !pc.ok )
   {
      err = "prover EC init failed";
      return false;
   }
   // Bounded retries with fresh randomness per attempt (degenerate
   // transcripts are negligible-probability; exhaustion fails closed).
   for( int attempt = 0; attempt < 8; ++attempt )
   {
      std::vector<char> p;
      if( bp_prove_attempt( pc, C, blind, value, p ) &&
          p.size() == stealth_bp_proof_size( 1 ) )
      {
         proof_out = std::move( p );
         return true;
      }
   }
   err = "BP+ prove retry exhausted";
   proof_out.clear();
   return false;
}

fc::sha256 stealth_compute_pool_excess( const fc::sha256& blind_P,
                                        const fc::sha256& blind_out )
{
   prover_ctx pc;
   FC_ASSERT( pc.ok, "prover EC init failed" );
   BIGNUM* a = BN_new();
   BIGNUM* b = BN_new();
   BIGNUM* e = BN_new();
   FC_ASSERT( a && b && e, "prover BN alloc failed" );
   BN_bin2bn( (const unsigned char*)blind_P.data(), 32, a );
   BN_bin2bn( (const unsigned char*)blind_out.data(), 32, b );
   BN_mod_sub( e, a, b, pc.order, pc.bctx );
   unsigned char buf[32];
   BN_bn2binpad( e, buf, 32 );
   BN_clear_free( a ); BN_clear_free( b ); BN_clear_free( e );
   fc::sha256 out;
   std::copy( buf, buf + 32, (char*)out.data() );
   stealth_cleanse_secret( buf, 32 );
   return out;
}

bool stealth_prove_value_pin( const fc::ecc::commitment_type& P,
   int64_t amount_to_sell, uint64_t pool_id,
   const fc::sha256& blind_P,
   std::vector<char>& T_out, std::string& s_out, std::string& err )
{
   // Mirrors the verifier's fail-closed gates (non-positive amounts never
   // produce a pin, even off-consensus).
   if( amount_to_sell <= 0 )
   {
      err = "pin amount must be positive";
      return false;
   }
   // WPC-02: refuse before any RAND_bytes draw if the CSPRNG is unseeded.
   if( !stealth_prover_entropy_ready() )
   {
      err = "prover RNG unseeded (entropy gate, WPC-02)";
      return false;
   }
#ifdef GRAPHENE_CTGRIND
   // WPC-05: blind_P is the secret; P, amount and pool id are public
   // (op109 wire) and stay defined.
   GRAPHENE_CTGRIND_SECRET( blind_P.data(), 32 );
#endif
   prover_ctx pc;
   if( !pc.ok )
   {
      err = "prover EC init failed";
      return false;
   }
   BIGNUM* bp = BN_new();
   BIGNUM* k = BN_new();
   BIGNUM* e = BN_new();
   BIGNUM* s = BN_new();
   if( !bp || !k || !e || !s )
   {
      err = "bn alloc fail";
      if( bp ) BN_clear_free( bp );
      if( k ) BN_clear_free( k );
      if( e ) BN_clear_free( e );
      if( s ) BN_clear_free( s );
      return false;
   }
   BN_bin2bn( (const unsigned char*)blind_P.data(), 32, bp );
   BN_mod( bp, bp, pc.order, pc.bctx );

   EC_POINT* Tp = EC_POINT_new( pc.g );
   if( !Tp )
   {
      err = "ec alloc fail";
      BN_clear_free( bp ); BN_clear_free( k );
      BN_clear_free( e ); BN_clear_free( s );
      return false;
   }
   // s = k + e*b_P must be canonical nonzero (R15C-04 discipline refuses
   // e == 0 too); both are negligible-probability, retried with fresh k.
   bool built = false;
   std::vector<unsigned char> T33;
   for( int attempt = 0; attempt < 8 && !built; ++attempt )
   {
      if( !rand_scalar_nonzero( k, pc.order, pc.bctx ) )
      {
         err = "rng fail";
         break;
      }
      if( EC_POINT_mul( pc.g, Tp, k, nullptr, nullptr, pc.bctx ) != 1 )
      {
         err = "ec fail";
         break;
      }
      if( !compress_point( pc.g, Tp, T33 ) )
      {
         err = "compress fail";
         break;
      }
      if( !g2vp_challenge( e, P, amount_to_sell, pool_id, T33, pc.order, pc.bctx ) )
      {
         err = "challenge fail";
         break;
      }
      if( BN_is_zero( e ) )
         continue; // unreachable by grinding; refused anyway
      BN_mod_mul( s, e, bp, pc.order, pc.bctx );
      BN_mod_add( s, s, k, pc.order, pc.bctx );
      if( BN_is_zero( s ) )
         continue;
      built = true;
   }
   if( !built )
   {
      if( err.empty() ) err = "pin retry exhausted";
      EC_POINT_free( Tp );
      BN_clear_free( bp ); BN_clear_free( k );
      BN_clear_free( e ); BN_clear_free( s );
      return false;
   }
   T_out.assign( T33.begin(), T33.end() );
   unsigned char sbuf[32];
   BN_bn2binpad( s, sbuf, 32 );
   s_out.assign( (char*)sbuf, 32 );
   stealth_cleanse_secret( sbuf, 32 );
   // Zeroization snapshot: post-cleanse copy of the one-time nonce k.
   {
      unsigned char k32[32];
      BN_bn2binpad( k, k32, 32 );
      cleanse_and_snapshot( k32 );
   }
   EC_POINT_free( Tp );
   BN_clear_free( bp ); BN_clear_free( k );
   BN_clear_free( e ); BN_clear_free( s );
#ifdef GRAPHENE_CTGRIND
   // WPC-05: (T, s) is wire data — public at the prover's exit.
   GRAPHENE_CTGRIND_PUBLIC( T_out.data(), T_out.size() );
   GRAPHENE_CTGRIND_PUBLIC( s_out.data(), s_out.size() );
#endif
   return true;
}

bool stealth_prove_spend_auth( uint8_t version,
   const std::vector<protocol::public_key_type>& owner_keys,
   size_t real_index,
   const fc::sha256& owner_scalar,
   const std::string& msg32,
   std::vector<char>& spend_auth,
   std::string& err )
{
   using protocol::GRAPHENE_STEALTH_PROOF_V1;
   using protocol::GRAPHENE_STEALTH_PROOF_V2;
   using protocol::GRAPHENE_STEALTH_PROOF_V3;

   const size_t n = owner_keys.size();
   if( n < 2 || n > 32 )
   { err = "owner key count out of bounds"; return false; }
   if( real_index >= n )
   { err = "real index out of range"; return false; }
   if( msg32.size() != 32 )
   { err = "message must be 32 bytes"; return false; }
   // WPC-02: refuse before any RAND_bytes draw if the CSPRNG is unseeded.
   if( !stealth_prover_entropy_ready() )
   { err = "prover RNG unseeded (entropy gate, WPC-02)"; return false; }

   prover_ctx pc;
   if( !pc.ok )
   { err = "prover EC init failed"; return false; }

   EC_GROUP* g = pc.g;
   BN_CTX* ctx = pc.bctx;
   const BIGNUM* order = pc.order;

   // Version-domain J1 base (same accessor the verifier uses — no divergence).
   std::vector<unsigned char> J1b = stealth_J1_point( version );
   own_pt J1( open_point( g, J1b.data(), 33 ) );
   if( !J1 )
   { err = "J1 base is not a valid point"; return false; }

   // G base (shared with the value leg and all ring verifiers).
   std::vector<unsigned char> gbytes = stealth_G_point();
   own_pt Gpt( EC_POINT_new( g ) );
   if( !Gpt ||
       EC_POINT_oct2point( g, Gpt.get(), gbytes.data(), gbytes.size(), nullptr ) != 1 )
   { err = "G base is not a valid point"; return false; }

   // Parse owner keys into points (fail-closed on any bad/identity member).
   std::vector<own_pt> K( n );
   for( size_t i = 0; i < n; ++i )
   {
      K[i].reset( open_point( g,
         (const unsigned char*)owner_keys[i].key_data.data(), 33 ) );
      if( !K[i] )
      { err = "owner key is not a valid point"; return false; }
      if( EC_POINT_is_at_infinity( g, K[i].get() ) )
      { err = "owner key must not be identity"; return false; }
   }

   // Owner scalar = discrete log of the real member's owner key.
   own_bn x_s( new_bn() );
   BN_bin2bn( (const unsigned char*)owner_scalar.data(), 32, x_s.get() );
   BN_mod( x_s.get(), x_s.get(), order, ctx );

   // Fresh nonce k and initial challenge c0 (both nonzero).
   own_bn k( new_bn() );
   own_bn c0( new_bn() );
   if( !rand_scalar_nonzero( k.get(), order, ctx ) ||
       !rand_scalar_nonzero( c0.get(), order, ctx ) )
   { err = "prover RNG failed"; return false; }

   // Key image I = x_s * J1 (version-domain; one per spend, nullifier-checked).
   own_pt I( EC_POINT_new( g ) );
   if( EC_POINT_mul( g, I.get(), nullptr, J1.get(), x_s.get(), ctx ) != 1 )
   { err = "image ec fail"; return false; }

   std::vector<unsigned char> I33( 33, 0 );
   if( !compress_point( g, I.get(), I33 ) )
   { err = "compress fail"; return false; }

   // Challenges c[i] and responses r[i], one per member.
   std::vector<own_bn> c( n ), r( n );
   for( size_t i = 0; i < n; ++i )
   {
      c[i] = new_bn();
      r[i] = new_bn();
      if( !c[i] || !r[i] )
      { err = "bn alloc fail"; return false; }
   }
   BN_copy( c[real_index].get(), c0.get() ); // c[s] = c0, overwritten by walk

   // Temporary EC points.
   own_pt L( EC_POINT_new( g ) );
   own_pt R( EC_POINT_new( g ) );
   own_pt T( EC_POINT_new( g ) );

   // Domain string, byte-identical to the verifier:
   // "BitShares-G1-SpendAuth-v1" || version_byte.
   std::string domain = "BitShares-G1-SpendAuth-v1";
   domain.push_back( (char)version );

   // Hash helper: c_next = SHA256(domain || msg32 || L33 || R33) mod n.
   auto spend_auth_challenge = [&]( const std::vector<unsigned char>& Lc,
                                    const std::vector<unsigned char>& Rc,
                                    BIGNUM* cnext_out ) -> bool
   {
      unsigned char h[32];
      SHA256_CTX sh;
      SHA256_Init( &sh );
      SHA256_Update( &sh, domain.data(), domain.size() );
      SHA256_Update( &sh, msg32.data(), 32 );
      SHA256_Update( &sh, Lc.data(), 33 );
      SHA256_Update( &sh, Rc.data(), 33 );
      SHA256_Final( h, &sh );
      BIGNUM* cnext = BN_bin2bn( h, 32, nullptr );
      if( !cnext ) return false;
      BN_mod( cnext_out, cnext, order, ctx );
      BN_clear_free( cnext );
      stealth_cleanse_secret( h, 32 );
      return true;
   };

   std::vector<unsigned char> Lc( 33, 0 ), Rc( 33, 0 );

   // --- Ring walk: start at the real member ---
   // Commitment uses k alone (c[s] applied at close): L_s = k*G, R_s = k*J1.
   if( EC_POINT_mul( g, L.get(), k.get(), nullptr, nullptr, ctx ) != 1 ||
       EC_POINT_mul( g, R.get(), nullptr, J1.get(), k.get(), ctx ) != 1 )
   { err = "commit ec fail"; return false; }
   if( !compress_point( g, L.get(), Lc ) || !compress_point( g, R.get(), Rc ) )
   { err = "compress fail"; return false; }
   // c[s+1] = H(domain || msg32 || L_s || R_s).
   if( !spend_auth_challenge( Lc, Rc, c[(real_index + 1) % n].get() ) )
   { err = "challenge fail"; return false; }

   // --- Simulate every non-real member, walking forward from s+1 ---
   size_t i = (real_index + 1) % n;
   size_t guard = 0;
   while( i != real_index && guard++ <= n )
   {
      // Fresh random response for this (simulated) member.
      if( !rand_scalar( r[i].get(), order, ctx ) )
      { err = "simulation RNG fail"; return false; }

      // L_i = r_i * G + c_i * K_i ; R_i = r_i * J1 + c_i * I.
      if( EC_POINT_mul( g, L.get(), r[i].get(), nullptr, nullptr, ctx ) != 1 ||
          EC_POINT_mul( g, T.get(), nullptr, K[i].get(), c[i].get(), ctx ) != 1 ||
          EC_POINT_add( g, L.get(), L.get(), T.get(), ctx ) != 1 ||
          EC_POINT_mul( g, R.get(), nullptr, J1.get(), r[i].get(), ctx ) != 1 ||
          EC_POINT_mul( g, T.get(), nullptr, I.get(), c[i].get(), ctx ) != 1 ||
          EC_POINT_add( g, R.get(), R.get(), T.get(), ctx ) != 1 )
      { err = "simulation ec fail"; return false; }

      if( !compress_point( g, L.get(), Lc ) || !compress_point( g, R.get(), Rc ) )
      { err = "simulation compress fail"; return false; }

      // c[i+1] = H(domain || msg32 || L_i || R_i) (wraps to c[s] at i = s-1).
      if( !spend_auth_challenge( Lc, Rc, c[(i + 1) % n].get() ) )
      { err = "simulation challenge fail"; return false; }

      i = (i + 1) % n;
   }
   if( i != real_index )
   { err = "ring walk did not close"; return false; }

   // --- Close at the real member: r[s] = k - c[s] * x_s ---
   {
      own_bn t( new_bn() );
      BN_mod_mul( t.get(), c[real_index].get(), x_s.get(), order, ctx );
      BN_mod_sub( r[real_index].get(), k.get(), t.get(), order, ctx );
   }

   // --- Assemble output: I(33) || c0(32) || r_0(32) || ... || r_{n-1}(32) ---
   spend_auth.clear();
   spend_auth.reserve( 33 + 32 + 32 * n );
   spend_auth.insert( spend_auth.end(), I33.begin(), I33.end() );

   unsigned char c0buf[32];
   BN_bn2binpad( c[0].get(), c0buf, 32 );
   spend_auth.insert( spend_auth.end(), (char*)c0buf, (char*)c0buf + 32 );
   stealth_cleanse_secret( c0buf, 32 );

   unsigned char rbuf[32];
   for( size_t i = 0; i < n; ++i )
   {
      BN_bn2binpad( r[i].get(), rbuf, 32 );
      spend_auth.insert( spend_auth.end(), (char*)rbuf, (char*)rbuf + 32 );
   }
   stealth_cleanse_secret( rbuf, 32 );

#ifdef GRAPHENE_CTGRIND
   // WPC-05: spend_auth is wire data — public at the prover's exit.
   GRAPHENE_CTGRIND_PUBLIC( spend_auth.data(), spend_auth.size() );
#endif
   err.clear();
   return true;
}

std::vector<unsigned char> stealth_prover_test_last_cleansed()
{
   return t_last_cleansed;
}

} } // graphene::chain
