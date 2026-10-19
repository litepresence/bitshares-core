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

#include <graphene/chain/stealth_proof.hpp>

#include <fc/io/raw.hpp>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <mutex>

namespace graphene { namespace chain {

// Protocol consensus constants live in graphene::protocol (stealth.hpp);
// this TU otherwise only sees graphene::chain.
using protocol::GRAPHENE_STEALTH_RING_MIN;
using protocol::GRAPHENE_STEALTH_RING_MAX;
using protocol::GRAPHENE_STEALTH_RING_TARGET;
using protocol::GRAPHENE_STEALTH_THIN_POOL_DEPTH;
using protocol::GRAPHENE_STEALTH_PROOF_V1;
using protocol::GRAPHENE_STEALTH_PROOF_V2;
using protocol::GRAPHENE_STEALTH_DECOY_MIN_AGE_SEC;
using protocol::GRAPHENE_STEALTH_DECOY_SKEW_WINDOW_BLOCKS;

namespace {

// ---------------------------------------------------------------------------
// RAII wrappers (no leaks on early-false paths; all bounded)
// ---------------------------------------------------------------------------

struct bn_ctx {
   BN_CTX* c;
   bn_ctx(): c( BN_CTX_new() ) {}
   ~bn_ctx() { if( c ) BN_CTX_free( c ); }
   bn_ctx( const bn_ctx& ) = delete;
   bn_ctx& operator=( const bn_ctx& ) = delete;
};

struct bn {
   BIGNUM* b;
   bn(): b( BN_new() ) {}
   explicit bn( const bn& o ): b( BN_dup( o.b ) ) {}
   ~bn() { BN_free( b ); }
   bn& operator=( const bn& ) = delete;
};

struct pt {
   EC_POINT* p;
   explicit pt( const EC_GROUP* g ): p( EC_POINT_new( g ) ) {}
   ~pt() { EC_POINT_free( p ); }
   pt( const pt& ) = delete;
   pt& operator=( const pt& ) = delete;
};

const EC_GROUP* secp_group()
{
   static EC_GROUP* g = EC_GROUP_new_by_curve_name( NID_secp256k1 );
   return g;
}

BIGNUM* secp_order()
{
   static BIGNUM* n = nullptr;
   static std::once_flag f;
   std::call_once( f, []() {
      n = BN_new();
      EC_GROUP_get_order( secp_group(), n, nullptr );
   } );
   return n;
}

BIGNUM* secp_field()
{
   static BIGNUM* p = nullptr;
   static std::once_flag f;
   std::call_once( f, []() {
      p = BN_new();
      EC_GROUP_get_curve_GFp( secp_group(), p, nullptr, nullptr, nullptr );
   } );
   return p;
}

/// Strict parse: 32B big-endian must encode a canonical NON-ZERO scalar
/// (0 < s < n). NC-16: zero was admitted by the < n check alone;
/// the strict S1 is_reduced / scalar_canonical_nz discipline is 0 < s < n,
/// so a zero response never reaches the multiexp legs (c0 == 0 would
/// otherwise collapse the ring equation, a zero pin s collapses to
/// T == e*Y). Used BEFORE any modular reduction so non-canonical encodings
/// are rejected exactly like S1's is_reduced (no malleability surface).
// AUDIT: strict canonical parse (0 < s < n, no wraparound reduction) is the
// S1 is_reduced discipline; relaxing it reopens proof malleability.
bool scalar_parse_strict( BIGNUM* out, const unsigned char* in, size_t len )
{
   if( len != 32 || out == nullptr ) return false;
   BN_bin2bn( in, 32, out );
   return !BN_is_zero( out ) && BN_cmp( out, secp_order() ) < 0;
}

bool scalar_from_sha( BIGNUM* out, const fc::sha256& h )
{
   if( out == nullptr ) return false;
   BN_bin2bn( (const unsigned char*)h.data(), 32, out );
   bn_ctx ctx;
   BN_mod( out, out, secp_order(), ctx.c );
   return true;
}

void scalar_to_bytes( unsigned char out32[32], const BIGNUM* b )
{
   BN_bn2binpad( b, out32, 32 );
}

/// Strict canonical check: 0 < s < n.
bool scalar_canonical_nz( const BIGNUM* b )
{
   if( BN_is_zero( b ) || BN_is_negative( b ) ) return false;
   return BN_cmp( b, secp_order() ) < 0;
}

/// Decompress 33B -> point. False on any invalid encoding/off-curve.
bool point_from_bytes( EC_POINT* out, const std::vector<unsigned char>& in )
{
   if( in.size() != 33 ) return false;
   if( in[0] != 0x02 && in[0] != 0x03 ) return false;
   if( EC_POINT_oct2point( (EC_GROUP*)secp_group(), out, in.data(), in.size(), nullptr ) != 1 )
      return false;
   if( EC_POINT_is_at_infinity( secp_group(), out ) == 1 ) return false;
   if( EC_POINT_is_on_curve( secp_group(), out, nullptr ) != 1 ) return false;
   return true;
}

bool point_from_commit( EC_POINT* out, const fc::ecc::commitment_type& c )
{
   if( EC_POINT_oct2point( (EC_GROUP*)secp_group(), out,
                           (const unsigned char*)c.data(), 33, nullptr ) != 1 )
      return false;
   if( EC_POINT_is_at_infinity( secp_group(), out ) == 1 ) return false;
   if( EC_POINT_is_on_curve( secp_group(), out, nullptr ) != 1 ) return false;
   return true;
}

std::vector<unsigned char> point_to_bytes( const EC_POINT* p )
{
   std::vector<unsigned char> out( 33 );
   size_t len = EC_POINT_point2oct( secp_group(), p, POINT_CONVERSION_COMPRESSED,
                                    out.data(), out.size(), nullptr );
   if( len != 33 ) return {};
   return out;
}

fc::sha256 sha256_of( const std::string& bytes )
{
   unsigned char d[32];
   SHA256( (const unsigned char*)bytes.data(), bytes.size(), d );
   fc::sha256 h;
   std::copy( d, d + 32, (char*)h.data() );
   return h;
}

/// Canonical-minimal ULEB128 encode of a uint64 (G2 pool field). Same wire
/// as fc::raw::pack(unsigned_int) (7 bits per byte, continuation bit),
/// extended to the full 64-bit range. Minimal length by construction, so
/// the encoding is canonical: distinct values give distinct bytes and no
/// value has two encodings. Hash-only transcript (never unpacked),
/// deterministic on every node; integer math only.
std::string pool_varint( uint64_t v )
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

BIGNUM* sqrt_exp() // (p+1)/4 for secp256k1 (p = 3 mod 4)
{
   static BIGNUM* q = nullptr;
   static std::once_flag f;
   std::call_once( f, []() {
      q = BN_new();
      bn_ctx ctx;
      bn tmp;
      BN_copy( tmp.b, secp_field() );
      BN_add_word( tmp.b, 1 );
      BN_rshift( q, tmp.b, 2 );
   } );
   return q;
}

/**
 * Try-and-increment hash-to-point matching tooling/g1_gen_vectors.py
 * EXACTLY (the independent model pinning the goldens): x =
 * sha256(domain || tag || ctr); y = x^((p+1)/4) mod p (principal square
 * root; sound because secp256k1's p = 3 mod 4); the compressed prefix
 * carries y's ACTUAL parity. First ctr with x < p and y^2 == x^3+7 wins
 * (256-try cap). Deterministic: identical on every node for identical
 * inputs.
 *
 * AUDIT: an earlier revision used EC_POINT_set_compressed_coordinates
 * with y_bit=0 (always-even root), which NEGATES ~half the derived points
 * vs the pinned goldens (J2v1/J2v2/BP_H0 are odd: 0x03 prefix). The
 * principal-root form below is what generator_provenance_vectors pins;
 * any change of derivation breaks that test instead of forking the chain.
 */
std::vector<unsigned char> hash_to_point( const std::string& domain,
                                          const std::vector<unsigned char>& tag )
{
   bn_ctx ctx;
   bn seven;
   BN_set_word( seven.b, 7 );
   for( int ctr = 0; ctr < 256; ++ctr )
   {
      std::string pre = domain;
      pre.append( (const char*)tag.data(), tag.size() );
      pre.push_back( (char)ctr );
      fc::sha256 h = sha256_of( pre );
      bn x;
      BN_bin2bn( (const unsigned char*)h.data(), 32, x.b );
      if( BN_cmp( x.b, secp_field() ) >= 0 ) continue;
      bn y, y2, rhs;
      // rhs = x^3 + 7, then y = rhs^((p+1)/4) (principal root)
      BN_mod_sqr( rhs.b, x.b, secp_field(), ctx.c );
      BN_mod_mul( rhs.b, rhs.b, x.b, secp_field(), ctx.c );
      BN_mod_add( rhs.b, rhs.b, seven.b, secp_field(), ctx.c );
      BN_mod_exp( y.b, rhs.b, sqrt_exp(), secp_field(), ctx.c );
      BN_mod_sqr( y2.b, y.b, secp_field(), ctx.c );
      if( BN_cmp( y2.b, rhs.b ) != 0 ) continue;
      unsigned char xb[32];
      BN_bn2binpad( x.b, xb, 32 );
      std::vector<unsigned char> enc;
      enc.reserve( 33 );
      enc.push_back( BN_is_odd( y.b ) ? 0x03 : 0x02 );
      enc.insert( enc.end(), xb, xb + 32 );
      pt P( secp_group() );
      if( EC_POINT_oct2point( (EC_GROUP*)secp_group(), P.p,
                              enc.data(), enc.size(), nullptr ) != 1 )
         continue;
      if( EC_POINT_is_on_curve( secp_group(), P.p, ctx.c ) != 1 ) continue;
      if( EC_POINT_is_at_infinity( secp_group(), P.p ) == 1 ) continue;
      return enc;
   }
   return {}; // fail-closed: no point found (never happens for fixed seeds)
}

/// S2 H constant: x only (y parity even -> prefix 0x02; verified at load).
std::vector<unsigned char> H_bytes()
{
   static const unsigned char Hx[32] = {
      0x50,0x92,0x9b,0x74,0xc1,0xa0,0x49,0x54,0xb7,0x8b,0x4b,0x60,0x35,0xe9,0x7a,0x5e,
      0x07,0x8a,0x5a,0x0f,0x28,0xec,0x96,0xd5,0x47,0xbf,0xee,0x9a,0xce,0x80,0x3a,0xc0 };
   std::vector<unsigned char> out;
   out.reserve( 33 );
   out.push_back( 0x02 );
   out.insert( out.end(), Hx, Hx + 32 );
   return out;
}

const std::vector<std::vector<unsigned char>>& J_cache()
{
   // [J1v1, J2v1, J1v2, J2v2]
   static std::vector<std::vector<unsigned char>> cache;
   static std::once_flag f;
   std::call_once( f, []() {
      const char* seeds[4] = { GRAPHENE_STEALTH_J1_SEED, GRAPHENE_STEALTH_J2_SEED,
                               GRAPHENE_STEALTH_J1_SEED, GRAPHENE_STEALTH_J2_SEED };
      uint8_t vers[4] = { 1, 1, 2, 2 };
      for( int k = 0; k < 4; ++k )
         cache.push_back( hash_to_point( seeds[k], { vers[k] } ) );
   } );
   return cache;
}

const std::vector<std::vector<unsigned char>>& BPG_cache()
{
   static std::vector<std::vector<unsigned char>> cache;
   static std::once_flag f;
   std::call_once( f, []() {
      for( size_t i = 0; i < STEALTH_BP_N; ++i )
         cache.push_back( hash_to_point( "BitShares-G1-BP-G-secp256k1-v1",
                                         { (unsigned char)i } ) );
   } );
   return cache;
}

const std::vector<std::vector<unsigned char>>& BPH_cache()
{
   static std::vector<std::vector<unsigned char>> cache;
   static std::once_flag f;
   std::call_once( f, []() {
      for( size_t i = 0; i < STEALTH_BP_N; ++i )
         cache.push_back( hash_to_point( "BitShares-G1-BP-H-secp256k1-v1",
                                         { (unsigned char)i } ) );
   } );
   return cache;
}

/**
 * Decoded (EC_POINT) cache for every fixed generator. Byte caches above make
 * derivation one-time; this makes point DECODING one-time too (oct2point +
 * on-curve check per verify otherwise dominates batch verification time).
 * Points aremutable only during call_once init; all verify paths use them
 * read-only (shared like secp_group itself). Timing only, never consensus.
 */
struct gen_points {
   EC_POINT* G = nullptr;
   EC_POINT* H = nullptr;
   EC_POINT* J1v1 = nullptr;
   EC_POINT* J2v1 = nullptr;
   EC_POINT* J1v2 = nullptr;
   EC_POINT* J2v2 = nullptr;
   std::vector<EC_POINT*> BPG;
   std::vector<EC_POINT*> BPH;
};

static EC_POINT* decode_or_null( const std::vector<unsigned char>& b )
{
   EC_POINT* p = EC_POINT_new( secp_group() );
   if( !point_from_bytes( p, b ) ) { EC_POINT_free( p ); return nullptr; }
   return p;
}

const gen_points& gen_points_cache()
{
   static gen_points c;
   static std::once_flag f;
   std::call_once( f, []() {
      c.G = EC_POINT_new( secp_group() );
      EC_POINT_copy( c.G, EC_GROUP_get0_generator( secp_group() ) );
      c.H = decode_or_null( H_bytes() );
      const auto& J = J_cache();
      c.J1v1 = decode_or_null( J[0] );
      c.J2v1 = decode_or_null( J[1] );
      c.J1v2 = decode_or_null( J[2] );
      c.J2v2 = decode_or_null( J[3] );
      const auto& Gv = BPG_cache();
      const auto& Hv = BPH_cache();
      for( size_t i = 0; i < STEALTH_BP_N; ++i )
      {
         c.BPG.push_back( decode_or_null( Gv[i] ) );
         c.BPH.push_back( decode_or_null( Hv[i] ) );
      }
   } );
   return c;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

std::vector<unsigned char> stealth_G_point()
{
   const EC_POINT* g = EC_GROUP_get0_generator( secp_group() );
   return point_to_bytes( g );
}

std::vector<unsigned char> stealth_H_point()
{
   return H_bytes();
}

std::vector<unsigned char> stealth_J1_point( uint8_t version )
{
   const auto& c = J_cache();
   if( version == 1 ) return c[0];
   if( version == 2 ) return c[2];
   return {};
}

std::vector<unsigned char> stealth_J2_point( uint8_t version )
{
   const auto& c = J_cache();
   if( version == 1 ) return c[1];
   if( version == 2 ) return c[3];
   return {};
}

std::vector<unsigned char> stealth_BP_G( size_t i )
{
   const auto& c = BPG_cache();
   if( i >= c.size() ) return {};
   return c[i];
}

std::vector<unsigned char> stealth_BP_H( size_t i )
{
   const auto& c = BPH_cache();
   if( i >= c.size() ) return {};
   return c[i];
}

size_t stealth_BP_count() { return STEALTH_BP_N; }

// ---------------------------------------------------------------------------
// Transcript
// ---------------------------------------------------------------------------
// AUDIT: "G1R2" is the ONLY ring-challenge domain in the tree. The G1b-2
// pre-kernel domain "G1R1" that this label was chosen to differ from no
// longer exists anywhere under libraries/ — `rg -n "pre-kernel" libraries/`
// returns these comments and nothing else. So there is no sibling domain to
// collide with; what actually prevents a pre-kernel signature from verifying
// here is that no pre-kernel path is produced or accepted at all. The ring
// message uses a separate domain, "G1RM" (see stealth_ring_message).
// CAUTION when searching for the old label: a bare `rg G1R1 libraries/` also
// matches libraries/egenesis/genesis.json, where the byte sequence occurs
// inside base58-encoded witness keys. Search for "pre-kernel" instead.
fc::sha256 stealth_challenge( const std::string& msg32,
                              const std::vector<unsigned char>& L33,
                              const std::vector<unsigned char>& R33,
                              const std::vector<unsigned char>& M33 )
{
   std::string pre = "G1R2";
   pre.append( msg32 );
   pre.append( (const char*)L33.data(), L33.size() );
   pre.append( (const char*)R33.data(), R33.size() );
   pre.append( (const char*)M33.data(), M33.size() );
   fc::sha256 h = sha256_of( pre );
   bn s;
   scalar_from_sha( s.b, h );
   unsigned char out[32];
   scalar_to_bytes( out, s.b );
   fc::sha256 r;
   std::copy( out, out + 32, (char*)r.data() );
   return r;
}

fc::sha256 stealth_bp_hash( const std::string& domain,
                            const std::vector<std::vector<unsigned char>>& items )
{
   std::string pre = domain;
   for( const auto& it : items )
      pre.append( (const char*)it.data(), it.size() );
   fc::sha256 h = sha256_of( pre );
   bn s;
   scalar_from_sha( s.b, h );
   // NOTE: zero is NOT reduced here; callers enforce non-zero challenges
   // (a zero challenge makes the prover resample; the verifier rejects).
   unsigned char out[32];
   scalar_to_bytes( out, s.b );
   fc::sha256 r;
   std::copy( out, out + 32, (char*)r.data() );
   return r;
}

static std::vector<unsigned char> sha_bytes( const fc::sha256& h )
{
   const char* d = h.data();
   return std::vector<unsigned char>( d, d + 32 );
}

fc::sha256 stealth_ring_message( uint8_t version,
                                 const protocol::asset_id_type& asset,
                                 const std::vector<char>& image33,
                                 const std::vector<fc::ecc::commitment_type>& ring,
                                 const fc::ecc::commitment_type& pseudo,
                                 const std::vector<fc::ecc::commitment_type>& outputs,
                                 protocol::share_type fee )
{
   std::string pre = "G1RM";
   pre.push_back( (char)version );
   // F-03 (mimo-2.6): bind the ring length and output count BEFORE the
   // commitment run. Without them the flat preimage cannot be re-partitioned:
   // ring[33n] || pseudo[33] || outputs[33m] is a fixed-stride byte string, so
   // (n,m)=(k+1,j) and (k,j+1) collide whenever ring[k]==pseudo'. Fixed-width
   // little-endian counts (not varints) keep the encoding canonical by
   // construction and deterministic on every node; 64-bit so no caller can
   // truncate a count.
   {
      auto nvec = fc::raw::pack( (uint64_t)ring.size() );
      pre.append( nvec.data(), nvec.size() );
      auto mvec = fc::raw::pack( (uint64_t)outputs.size() );
      pre.append( mvec.data(), mvec.size() );
   }
   auto avec = fc::raw::pack( asset );
   pre.append( avec.data(), avec.size() );
   pre.append( image33.data(), image33.size() );
   for( const auto& c : ring ) pre.append( (const char*)c.data(), 33 );
   pre.append( (const char*)pseudo.data(), 33 );
   for( const auto& c : outputs ) pre.append( (const char*)c.data(), 33 );
   auto fvec = fc::raw::pack( fee );
   pre.append( fvec.data(), fvec.size() );
   return sha256_of( pre );
}

fc::sha256 stealth_pool_message( uint8_t version,
                                 const protocol::asset_id_type& asset_a,
                                 uint64_t pool_id,
                                 int64_t amount_to_sell, int64_t min_to_receive,
                                 const std::vector<char>& key_image,
                                 const std::vector<fc::ecc::commitment_type>& ring,
                                 const fc::ecc::commitment_type& pseudo,
                                 const std::vector<fc::ecc::commitment_type>& outputs,
                                 int64_t F )
{
   std::string pre = "G2RM";
   pre.push_back( (char)version );
   // F-03 count binding (same discipline as stealth_ring_message :475-507):
   // fixed-width LE64 counts hashed BEFORE the commitment run so no
   // (n,m) re-partitioning of ring[33n] || pseudo[33] || outputs[33m]
   // can share a preimage.
   {
      auto nvec = fc::raw::pack( (uint64_t)ring.size() );
      pre.append( nvec.data(), nvec.size() );
      auto mvec = fc::raw::pack( (uint64_t)outputs.size() );
      pre.append( mvec.data(), mvec.size() );
   }
   auto avec = fc::raw::pack( asset_a ); // varint, self-delimiting
   pre.append( avec.data(), avec.size() );
   pre.append( pool_varint( pool_id ) ); // ULEB128 varint, self-delimiting
   auto amt = fc::raw::pack( amount_to_sell ); // int64: fixed 8B LE
   pre.append( amt.data(), amt.size() );
   auto mn = fc::raw::pack( min_to_receive ); // int64: fixed 8B LE
   pre.append( mn.data(), mn.size() );
   pre.append( key_image.data(), key_image.size() );
   for( const auto& c : ring ) pre.append( (const char*)c.data(), 33 );
   pre.append( (const char*)pseudo.data(), 33 );
   for( const auto& c : outputs ) pre.append( (const char*)c.data(), 33 );
   auto fvec = fc::raw::pack( F ); // int64: fixed 8B LE
   pre.append( fvec.data(), fvec.size() );
   return sha256_of( pre );
}

// ---------------------------------------------------------------------------
// Ring verification
// ---------------------------------------------------------------------------

bool stealth_verify_ring( uint8_t version,
                          const protocol::stealth_ring_input& in,
                          const std::string& msg32,
                          std::string& err )
{
   const size_t n = in.ring.size();
   if( version != GRAPHENE_STEALTH_PROOF_V1 && version != GRAPHENE_STEALTH_PROOF_V2 )
      { err = "bad version"; return false; }
   if( n < GRAPHENE_STEALTH_RING_MIN || n > GRAPHENE_STEALTH_RING_MAX )
      { err = "ring size out of bounds"; return false; }
   if( msg32.size() != 32 ) { err = "message must be 32 bytes"; return false; }
   if( in.key_image.size() != 33 ) { err = "image size"; return false; }
   if( in.ring_sig.size() != 32 + 96 * n ) { err = "sig size"; return false; }

   bn_ctx ctx;
   std::vector<unsigned char> img( in.key_image.begin(), in.key_image.end() );
   pt I( secp_group() );
   if( !point_from_bytes( I.p, img ) ) { err = "bad image point"; return false; }

   auto J1b = stealth_J1_point( version );
   auto J2b = stealth_J2_point( version );
   auto Hb = stealth_H_point();
   if( J1b.empty() || J2b.empty() || Hb.empty() ) { err = "generators unavailable"; return false; }
   // Fixed generators come from the decoded-point cache (timing only).
   const gen_points& GP = gen_points_cache();
   const EC_POINT* J1p = ( version == 1 ) ? GP.J1v1 : GP.J1v2;
   const EC_POINT* J2p = ( version == 1 ) ? GP.J2v1 : GP.J2v2;
   if( !J1p || !J2p || !GP.H ) { err = "generators unavailable"; return false; }
   pt J1( secp_group() ), J2( secp_group() ), H( secp_group() );
   if( !EC_POINT_copy( J1.p, J1p ) || !EC_POINT_copy( J2.p, J2p ) ||
       !EC_POINT_copy( H.p, GP.H ) ) { err = "bad generator"; return false; }
   const EC_POINT* G = EC_GROUP_get0_generator( secp_group() );

   std::vector<EC_POINT*> Q( n, nullptr );
   std::vector<EC_POINT*> Dv( n, nullptr );
   for( size_t i = 0; i < n; ++i )
   {
      Q[i] = EC_POINT_new( secp_group() );
      if( !point_from_commit( Q[i], in.ring[i] ) ) { err = "bad ring point"; goto fail; }
      for( size_t j = 0; j < i; ++j )
         if( EC_POINT_cmp( secp_group(), Q[i], Q[j], ctx.c ) == 0 )
            { err = "duplicate ring member"; goto fail; }
   }

   // Pseudo-output P (kernel input): must be a valid non-identity point.
   // D_i = P - Q_i per member: commitment to zero iff P and Q_i share the
   // value. The M equation below forces the prover to know every real
   // member's value-matching blinding difference.
   {
      pt P( secp_group() );
      if( !point_from_commit( P.p, in.pseudo_output ) ) { err = "bad pseudo point"; goto fail; }
      for( size_t i = 0; i < n; ++i )
      {
         Dv[i] = EC_POINT_new( secp_group() );
         if( !EC_POINT_copy( Dv[i], P.p ) ) { err = "ec fail"; goto fail; }
         pt Qi( secp_group() );
         if( !EC_POINT_copy( Qi.p, Q[i] ) ) { err = "ec fail"; goto fail; }
         if( EC_POINT_invert( (EC_GROUP*)secp_group(), Qi.p, ctx.c ) != 1 )
            { err = "ec fail"; goto fail; }
         if( EC_POINT_add( (EC_GROUP*)secp_group(), Dv[i], Dv[i], Qi.p, ctx.c ) != 1 )
            { err = "ec fail"; goto fail; }
      }
   }

   // parse c0, (rb_i, rv_i, rd_i); strict canonical (S1 is_reduced discipline)
   {
      bn c;
      if( !scalar_parse_strict( c.b, (const unsigned char*)in.ring_sig.data(), 32 ) )
         { err = "c0 not canonical"; goto fail; }
      // NC-16: c0 == 0 is NOT accepted — the strict parse is
      // 0 < s < n (scalar_parse_strict / scalar_canonical_nz discipline),
      // same as every other scalar on this path.
      std::vector<bn*> rb( n ), rv( n ), rd( n );
      for( size_t i = 0; i < n; ++i ) { rb[i] = new bn(); rv[i] = new bn(); rd[i] = new bn(); }
      bool ok = true;
      for( size_t i = 0; i < n; ++i )
      {
         const unsigned char* p = (const unsigned char*)in.ring_sig.data() + 32 + 96*i;
         if( !scalar_parse_strict( rb[i]->b, p, 32 ) ||
             !scalar_parse_strict( rv[i]->b, p + 32, 32 ) ||
             !scalar_parse_strict( rd[i]->b, p + 64, 32 ) ) ok = false;
      }
      if( !ok ) { err = "responses not canonical"; for( auto x : rb ) delete x; for( auto x : rv ) delete x; for( auto x : rd ) delete x; goto fail; }

      pt L( secp_group() ), R( secp_group() ), M( secp_group() );
      bn ci;
      BN_copy( ci.b, c.b );
      bool accept = false;
      // Batched per-member multiexps (EC_POINTs_mul): L and R each collapse
      // from 4 scalar muls + 3 adds to a single 3-term multiexp, M is one
      // 2-term multiexp. Identical results, fewer EC multiplications
      // (timing only, no consensus change).
      const EC_POINT* Gptr = EC_GROUP_get0_generator( secp_group() );
      for( size_t i = 0; i < n; ++i )
      {
         // L = rb*G + rv*H + c*Q
         {
            const EC_POINT* pts[3] = { Gptr, H.p, Q[i] };
            const BIGNUM* scs[3] = { rb[i]->b, rv[i]->b, ci.b };
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
            if( EC_POINTs_mul( (EC_GROUP*)secp_group(), L.p, nullptr, 3,
                               pts, scs, ctx.c ) != 1 ) break;
#pragma GCC diagnostic pop
         }
         // R = rb*J1 + rv*J2 + c*I
         {
            const EC_POINT* pts[3] = { J1.p, J2.p, I.p };
            const BIGNUM* scs[3] = { rb[i]->b, rv[i]->b, ci.b };
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
            if( EC_POINTs_mul( (EC_GROUP*)secp_group(), R.p, nullptr, 3,
                               pts, scs, ctx.c ) != 1 ) break;
#pragma GCC diagnostic pop
         }
         // M = rd*G + c*D (pseudo-output binding leg)
         {
            const EC_POINT* pts[2] = { Gptr, Dv[i] };
            const BIGNUM* scs[2] = { rd[i]->b, ci.b };
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
            if( EC_POINTs_mul( (EC_GROUP*)secp_group(), M.p, nullptr, 2,
                               pts, scs, ctx.c ) != 1 ) break;
#pragma GCC diagnostic pop
         }
         auto Lb = point_to_bytes( L.p ), Rb = point_to_bytes( R.p ),
              Mb = point_to_bytes( M.p );
         if( Lb.empty() || Rb.empty() || Mb.empty() ) break;
         fc::sha256 nx = stealth_challenge( msg32, Lb, Rb, Mb );
         scalar_from_sha( ci.b, nx );
         if( i + 1 == n )
         {
            // wrap: c_n must equal c_0
            accept = ( BN_cmp( ci.b, c.b ) == 0 );
         }
      }
      for( auto x : rb ) delete x;
      for( auto x : rv ) delete x;
      for( auto x : rd ) delete x;
      for( auto q : Q ) EC_POINT_free( q );
      for( auto d : Dv ) EC_POINT_free( d );
      if( !accept ) { err = "ring did not close"; return false; }
      return true;
   }
fail:
   for( auto q : Q ) if( q ) EC_POINT_free( q );
   for( auto d : Dv ) if( d ) EC_POINT_free( d );
   return false;
}

// ---------------------------------------------------------------------------
// R15 representation proof (F-08 recovery; spec
// 2026-10-08-f08-representation-proof-recovery-design.md §3.2)
// ---------------------------------------------------------------------------

bool stealth_verify_recovery_proof( const fc::ecc::commitment_type& C,
                                    const fc::ecc::commitment_type& I1,
                                    const fc::ecc::commitment_type& I2,
                                    const std::vector<char>& proof,
                                    uint64_t asset_id, std::string& err )
{
   // ---- wire parse (exact 163B: A_C || A_1 || A_2 || s_b || s_v) ----
   if( proof.size() != 163 ) { err = "recovery proof size"; return false; }
   bn_ctx ctx;
   const EC_GROUP* g = secp_group();
   std::vector<unsigned char> aC( proof.begin(), proof.begin() + 33 ),
                              a1( proof.begin() + 33, proof.begin() + 66 ),
                              a2( proof.begin() + 66, proof.begin() + 99 );
   pt AC( g ), A1( g ), A2( g );
   if( !point_from_bytes( AC.p, aC ) ) { err = "bad recovery A_C"; return false; }
   if( !point_from_bytes( A1.p, a1 ) ) { err = "bad recovery A_1"; return false; }
   if( !point_from_bytes( A2.p, a2 ) ) { err = "bad recovery A_2"; return false; }
   bn sb, sv;
   if( !scalar_parse_strict( sb.b, (const unsigned char*)proof.data() + 99, 32 ) )
      { err = "recovery s_b not canonical"; return false; }
   if( !scalar_parse_strict( sv.b, (const unsigned char*)proof.data() + 131, 32 ) )
      { err = "recovery s_v not canonical"; return false; }

   // ---- statement points (rejects bad/off-curve/identity) ----
   pt Cp( g ), I1p( g ), I2p( g );
   if( !point_from_commit( Cp.p, C ) ) { err = "bad recovery C"; return false; }
   if( !point_from_commit( I1p.p, I1 ) ) { err = "bad recovery I1"; return false; }
   if( !point_from_commit( I2p.p, I2 ) ) { err = "bad recovery I2"; return false; }

   // ---- generators (same derivation as the ring path) ----
   pt Hp( g ), J1_1( g ), J2_1( g ), J1_2( g ), J2_2( g );
   auto Hb = stealth_H_point();
   auto J1_1b = stealth_J1_point( GRAPHENE_STEALTH_PROOF_V1 );
   auto J2_1b = stealth_J2_point( GRAPHENE_STEALTH_PROOF_V1 );
   auto J1_2b = stealth_J1_point( GRAPHENE_STEALTH_PROOF_V2 );
   auto J2_2b = stealth_J2_point( GRAPHENE_STEALTH_PROOF_V2 );
   if( !point_from_bytes( Hp.p, Hb ) ||
       !point_from_bytes( J1_1.p, J1_1b ) || !point_from_bytes( J2_1.p, J2_1b ) ||
       !point_from_bytes( J1_2.p, J1_2b ) || !point_from_bytes( J2_2.p, J2_2b ) )
      { err = "generators unavailable"; return false; }
   const EC_POINT* G = EC_GROUP_get0_generator( g );

   // ---- Fiat-Shamir challenge: byte order matches T_prove_recovery exactly:
   // "BTS-STEALTH-RECOVERY-v1" || C || I1 || I2 || A_C || A_1 || A_2
   //   || asset_id_le64 || C (trailing C binds the statement's commitment) ----
   std::string pre = "BTS-STEALTH-RECOVERY-v1";
   pre.append( (const char*)C.data(), 33 );
   pre.append( (const char*)I1.data(), 33 );
   pre.append( (const char*)I2.data(), 33 );
   pre.append( (const char*)aC.data(), 33 );
   pre.append( (const char*)a1.data(), 33 );
   pre.append( (const char*)a2.data(), 33 );
   for( int i = 0; i < 8; ++i ) pre.push_back( (char)( asset_id >> (8*i) ) );
   pre.append( (const char*)C.data(), 33 );
   fc::sha256 h = sha256_of( pre );
   bn c;
   scalar_from_sha( c.b, h );
   // R15C-04 defense-in-depth: c == 0 collapses every leg to
   // s_b*P + s_v*Q == A, dropping the (I1, I2) image binding entirely.
   // Unreachable by grinding (2^-256), and honest proofs never hit it,
   // so refuse fail-closed.
   if( BN_is_zero( c.b ) ) { err = "recovery challenge-zero"; return false; }

   // One leg: s_b*P + s_v*Q == A + c*S, via two batched EC_POINTs_mul
   // multiexps + EC_POINT_cmp (same pattern as stealth_verify_ring).
   auto check_leg = [&]( const EC_POINT* P, const EC_POINT* Q,
                         const EC_POINT* A, const EC_POINT* S ) -> bool {
      pt LHS( g ), RHS( g );
      {
         const EC_POINT* pts[2] = { P, Q };
         const BIGNUM* scs[2] = { sb.b, sv.b };
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
         if( EC_POINTs_mul( (EC_GROUP*)g, LHS.p, nullptr, 2,
                            pts, scs, ctx.c ) != 1 )
            return false;
#pragma GCC diagnostic pop
      }
      {
         const EC_POINT* pts[2] = { A, S };
         const BIGNUM* scs[2] = { BN_value_one(), c.b };
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
         if( EC_POINTs_mul( (EC_GROUP*)g, RHS.p, nullptr, 2,
                            pts, scs, ctx.c ) != 1 )
            return false;
#pragma GCC diagnostic pop
      }
      return EC_POINT_cmp( g, LHS.p, RHS.p, ctx.c ) == 0;
   };

   if( !check_leg( G, Hp.p, AC.p, Cp.p ) )
      { err = "recovery equation C mismatch"; return false; }
   if( !check_leg( J1_1.p, J2_1.p, A1.p, I1p.p ) )
      { err = "recovery equation I1 mismatch"; return false; }
   if( !check_leg( J1_2.p, J2_2.p, A2.p, I2p.p ) )
      { err = "recovery equation I2 mismatch"; return false; }
   return true;
}

// ---------------------------------------------------------------------------
// Conservation kernel
// ---------------------------------------------------------------------------

bool stealth_verify_excess( const std::vector<fc::ecc::commitment_type>& ins,
                            const std::vector<fc::ecc::commitment_type>& outs,
                            int64_t fee,
                            const fc::sha256& excess,
                            std::string& err )
{
   if( fee < 0 ) { err = "negative fee"; return false; }
   if( ins.empty() || ins.size() > 8 || outs.empty() || outs.size() > 8 )
      { err = "io count out of bounds"; return false; }
   bn_ctx ctx;
   auto Hb = stealth_H_point();
   pt H( secp_group() ), acc( secp_group() ), T( secp_group() );
   if( !point_from_bytes( H.p, Hb ) ) { err = "bad H"; return false; }
   const EC_POINT* G = EC_GROUP_get0_generator( secp_group() );
   bn e, f;
   scalar_from_sha( e.b, excess );
   BN_set_word( f.b, (BN_ULONG)fee );
   // acc = excess*G + fee*H + sum(outs) - sum(ins)
   if( EC_POINT_mul( (EC_GROUP*)secp_group(), acc.p, e.b, nullptr, nullptr, ctx.c ) != 1 )
      { err = "ec fail"; return false; }
   if( EC_POINT_mul( (EC_GROUP*)secp_group(), T.p, nullptr, H.p, f.b, ctx.c ) != 1 )
      { err = "ec fail"; return false; }
   if( EC_POINT_add( (EC_GROUP*)secp_group(), acc.p, acc.p, T.p, ctx.c ) != 1 )
      { err = "ec fail"; return false; }
   for( const auto& c : outs )
   {
      pt P( secp_group() );
      if( !point_from_commit( P.p, c ) ) { err = "bad out point"; return false; }
      if( EC_POINT_add( (EC_GROUP*)secp_group(), acc.p, acc.p, P.p, ctx.c ) != 1 )
         { err = "ec fail"; return false; }
   }
   for( const auto& c : ins )
   {
      pt P( secp_group() );
      if( !point_from_commit( P.p, c ) ) { err = "bad in point"; return false; }
      if( EC_POINT_invert( (EC_GROUP*)secp_group(), P.p, ctx.c ) != 1 )
         { err = "ec fail"; return false; }
      if( EC_POINT_add( (EC_GROUP*)secp_group(), acc.p, acc.p, P.p, ctx.c ) != 1 )
         { err = "ec fail"; return false; }
   }
   if( EC_POINT_is_at_infinity( secp_group(), acc.p ) != 1 )
      { err = "conservation mismatch"; return false; }
   return true;
}

// ---------------------------------------------------------------------------
// G2 Schnorr value-pin (design §3 link 1; proof Lemma 1)
// ---------------------------------------------------------------------------

bool stealth_verify_value_pin( const fc::ecc::commitment_type& P,
                               int64_t amount_to_sell, uint64_t pool_id,
                               const std::vector<char>& T_bytes,
                               const std::string& s_bytes, std::string& err )
{
   if( amount_to_sell <= 0 ) { err = "non-positive amount"; return false; }
   if( T_bytes.size() != 33 ) { err = "pin T size"; return false; }
   if( s_bytes.size() != 32 ) { err = "pin s size"; return false; }
   bn_ctx ctx;
   const EC_GROUP* g = secp_group();
   // Strict canonical scalar (stealth_verify_ring :571-575 discipline).
   bn s;
   if( !scalar_parse_strict( s.b, (const unsigned char*)s_bytes.data(), 32 ) )
      { err = "pin s not canonical"; return false; }
   // Statement + nonce points (reject bad/off-curve/identity).
   pt Pp( g ), Tp( g );
   if( !point_from_commit( Pp.p, P ) ) { err = "bad pin P"; return false; }
   std::vector<unsigned char> Tv( T_bytes.begin(), T_bytes.end() );
   if( !point_from_bytes( Tp.p, Tv ) ) { err = "bad pin T"; return false; }
   // Y = P - amount*H (amount > 0, so BN_set_word is exact, no sign path).
   pt H( g ), AH( g ), Y( g );
   auto Hb = stealth_H_point();
   if( !point_from_bytes( H.p, Hb ) ) { err = "bad H"; return false; }
   bn a;
   BN_set_word( a.b, (BN_ULONG)amount_to_sell );
   if( EC_POINT_mul( (EC_GROUP*)g, AH.p, nullptr, H.p, a.b, ctx.c ) != 1 )
      { err = "ec fail"; return false; }
   if( EC_POINT_copy( Y.p, Pp.p ) != 1 ) { err = "ec fail"; return false; }
   if( EC_POINT_invert( (EC_GROUP*)g, AH.p, ctx.c ) != 1 )
      { err = "ec fail"; return false; }
   if( EC_POINT_add( (EC_GROUP*)g, Y.p, Y.p, AH.p, ctx.c ) != 1 )
      { err = "ec fail"; return false; }
   // e = H("G2VP" || P || amount LE64 || pool ULEB128 || T), mod n.
   std::string pre = "G2VP";
   pre.append( (const char*)P.data(), 33 );
   auto avec = fc::raw::pack( amount_to_sell ); // int64: fixed 8B LE
   pre.append( avec.data(), avec.size() );
   pre.append( pool_varint( pool_id ) );
   pre.append( T_bytes.data(), T_bytes.size() );
   fc::sha256 h = sha256_of( pre );
   bn e;
   scalar_from_sha( e.b, h );
   // R15C-04 discipline: e == 0 collapses the equation to s*G == T,
   // dropping the (P, amount, pool) binding entirely. Unreachable by
   // grinding (2^-256), and honest provers never hit it, so refuse
   // fail-closed.
   if( BN_is_zero( e.b ) ) { err = "pin challenge-zero"; return false; }
   // s*G == T + e*Y: one scalar mul + one 2-term multiexp + compare
   // (same pattern as stealth_verify_ring / recovery check_leg).
   pt LHS( g ), RHS( g );
   if( EC_POINT_mul( (EC_GROUP*)g, LHS.p, s.b, nullptr, nullptr, ctx.c ) != 1 )
      { err = "ec fail"; return false; }
   {
      const EC_POINT* pts[2] = { Tp.p, Y.p };
      const BIGNUM* scs[2] = { BN_value_one(), e.b };
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
      if( EC_POINTs_mul( (EC_GROUP*)g, RHS.p, nullptr, 2,
                         pts, scs, ctx.c ) != 1 )
#pragma GCC diagnostic pop
         { err = "ec fail"; return false; }
   }
   if( EC_POINT_cmp( g, LHS.p, RHS.p, ctx.c ) != 0 )
      { err = "pin equation mismatch"; return false; }
   return true;
}

// ---------------------------------------------------------------------------
// V1 range proofs (fc Borromean backend; legacy proofs verify forever)
// ---------------------------------------------------------------------------

bool stealth_verify_range_v1( const fc::ecc::commitment_type& c,
                              const std::vector<char>& proof,
                              uint64_t& min_value, uint64_t& max_value )
{
   if( proof.empty() || proof.size() > 4096 ) return false;
   fc::ecc::range_proof_type p( proof.begin(), proof.end() );
   return fc::ecc::verify_range( min_value, max_value, c, p );
}

// ---------------------------------------------------------------------------
// V2 Bulletproofs+ (2020-735 transcription, prime-order form)
// ---------------------------------------------------------------------------

size_t stealth_bp_proof_size( uint8_t m )
{
   if( m != 1 && m != 2 ) return 0;
   size_t logM = ( m == 1 ) ? 0 : 1;
   size_t rounds = 6 + logM;
   return 1 + 33*3 + 32*3 + rounds * 66;
}

namespace {

/// BIGNUM vector helpers (all mod n)
struct bvec {
   std::vector<BIGNUM*> v;
   explicit bvec( size_t n = 0 ) { v.reserve( n ); for( size_t i = 0; i < n; ++i ) v.push_back( BN_new() ); }
   ~bvec() { for( auto x : v ) BN_free( x ); }
   bvec( const bvec& ) = delete;
   bvec& operator=( const bvec& ) = delete;
   size_t size() const { return v.size(); }
   BIGNUM* operator[]( size_t i ) { return v[i]; }
};

void mod_add( BIGNUM* r, const BIGNUM* a, const BIGNUM* b )
{ bn_ctx c; BN_mod_add( r, a, b, secp_order(), c.c ); }
void mod_sub( BIGNUM* r, const BIGNUM* a, const BIGNUM* b )
{ bn_ctx c; BN_mod_sub( r, a, b, secp_order(), c.c ); }
void mod_mul( BIGNUM* r, const BIGNUM* a, const BIGNUM* b )
{ bn_ctx c; BN_mod_mul( r, a, b, secp_order(), c.c ); }
bool mod_inv( BIGNUM* r, const BIGNUM* a )
{
   bn_ctx c;
   return BN_mod_inverse( r, a, secp_order(), c.c ) != nullptr;
}

} // anonymous namespace

bool stealth_verify_bp_plus( uint8_t m,
                             const std::vector<char>& proof,
                             const std::vector<fc::ecc::commitment_type>& commits,
                             std::string& err )
{
   // ---- wire parse (exact sizes; no padding ambiguity) ----
   // AUDIT: exact-size parse with the m tag checked first; any accepted
   // padding or tag/size skew between relay and verifier forks the network.
   if( m != 1 && m != 2 ) { err = "m out of range"; return false; }
   // R9A (F-02/F-06): only m=1 is wired — the m=2 branch below indexes
   // GP.BPG/BPH over [0,MN=128) but the caches hold exactly 64 entries,
   // and no prover or consensus caller ever exercised it. Reject here,
   // before any m-sized indexing, so the dead branch is unreachable.
   if( m != 1 ) { err = "only m=1 is wired"; return false; }
   if( commits.size() != m ) { err = "commit count != m"; return false; }
   if( proof.size() != stealth_bp_proof_size( m ) ) { err = "blob size"; return false; }
   if( (unsigned char)proof[0] != m ) { err = "m tag mismatch"; return false; }
   size_t logM = ( m == 1 ) ? 0 : 1;
   const size_t N = STEALTH_BP_N; // 64
   const size_t M = (size_t)m;
   const size_t MN = M * N;
   const size_t rounds = 6 + logM;

   bn_ctx ctx;
   const EC_GROUP* g = secp_group();

   // points: A, A1, B, L[rounds], R[rounds], V[m]
   std::vector<EC_POINT*> L( rounds, nullptr ), R( rounds, nullptr );
   EC_POINT *A = nullptr, *A1 = nullptr, *B = nullptr;
   std::vector<EC_POINT*> V( m, nullptr );
   auto fail_pts = [&]() {
      for( auto p : L ) if( p ) EC_POINT_free( p );
      for( auto p : R ) if( p ) EC_POINT_free( p );
      if( A ) EC_POINT_free( A );
      if( A1 ) EC_POINT_free( A1 );
      if( B ) EC_POINT_free( B );
      for( auto p : V ) if( p ) EC_POINT_free( p );
   };
   size_t off = 1;
   auto load_point = [&]( EC_POINT*& out ) -> bool {
      out = EC_POINT_new( g );
      std::vector<unsigned char> b( proof.begin() + off, proof.begin() + off + 33 );
      off += 33;
      return point_from_bytes( out, b ); // rejects identity + off-curve
   };
   if( !load_point( A ) ) { err = "bad A"; fail_pts(); return false; }
   if( !load_point( A1 ) ) { err = "bad A1"; fail_pts(); return false; }
   if( !load_point( B ) ) { err = "bad B"; fail_pts(); return false; }
   bn r1, s1, d1;
   auto load_scalar = [&]( bn& out ) -> bool {
      // Strict canonical AND nonzero (S1 is_reduced discipline, tightened:
      // honest provers mask with fresh randomness so zero never occurs).
      if( !scalar_parse_strict( out.b, (const unsigned char*)proof.data() + off, 32 ) ) return false;
      off += 32;
      return scalar_canonical_nz( out.b );
   };
   if( !load_scalar( r1 ) ) { err = "bad r1"; fail_pts(); return false; }
   if( !load_scalar( s1 ) ) { err = "bad s1"; fail_pts(); return false; }
   if( !load_scalar( d1 ) ) { err = "bad d1"; fail_pts(); return false; }
   for( size_t j = 0; j < rounds; ++j )
   {
      if( !load_point( L[j] ) ) { err = "bad L"; fail_pts(); return false; }
      if( !load_point( R[j] ) ) { err = "bad R"; fail_pts(); return false; }
   }
   for( size_t j = 0; j < m; ++j )
   {
      V[j] = EC_POINT_new( g );
      if( !point_from_commit( V[j], commits[j] ) ) { err = "bad V"; fail_pts(); return false; }
   }

   // generator vectors (owned copies of the decoded-point cache; all
   // existing free sites below stay correct; timing only, never consensus)
   const gen_points& GP = gen_points_cache();
   std::vector<EC_POINT*> Gv( MN, nullptr ), Hv( MN, nullptr );
   for( size_t i = 0; i < MN; ++i )
   {
      Gv[i] = EC_POINT_new( g ); Hv[i] = EC_POINT_new( g );
      if( !GP.BPG[i] || !GP.BPH[i] ||
          !EC_POINT_copy( Gv[i], GP.BPG[i] ) ||
          !EC_POINT_copy( Hv[i], GP.BPH[i] ) )
         { err = "bad generators"; fail_pts(); for( auto p : Gv ) if(p) EC_POINT_free(p); for( auto p : Hv ) if(p) EC_POINT_free(p); return false; }
   }
   pt G0( g ), H0( g );
   if( !GP.G || !GP.H ||
       !EC_POINT_copy( G0.p, GP.G ) ||
       !EC_POINT_copy( H0.p, GP.H ) )
      { err = "bad base generators"; fail_pts(); for( auto p : Gv ) EC_POINT_free(p); for( auto p : Hv ) EC_POINT_free(p); return false; }

    // ---- transcript (order mirrors S1; labels are G1 sha256 domains) ----
    // R9C (mimo F-01, fledge F1/F2, space-bunny F-10): CHAINED transcript,
    // S1-style. state_0 is the z bytes (z binds y binds V||A, so the seed
    // binds the full statement); e_j = H("G1BPr" || state_{j-1} || L_j ||
    // R_j) with state_j = e_j; e = H("G1BPf" || state_last || A1 || B).
    // Stage labels are partitioned (G1BPy/G1BPz/G1BPr/G1BPf) so no label
    // does double duty: the pre-R9C round-vs-final "G1BPe" reuse (whose
    // only disambiguator was fixed stage ORDER) is gone by construction.
    // Consensus-visible protocol break (pre-activation, zero mainnet G1
    // traffic): pre-R9C flat-transcript proofs REJECT here. The in-tree
    // test prover (tests/tests/g1_stealth_tests.cpp T_bp_prove) implements
    // this transcript identically; wallets reimplement from this spec
    // (and stealth_proof.hpp), never from S1. y=H(V||A), z=H(y) unchanged.
    // m=1-only (R9A gate stays); no batch path (weights would have to be
    // transcript-derived, never RNG).
   size_t Loff = 1 + 99 + 96;
   {
      std::vector<std::vector<unsigned char>> items;
      for( size_t j = 0; j < m; ++j )
      {
         EC_POINT* p = V[j];
         (void)p;
         std::vector<unsigned char> vb( 33 );
         size_t l = EC_POINT_point2oct( g, V[j], POINT_CONVERSION_COMPRESSED, vb.data(), 33, nullptr );
         if( l != 33 ) { err = "point enc"; fail_pts(); for( auto q : Gv ) EC_POINT_free(q); for( auto q : Hv ) EC_POINT_free(q); return false; }
         items.push_back( vb );
      }
      items.push_back( std::vector<unsigned char>( proof.begin() + 1, proof.begin() + 34 ) );
      fc::sha256 y = stealth_bp_hash( "G1BPy", items );
      bn yb; scalar_from_sha( yb.b, y );
      if( BN_is_zero( yb.b ) ) { err = "y == 0"; fail_pts(); for( auto q : Gv ) EC_POINT_free(q); for( auto q : Hv ) EC_POINT_free(q); return false; }
      fc::sha256 z = stealth_bp_hash( "G1BPz", { sha_bytes( y ) } );
      bn zb; scalar_from_sha( zb.b, z );
      if( BN_is_zero( zb.b ) ) { err = "z == 0"; fail_pts(); for( auto q : Gv ) EC_POINT_free(q); for( auto q : Hv ) EC_POINT_free(q); return false; }

      // round challenges + final e (chained, R9C — see note above)
      std::vector<unsigned char> tstate = sha_bytes( z );
      bvec ch( rounds ), chi( rounds );
      for( size_t j = 0; j < rounds; ++j )
      {
         std::vector<unsigned char> lb( proof.begin() + Loff + j*66,
                                        proof.begin() + Loff + j*66 + 33 );
         std::vector<unsigned char> rb( proof.begin() + Loff + j*66 + 33,
                                        proof.begin() + Loff + j*66 + 66 );
         fc::sha256 ej = stealth_bp_hash( "G1BPr", { tstate, lb, rb } );
         scalar_from_sha( ch[j], ej );
         if( BN_is_zero( ch[j] ) ) { err = "challenge == 0"; fail_pts(); for( auto q : Gv ) EC_POINT_free(q); for( auto q : Hv ) EC_POINT_free(q); return false; }
         if( !mod_inv( chi[j], ch[j] ) ) { err = "challenge inv"; fail_pts(); for( auto q : Gv ) EC_POINT_free(q); for( auto q : Hv ) EC_POINT_free(q); return false; }
         tstate = sha_bytes( ej );
      }
      bn yinv; scalar_from_sha( yinv.b, y );
      if( !mod_inv( yinv.b, yinv.b ) ) { err = "y inv"; fail_pts(); for( auto q : Gv ) EC_POINT_free(q); for( auto q : Hv ) EC_POINT_free(q); return false; }
      std::vector<unsigned char> a1b( proof.begin() + 34, proof.begin() + 67 );
      std::vector<unsigned char> bb( proof.begin() + 67, proof.begin() + 100 );
      fc::sha256 e = stealth_bp_hash( "G1BPf", { tstate, a1b, bb } );
      bn eb; scalar_from_sha( eb.b, e );
      if( BN_is_zero( eb.b ) ) { err = "e == 0"; fail_pts(); for( auto q : Gv ) EC_POINT_free(q); for( auto q : Hv ) EC_POINT_free(q); return false; }

      // ---- scalar algebra (S1 §verify transcription, weight = 1) ----
      bn yMN, yMN1, e2, z2;
      BN_copy( yMN.b, yb.b );
      { size_t t = MN; while( t > 1 ) { mod_mul( yMN.b, yMN.b, yMN.b ); t /= 2; } }
      mod_mul( yMN1.b, yMN.b, yb.b );
      mod_mul( e2.b, eb.b, eb.b );
      mod_mul( z2.b, zb.b, zb.b );

      // d[i] = z^{2(j+1)} * 2^i ; sum_d = (2^64-1) * sum_{k=1..M} z^{2k}
      bvec d( MN );
      BN_copy( d[0], z2.b );
      bn two; BN_set_word( two.b, 2 );
      for( size_t i = 1; i < N; ++i ) mod_mul( d[i], d[i-1], two.b );
      for( size_t j = 1; j < M; ++j )
         for( size_t i = 0; i < N; ++i ) mod_mul( d[j*N+i], d[(j-1)*N+i], z2.b );
      bn pow2m1; BN_set_word( pow2m1.b, 2 );
      for( int k = 0; k < 6; ++k ) mod_mul( pow2m1.b, pow2m1.b, pow2m1.b ); // 2^64
      { bn one; BN_set_word( one.b, 1 ); mod_sub( pow2m1.b, pow2m1.b, one.b ); } // 2^64-1
      bn evensum; BN_zero( evensum.b );
      { bn zk; BN_copy( zk.b, z2.b ); for( size_t k = 0; k < M; ++k ) { mod_add( evensum.b, evensum.b, zk.b ); mod_mul( zk.b, zk.b, z2.b ); } }
      bn sum_d; mod_mul( sum_d.b, pow2m1.b, evensum.b );
      // S1 sum_of_scalar_powers(y, MN) = y^1 + ... + y^MN (note: starts at
      // y^1, ends at y^MN -- NOT y^0..y^{MN-1}; an earlier revision had the
      // off-by-one and no honest proof verified). AUDIT: cross-checked
      // against vendored bulletproofs_plus.cc:1007 + sum_of_scalar_powers.
      bn sum_y; BN_zero( sum_y.b );
      { bn yp; BN_copy( yp.b, yb.b ); for( size_t i = 0; i < MN; ++i ) { mod_add( sum_y.b, sum_y.b, yp.b ); mod_mul( yp.b, yp.b, yb.b ); } }

      // challenges_cache[i] = prod_j e_j^{s(j,i)} with s = +1 iff
      // bit_{rounds-1-j}(i) is set, else -1 (the TRUE IPA fold weights,
      // derived from the prover fold, NOT from the vendored loop: the
      // in-tree prover folds G'[i] = G_lo[i]*e^-1 + G_hi[i]*(y^-n'*e) and
      // H'[i] = H_lo[i]*e + H_hi[i]*e^-1 (tests g1_stealth_tests.cpp:632-642),
      // so round j halves the vector and selects bit_{R-1-j}, lo-branch
      // taking e_j^-1 and hi-branch e_j^+1).
      // AUDIT: the vendored S1 loop (bulletproofs_plus.cc:1028-1039) is NOT
      // the authority for these weights — its in-place overlapping writes
      // are undefined behavior in C++ (plus an OOB write at s=0) — and no
      // claim of agreement with observed S1 runtime values is made here.
      // G1 implements the fold-derived clean form directly. Any change here
      // breaks bp_plus soundness.
      // F-02: cache covers the Gi/Hi index space [0,MN) iff nc >= MN, i.e.
      // 2^(6+logM) >= 2^logM * N iff N <= 64. STEALTH_BP_N is exactly 64 and
      // rounds = 6+logM hardcodes log2(64) a second time — raising N above
      // 64 without touching rounds OOB-reads cache in consensus. With m==1
      // wired above, MN = nc = 64 exactly.
      size_t nc = (size_t)1 << rounds;
      bvec cache( nc );
      for( size_t i = 0; i < nc; ++i )
      {
         BN_set_word( cache[i], 1 );
         for( size_t j = 0; j < rounds; ++j )
         {
            if( ( i >> (rounds-1-j) ) & 1 ) mod_mul( cache[i], cache[i], ch[j] );
            else mod_mul( cache[i], cache[i], chi[j] );
         }
      }

      // ---- multiexp terms: LHS - RHS == 0 ----
      // V_j: -e^2 * z^{2(j+1)} * y^{MN+1}
      struct term { BIGNUM* s; EC_POINT* p; };
      std::vector<term> terms;
      terms.reserve( 2*MN + m + 3 + 2*rounds + 2 );
      std::vector<bn*> owned;
      auto new_scalar = [&]() { bn* x = new bn(); owned.push_back( x ); return x->b; };
      for( size_t j = 0; j < m; ++j )
      {
         // V_j coefficient: -e^2 * y^{MN+1} * z^{2(j+1)}
         BIGNUM* s = new_scalar();
         BN_copy( s, e2.b );
         mod_mul( s, s, yMN1.b );
         bn zk; BN_copy( zk.b, z2.b );
         for( size_t k = 0; k < j; ++k ) mod_mul( zk.b, zk.b, z2.b );
         mod_mul( s, s, zk.b );
         { bn_ctx cc; BN_mod_sub( s, secp_order(), s, secp_order(), cc.c ); } // negate
         terms.push_back( { s, V[j] } );
      }
      { // B: -1
         BIGNUM* s = new_scalar();
         bn_ctx cc; BN_mod_sub( s, secp_order(), BN_value_one(), secp_order(), cc.c );
         terms.push_back( { s, B } );
      }
      { // A1: -e
         BIGNUM* s = new_scalar();
         bn_ctx cc; BN_mod_sub( s, secp_order(), eb.b, secp_order(), cc.c );
         terms.push_back( { s, A1 } );
      }
      { // A: -e^2
         BIGNUM* s = new_scalar();
         bn_ctx cc; BN_mod_sub( s, secp_order(), e2.b, secp_order(), cc.c );
         terms.push_back( { s, A } );
      }
      // G0 (blinding base G_std): +d1
      terms.push_back( { d1.b, G0.p } );
      { // H0 (value base H_s2): r1*y*s1 + e^2*(y^{MN+1}*z*sum_d + (z^2-z)*sum_y)
         BIGNUM* s = new_scalar();
         bn t1, t2, t3;
         mod_mul( t1.b, r1.b, yb.b ); mod_mul( t1.b, t1.b, s1.b );
         mod_mul( t2.b, yMN1.b, zb.b ); mod_mul( t2.b, t2.b, sum_d.b );
         mod_sub( t3.b, z2.b, zb.b ); mod_mul( t3.b, t3.b, sum_y.b );
         mod_add( t2.b, t2.b, t3.b );
         mod_mul( t2.b, t2.b, e2.b );
         mod_add( s, t1.b, t2.b );
         terms.push_back( { s, H0.p } );
      }
      // Gi/Hi folded generator terms (weight = 1, single proof)
      bn er1; mod_mul( er1.b, eb.b, r1.b );
      bn es1; mod_mul( es1.b, eb.b, s1.b );
      bn e2z; mod_mul( e2z.b, e2.b, zb.b );
      bn ypow; BN_set_word( ypow.b, 1 ); // y^{-i}
      bn yMNpow; BN_copy( yMNpow.b, yMN.b ); // y^{MN-i}
      for( size_t i = 0; i < MN; ++i )
      {
         { // Gi: e*r1*y^{-i}*cache[i] + e^2*z (S1 form; an earlier
            // revision multiplied the z-term by the cache instead and no
            // honest proof verified -- see challenges_cache note above).
            BIGNUM* s = new_scalar();
            bn t1, t2;
            mod_mul( t1.b, er1.b, ypow.b ); mod_mul( t1.b, t1.b, cache[i] );
            BN_copy( t2.b, e2z.b );
            mod_add( s, t1.b, t2.b );
            terms.push_back( { s, Gv[i] } );
         }
         { // Hi: e*s1*cache[~i] - e^2*z - e^2*y^{MN-i}*d[i]
            BIGNUM* s = new_scalar();
            bn t1, t2, t3;
            size_t ci = ( ~i ) & ( MN - 1 );
            mod_mul( t1.b, es1.b, cache[ci] );
            mod_mul( t3.b, e2.b, yMNpow.b ); mod_mul( t3.b, t3.b, d[i] );
            mod_add( t2.b, e2z.b, t3.b );
            mod_sub( s, t1.b, t2.b );
            terms.push_back( { s, Hv[i] } );
         }
         mod_mul( ypow.b, ypow.b, yinv.b );
         mod_mul( yMNpow.b, yMNpow.b, yinv.b );
      }
      // L_j: -e^2*e_j^2 ; R_j: -e^2*e_j^{-2}
      for( size_t j = 0; j < rounds; ++j )
      {
         bn ej2, eji2;
         mod_mul( ej2.b, ch[j], ch[j] );
         mod_mul( eji2.b, chi[j], chi[j] );
         BIGNUM* s1t = new_scalar();
         mod_mul( s1t, e2.b, ej2.b );
         { bn_ctx cc; BN_mod_sub( s1t, secp_order(), s1t, secp_order(), cc.c ); }
         terms.push_back( { s1t, L[j] } );
         BIGNUM* s2t = new_scalar();
         mod_mul( s2t, e2.b, eji2.b );
         { bn_ctx cc; BN_mod_sub( s2t, secp_order(), s2t, secp_order(), cc.c ); }
         terms.push_back( { s2t, R[j] } );
      }

      // single multiexp via EC_POINTs_mul (deterministic; timing-only vartime)
      std::vector<const EC_POINT*> pts;
      std::vector<const BIGNUM*> scs;
      pts.reserve( terms.size() ); scs.reserve( terms.size() );
      for( const auto& t : terms ) { pts.push_back( t.p ); scs.push_back( t.s ); }
      pt acc( g );
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
      int ok = EC_POINTs_mul( (EC_GROUP*)g, acc.p, nullptr, pts.size(),
                              pts.data(), scs.data(), ctx.c );
#pragma GCC diagnostic pop
      bool pass = ( ok == 1 ) && ( EC_POINT_is_at_infinity( g, acc.p ) == 1 );
      for( auto x : owned ) delete x;
      for( auto p : Gv ) EC_POINT_free( p );
      for( auto p : Hv ) EC_POINT_free( p );
      fail_pts();
      if( !pass ) { err = "multiexp != identity"; return false; }
      return true;
   }
}

// ---------------------------------------------------------------------------
// Decoy policy
// ---------------------------------------------------------------------------

bool stealth_check_decoy_policy( const std::vector<uint32_t>& heights,
                                  const std::vector<fc::time_point_sec>& times,
                                  fc::time_point_sec now,
                                  uint32_t head_block,
                                  std::string& err,
                                  uint32_t pool_depth )
{
   const size_t n = heights.size();
   // Task 6 (R7 C-01): TARGET (16) is the consensus floor in ALL non-halted
   // states — deep or thin. The old deep floor-11 accepted rings an
   // attacker-majority window could mark; MIN-11 survives only as the
   // verifier bound (and a future governance-opened thin-pool emergency).
   // The thin regime (< 64) keeps its tighter age spread (25%, R-04).
   // Bounds stay exact integer math, no floats.
   const bool thin = ( pool_depth < GRAPHENE_STEALTH_THIN_POOL_DEPTH );
   const size_t min_n = GRAPHENE_STEALTH_RING_TARGET;
   if( n != times.size() || n < min_n ||
       n > GRAPHENE_STEALTH_RING_MAX )
      { err = thin ? "thin-pool ring below target size" : "deep-pool ring below target size"; return false; }
   for( size_t i = 0; i < n; ++i )
   {
      if( heights[i] == 0 || heights[i] > head_block )
         { err = "decoy height out of range"; return false; }
      if( times[i] > now )
         { err = "decoy from the future"; return false; }
      uint32_t age = (uint32_t)( now.sec_since_epoch() - times[i].sec_since_epoch() );
      if( age < GRAPHENE_STEALTH_DECOY_MIN_AGE_SEC )
         { err = "decoy under minimum age"; return false; }
   }
   // skew: bucket heights into 100-block windows; no window may hold more
   // than 40% of members (25% when thin, R-04). Bounded: n <= 32,
   // windows <= 32. Exact integer math: count/n <= p/100 <=> count*100 <=
   // n*p would overflow nothing here (count,n <= 32) but the legacy
   // factored forms are kept (40%: count*5 <= 2*n; 25%: count*4 <= n) so
   // the boundary (exactly 40%/25%) passes identically.
   for( size_t i = 0; i < n; ++i )
   {
      uint32_t w = heights[i] / GRAPHENE_STEALTH_DECOY_SKEW_WINDOW_BLOCKS;
      size_t count = 0;
      for( size_t j = 0; j < n; ++j )
         if( heights[j] / GRAPHENE_STEALTH_DECOY_SKEW_WINDOW_BLOCKS == w )
            ++count;
      if( thin )
      {
         // count/n <= 25/100  <=>  count*4 <= n
         if( count * 4 > n )
            { err = "thin-pool decoy age-skew violation"; return false; }
      }
      else if( count * 5 > 2 * n )
         { err = "decoy age-skew violation"; return false; }
   }
   return true;
}

} } // graphene::chain
