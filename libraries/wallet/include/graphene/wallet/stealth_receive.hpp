#pragma once
/*
 * RP2: wallet-layer receive-path derivation helpers.
 * Spec §4: docs/superpowers/specs/2026-10-12-g1-stealth-receive-path-design.md
 *
 * Pure fc crypto; header-only; consensus-free. AuthKey = base_pub.child(sha256(shared))
 * — the multiplicative fc child the Phase-I path already uses (wallet.cpp:1739/1930).
 * Send and receive MUST both call these helpers so the derivation cannot diverge.
 *
 * Hygiene (spec §4, binding): callers treat any returned auth_priv as
 * address-key-grade forever (sender holds the offset; leaked auth ⇒ address
 * spend key recovery). Compute-and-use; zeroize where fc allows; never log.
 */
#include <graphene/protocol/confidential.hpp>
#include <graphene/protocol/stealth.hpp>
#include <fc/crypto/sha256.hpp>
#include <fc/crypto/aes.hpp>
#include <fc/optional.hpp>

namespace graphene { namespace wallet {

using graphene::protocol::stealth_recognition;
using graphene::protocol::stealth_confirmation;
using memo_data = stealth_confirmation::memo_data;

struct stealth_match_result
{
   fc::ecc::private_key auth_priv; ///< valid iff has_auth (hot path only)
   bool                 has_auth = false; ///< false for watch-only matches
   memo_data            memo;      ///< decrypted; caller MUST verify_memo_commitment
};

/// Deterministic dual-key material from a brainkey (BSIP-0054 salvage).
/// Versioned path: sha256(sha256(brainkey || tag) || index_be32). Wallet-layer
/// only; changing the path later is a wallet release, not a fork.
struct stealth_address_keys
{
   fc::ecc::private_key view_priv;
   fc::ecc::private_key spend_priv;
   fc::ecc::public_key  view_pub;
   fc::ecc::public_key  spend_pub;
};

inline stealth_address_keys derive_stealth_address_keys( const std::string& brain_key, uint32_t index )
{
   auto path = [&]( const char* tag ) {
      std::string pre = brain_key + tag;
      unsigned char idx[4] = { char(index>>24), char(index>>16), char(index>>8), char(index) };
      fc::sha256::encoder enc;
      auto h = fc::sha256::hash( pre.data(), pre.size() );
      enc.write( h.data(), 32 );
      enc.write( (char*)idx, 4 );
      return fc::ecc::private_key::regenerate( enc.result() );
   };
   stealth_address_keys k;
   k.view_priv  = path( "|G1-STEALTH-v1|VIEW|" );
   k.spend_priv = path( "|G1-STEALTH-v1|SPEND|" );
   k.view_pub   = k.view_priv.get_public_key();
   k.spend_pub  = k.spend_priv.get_public_key();
   return k;
}

inline stealth_recognition build_recognition( const fc::ecc::private_key& otk,
                                              const fc::ecc::public_key& view_pub,
                                              const fc::ecc::public_key& spend_pub,
                                              const memo_data& memo )
{
   auto secret = otk.get_shared_secret( view_pub );
   auto child  = fc::sha256::hash( secret );
   stealth_recognition rec;
   rec.one_time_key = otk.get_public_key();
   rec.to           = spend_pub.child( child ); // AuthKey — NEVER the address key
   rec.encrypted_memo = fc::aes_encrypt( secret, fc::raw::pack( memo ) );
   return rec;
}

/// Match + decrypt. spend_priv overload derives auth_priv (hot); without it
/// (watch-only) auth_priv is left default and has_auth stays false.
inline fc::optional<stealth_match_result> try_recognition(
      const stealth_recognition& rec,
      const fc::ecc::private_key& view_priv,
      const fc::ecc::public_key& spend_pub,
      fc::optional<fc::ecc::private_key> spend_priv = fc::optional<fc::ecc::private_key>() )
{
   try {
      auto secret = view_priv.get_shared_secret( rec.one_time_key );
      auto child  = fc::sha256::hash( secret );
      auto auth_pub = spend_pub.child( child );
      if( graphene::protocol::public_key_type( auth_pub ) != rec.to )
         return {};
      stealth_match_result out;
      auto plain = fc::aes_decrypt( secret, rec.encrypted_memo );
      out.memo = fc::raw::unpack<memo_data>( plain );
      if( spend_priv.valid() )
      {
         out.auth_priv = spend_priv->child( child );
         out.has_auth  = true;
      }
      return out;
   } catch( const fc::exception& ) {
      return {}; // tampered/foreign ciphertext fails closed (spec §3)
   }
}

inline fc::optional<stealth_match_result> try_recognition_single_key(
      const stealth_recognition& rec, const fc::ecc::private_key& address_priv )
{
   return try_recognition( rec, address_priv, address_priv.get_public_key(), address_priv );
}

/// Mandatory before trusting any memo (spec §2 R6 / §3): re-derive the opening.
inline bool verify_memo_commitment( const memo_data& memo )
{
   try {
      auto c = fc::ecc::blind( memo.blinding_factor, memo.amount.amount.value );
      return fc::ecc::verify_sum( { c }, { memo.commitment }, 0 );
   } catch( const fc::exception& ) {
      return false;
   }
}

} } // graphene::wallet
