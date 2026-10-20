#pragma once
/*
 * RP2: wallet-layer receive-path derivation helpers.
 * Spec §4: docs/superpowers/specs/2026-10-12-g1-stealth-receive-path-design.md
 *
 * Pure fc crypto; header-only; consensus-free. AuthKey = base_pub.child(sha256(shared))
 * — the multiplicative fc child the Phase-I path already uses (wallet.cpp:1739/1930).
 * Send and receive MUST both call these helpers so the derivation cannot diverge.
 *
 * The OPENING (the Pedersen blind factor) of a NEW output is derived from the
 * SPEND key, not from the view key, and the recognition memo ships no opening
 * at all (the zero marker): a view-key holder can read the amount and the
 * commitment but cannot open the output, so it cannot construct a ring spend
 * over it. Spec: docs/superpowers/specs/2026-10-19-viewkey-ring-auth-construction.md section 1
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
// NB: no `memo_data` alias here — graphene::wallet::memo_data already names
// the legacy blind memo (sign_memo/read_memo). Always spell the stealth memo
// as stealth_confirmation::memo_data in full.

struct stealth_match_result
{
   fc::ecc::private_key auth_priv; ///< valid iff has_auth (hot path only)
   bool                 has_auth = false; ///< false for watch-only matches
   stealth_confirmation::memo_data memo; ///< decrypted; caller MUST verify_memo_commitment
   /// The output's opening (the Pedersen blind factor).
   ///
   /// A legacy memo carries its own opening: it is known even to a
   /// watch-only holder (and is therefore still view-openable — the
   /// grandfathered hole). An OPENINGLESS memo (the zero marker) carries
   /// none: the opening is derived from the SPEND key and recomputed by its
   /// holder, so it is invalid exactly when the holder has no spend key —
   /// the output stays closed to a view-key holder.
   fc::optional<fc::sha256> opening;
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
      unsigned char idx[4] = { static_cast<unsigned char>(index>>24), static_cast<unsigned char>(index>>16),
                                 static_cast<unsigned char>(index>>8), static_cast<unsigned char>(index) };
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
                                              const stealth_confirmation::memo_data& memo )
{
   auto secret = otk.get_shared_secret( view_pub );
   auto child  = fc::sha256::hash( secret );
   stealth_recognition rec;
   rec.one_time_key = otk.get_public_key();
   rec.to           = spend_pub.child( child ); // AuthKey — NEVER the address key
   rec.encrypted_memo = fc::aes_encrypt( secret, fc::raw::pack( memo ) );
   return rec;
}

/// The opening (Pedersen blind factor) of a stealth output:
///   opening = H( H( ECDH( priv, pub ) ) )
///
/// ECDH is symmetric, so the sender (one-time private key, spend public key)
/// and the recipient (spend private key, one-time public key) compute the
/// SAME opening. A holder of the VIEW key computes a DIFFERENT one (the
/// bases differ), so it cannot open the output — the hole the spend-derived
/// derivation closes.
///
/// Spec: docs/superpowers/specs/2026-10-19-viewkey-ring-auth-construction.md section 1
inline fc::sha256 derive_opening( const fc::ecc::private_key& priv, const fc::ecc::public_key& pub )
{
   auto secret = priv.get_shared_secret( pub );
   auto child  = fc::sha256::hash( secret );
   return fc::sha256::hash( child );
}

/// The zero marker: a memo whose blinding factor is all-zero carries NO
/// opening. The opening of such an output is derived from the SPEND key and
/// recomputed by its holder; the memo ships the amount, the commitment and
/// the check only. Zero is not a reachable blind factor (an opening is the
/// output of a hash), so the marker cannot collide with a real opening.
///
/// Spec: docs/superpowers/specs/2026-10-19-viewkey-ring-auth-construction.md section 1
inline bool memo_is_openingless( const stealth_confirmation::memo_data& memo )
{
   return memo.blinding_factor == fc::sha256();
}

/// Select the opening of a recognized output (the marker dispatch):
///  - an openingless (zero-marker) memo: recompute it from the SPEND key; a
///    holder without the spend key gets NOTHING (the output stays closed).
///  - a legacy memo: the opening is the memo's own value (grandfathered).
///
/// Spec: docs/superpowers/specs/2026-10-19-viewkey-ring-auth-construction.md section 1
inline fc::optional<fc::sha256> select_opening(
        const stealth_confirmation::memo_data& memo,
        const fc::optional<fc::ecc::private_key>& spend_priv,
        const fc::ecc::public_key& one_time_key )
{
   if( !memo_is_openingless( memo ) )
      return memo.blinding_factor;
   if( !spend_priv.valid() )
      return fc::optional<fc::sha256>();
   return derive_opening( *spend_priv, one_time_key );
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
      out.memo = fc::raw::unpack<stealth_confirmation::memo_data>( plain );
      // The opening: a legacy memo carries it, an openingless one is
      // recomputed from the SPEND key (a watch-only holder gets nothing —
      // the output stays closed to it).
      out.opening = select_opening( out.memo, spend_priv, rec.one_time_key );
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

/// Mandatory before trusting any memo (spec §2 R6 / §3): re-derive the
/// opening and check it against the commitment.
///
/// For an OPENINGLESS memo the check runs against the RECOMPUTED opening
/// (the spend-derived one). A holder without the spend key cannot produce
/// that opening — the check IS the opening — so the watch-only path verifies
/// only what it can: the memo is well formed and its commitment is not the
/// identity. What ties such a memo to an output is the chain-side
/// commitment (the scan path compares the memo's commitment with the
/// commitment the chain shows for that output).
///
/// Spec: docs/superpowers/specs/2026-10-19-viewkey-ring-auth-construction.md section 1
inline bool verify_memo_commitment( const stealth_confirmation::memo_data& memo,
                                    const fc::optional<fc::sha256>& opening = fc::optional<fc::sha256>() )
{
   try {
      if( memo_is_openingless( memo ) )
      {
         if( !opening.valid() )
            return memo.commitment != fc::ecc::commitment_type();
         auto c = fc::ecc::blind( *opening, memo.amount.amount.value );
         return fc::ecc::verify_sum( { c }, { memo.commitment }, 0 );
      }
      auto c = fc::ecc::blind( memo.blinding_factor, memo.amount.amount.value );
      return fc::ecc::verify_sum( { c }, { memo.commitment }, 0 );
   } catch( const fc::exception& ) {
      return false;
   }
}

} } // graphene::wallet
