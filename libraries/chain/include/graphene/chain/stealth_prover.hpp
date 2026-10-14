/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License (see stealth_proof.cpp for the full text).
 */
#pragma once

#include <fc/crypto/elliptic.hpp>
#include <fc/crypto/sha256.hpp>

#include <openssl/crypto.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace graphene { namespace chain {

/**
 * Wallet-side G2 stealth-pool-swap provers (BSIP-2, G2 design
 * 2026-10-10-stealth-pool-swaps-design §9).
 *
 * PRODUCTION PROVING LIBRARY. No provers existed in libraries/ — only
 * consensus verifiers plus test-side provers — so this file is written from
 * scratch for wallets. Structure mirrors the test provers (same equations
 * the verifiers check) with two production disciplines the test provers
 * lack: fresh randomness (RAND_bytes, never deterministic labels) and
 * secret zeroization (BN_clear_free on every secret BIGNUM,
 * OPENSSL_cleanse on secret byte buffers).
 *
 * *** EVALUATORS MUST NEVER CALL THIS FILE. *** Consensus verification lives
 * in stealth_proof.{hpp,cpp} (deterministic, no randomness, no secrets).
 * Any evaluator including this header is a consensus bug: proving is
 * non-deterministic across nodes by construction (fresh randomness per
 * proof) and would fork the chain. The vendor-never-compiled guard in
 * libraries/chain/CMakeLists.txt does not cover this file (it is a real
 * link unit); the call-graph separation is by review, enforced by this
 * comment and by the absence of any include of this header from the
 * evaluator translation units (stealth_evaluator.cpp and kin).
 *
 * Constant-time discipline (local side-channel only — determinism across
 * nodes is NOT required here, only verifier acceptance): no
 * secret-dependent branches (all loops run fixed counts: ring size, 64 BP+
 * state, 6 fold rounds), fixed-width modular arithmetic throughout, no
 * early-outs on secret data. The OpenSSL EC backend is shared with the
 * verifiers; its wNAF timing variability is accepted wallet-side surface,
 * not consensus surface.
 *
 * RNG discipline (WPC-02): every RNG-using entry point consults the
 * entropy gate (stealth_prover_entropy_ready — RAND_status() == 1 after a
 * one-time RAND_poll attempt) before it draws anything, and each draw is
 * still individually fail-closed on RAND_bytes. Proving against an
 * unseeded generator is refused, never degraded.
 *
 * Zeroization discipline: every secret BIGNUM is released with
 * BN_clear_free (OpenSSL zeroes before free); secret byte buffers go
 * through stealth_cleanse_secret (OPENSSL_cleanse + compiler barrier,
 * WPC-03) and caller-held blinds through the secret_buffer RAII guard
 * (WPC-04). The test hook below asserts the cleanse path
 * executed on a per-prove secret buffer (post-cleanse copy must read all
 * zeros); full coverage of every temporary is by construction + review,
 * not by the hook alone — the hook proves the path runs, review proves it
 * covers.
 *
 * Integer law: amounts are int64_t/units (never floats); no unordered_*;
 * no wall-clock; no consensus state.
 */

/**
 * WPC-03 (REPAIR-159): cleanse secret storage AND compiler-fence it.
 *
 * OPENSSL_cleanse is an external call the compiler cannot delete outright,
 * but it can still reorder later reads/writes of the same bytes across the
 * call, or keep a dead copy of the secret alive past it. The seq-cst
 * atomic_signal_fence (the standard-conforming spelling of
 * `asm volatile("" ::: "memory")`) forbids both: every access to the
 * cleansed bytes after this point is ordered after the cleanse.
 *
 * Every secret-buffer cleanse in the prover and the pool builder MUST go
 * through this one function — it is the only place the barrier lives (the
 * secret_buffer guard below uses it too).
 */
inline void stealth_cleanse_secret( void* p, std::size_t n )
{
   OPENSSL_cleanse( p, n );
   std::atomic_signal_fence( std::memory_order_seq_cst );
}

/**
 * WPC-04 (REPAIR-143): RAII zeroization guard over caller-held secret
 * storage — the pool builder's bP/bOut blinding factors.
 *
 * Adopts the storage BY REFERENCE: construction only records the pointer;
 * destruction cleanses + fences it through stealth_cleanse_secret. Every
 * exit from the enclosing scope — normal return, FC_ASSERT, any thrown
 * exception — therefore zeroizes the blind. The destructor is the ONE
 * zeroize site, so there is no unwind path that can be forgotten.
 *
 * Non-copyable; zeroize() is idempotent (after the first cleanse the guard
 * releases its claim, so it can never touch storage it no longer owns).
 *
 * The reference shape is deliberate: an owning wrapper's storage dies with
 * the object, so a test cannot observe that the destructor zeroized it
 * without reading destroyed memory. Here the harness owns the fc::sha256,
 * the guard owns only the wipe, and post-scope bytes are readable, defined
 * and asserted zero (wpc04_secret_buffer_zeroizes_on_unwind).
 */
class secret_buffer
{
public:
   explicit secret_buffer( fc::sha256& storage ) : m_storage( &storage ) {}
   ~secret_buffer() { zeroize(); }

   secret_buffer( const secret_buffer& ) = delete;
   secret_buffer& operator=( const secret_buffer& ) = delete;

   /// Cleanse the adopted storage (idempotent: further calls no-op).
   void zeroize()
   {
      if( m_storage )
      {
         stealth_cleanse_secret( m_storage->data(), fc::sha256::data_size() );
         m_storage = nullptr;
      }
   }

private:
   fc::sha256* m_storage;
};

/**
 * Dual-version pool-ring proof (one opening authorized under both proof
 * versions over the same ring and pseudo-output; mirrors the evaluator's
 * main + alt-leg verification).
 */
struct stealth_pool_ring_proof
{
   /// Key image under `version` (33B compressed point).
   std::vector<char> key_image;
   /// Key image under `alt_version` (33B compressed point).
   std::vector<char> alt_key_image;
   /// Pseudo-output P = value*H + blind_P*G (shared by both legs).
   fc::ecc::commitment_type pseudo_output;
   /// Ring signature under `version`: c_0 || (rb, rv, rd)*n, 32+96*n bytes.
   std::vector<char> ring_sig;
   /// Ring signature under `alt_version` (same ring, same P, alt message).
   std::vector<char> alt_ring_sig;
};

/**
 * WPC-02 (REPAIR-134): prover entropy gate. True iff OpenSSL's CSPRNG
 * reports fully seeded (RAND_status() == 1); a one-time RAND_poll()
 * attempt runs at the first call and the status is then read per call.
 * Every RNG-using prover entry point (sample / ring / BP+ / pin) consults
 * this and refuses to prove when it is false: proving against an unseeded
 * generator would mint predictable blinds and signing nonces, i.e.
 * recoverable keys. The fail-closed RAND_bytes checks inside the provers
 * remain as the second line; this gate is the first (and reports the
 * failure instead of silently burning retries). stealth_compute_pool_excess
 * draws no randomness (pure scalar subtraction) and needs no gate.
 */
bool stealth_prover_entropy_ready();

/**
 * Test hook (WPC-02): install a RAND_status() stand-in for the entropy
 * gate and get the previous provider back (pass nullptr to restore the
 * real RAND_status). Production code never calls this — it exists so the
 * unit suite can drive the unseeded branch without interposing on OpenSSL
 * itself (an LD_PRELOAD/link-level shim is not practical inside
 * chain_test). Worst case a caller can only lie to its OWN process about
 * entropy that process already holds; the RAND_bytes fail-closed checks
 * are untouched by this hook.
 */
using stealth_rand_status_fn = int (*)();
stealth_rand_status_fn stealth_prover_test_set_rand_status( stealth_rand_status_fn fn );

/**
 * Sample a fresh blinding factor: 32 RAND_bytes reduced mod n, retried to
 * nonzero. Fail-closed: throws on RNG failure (a proof must never fall
 * back to a weak/zero blind) or when the entropy gate is closed.
 */
fc::sha256 stealth_sample_blind();

/**
 * Prove one pool-ring under two versions (production port of the test-side
 * ring prover: same L/R/M equations, same stealth_challenge transcript —
 * randomness from RAND_bytes instead of deterministic labels).
 *
 * @param version     main proof version (V1 or V2).
 * @param alt_version the other proof version.
 * @param ring        n member commitments, 16..32, distinct, on-curve.
 * @param real_index  position of the real spent member (< n).
 * @param blind_s     opening blind of the real member.
 * @param value_s     opening value of the real member.
 * @param blind_P     FRESH pseudo-output blind (caller samples per proof,
 *                    e.g. via stealth_sample_blind; caller retains it for
 *                    the excess kernel + value pin — it is wallet secret
 *                    state, not cleansed here).
 * @param msg_main32  32-byte G2RM digest for the main leg (binds version,
 *                    asset, pool, amount, min, image, ring, P, outputs, F).
 * @param msg_alt32   32-byte G2RM digest for the alt leg.
 * @param out         dual proof (images, shared P, both sigs).
 * @param err         failure reason (never a secret).
 * @return true on success; false fail-closed (bad point, RNG failure —
 *         caller must not retry with a tired blind).
 */
bool stealth_prove_pool_ring( uint8_t version, uint8_t alt_version,
   const std::vector<fc::ecc::commitment_type>& ring,
   size_t real_index,
   const fc::sha256& blind_s, uint64_t value_s,
   const fc::sha256& blind_P,
   const std::string& msg_main32, const std::string& msg_alt32,
   stealth_pool_ring_proof& out, std::string& err );

/**
 * Prove a V2 Bulletproofs+ range proof (m=1, n=64, 592-byte blob) for
 * C = value*H + blind*G (production fold of the test-side BP+ prover:
 * same wire, same G1BPy/G1BPz/G1BPr/G1BPf transcript — randomness from
 * RAND_bytes instead of deterministic labels). Retries with fresh
 * randomness on degenerate transcripts (bounded attempts; exhaustion
 * returns false, probability negligible).
 *
 * @return true with a 592-byte proof the consensus
 *         stealth_verify_bp_plus(1, …) accepts; false fail-closed.
 */
bool stealth_prove_bp_plus_m1( const fc::ecc::commitment_type& C,
   const fc::sha256& blind, uint64_t value,
   std::vector<char>& proof_out, std::string& err );

/**
 * Conservation-kernel scalar: excess = blind_P − blind_out mod n
 * (design §3 link 3 input; verified by stealth_verify_excess with the
 * composite fee F). Pure scalar arithmetic, no secrets retained.
 */
fc::sha256 stealth_compute_pool_excess( const fc::sha256& blind_P,
                                        const fc::sha256& blind_out );

/**
 * Prove the Schnorr value pin (design §3 link 1): knowledge of blind_P
 * with P − amount*H = blind_P*G, bound to (P, amount, pool) via the G2VP
 * transcript ("G2VP" || P || amount LE64 || pool ULEB128 || T — same bytes
 * the consensus verifier hashes; a divergent encoder fails closed at
 * verify time, never silently).
 *
 * k is fresh RAND_bytes per proof (never reused, never deterministic).
 *
 * @param T_out 33-byte compressed T = k*G; @param s_out 32-byte scalar
 *        s = k + e*blind_P (canonical nonzero, retried).
 * @return true iff (T, s) built; acceptance is the verifier's job.
 */
bool stealth_prove_value_pin( const fc::ecc::commitment_type& P,
   int64_t amount_to_sell, uint64_t pool_id,
   const fc::sha256& blind_P,
   std::vector<char>& T_out, std::string& s_out, std::string& err );

/**
 * Test hook: post-cleanse image of the most recent secret buffer cleansed
 * by any prover in this file (32 bytes; the copy is taken AFTER
 * OPENSSL_cleanse, so any nonzero byte proves cleansing did not run).
 * Always available (harmless: it can only ever return zeros in a correct
 * build); production callers ignore it.
 */
std::vector<unsigned char> stealth_prover_test_last_cleansed();

} } // graphene::chain
