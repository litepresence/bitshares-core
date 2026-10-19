/*
 * Copyright (c) 2026 BitShares contributors.
 *
 * The MIT License
 * ... (same as other G1 files; see stealth_proof.cpp for the full text)
 */
#pragma once

#include <graphene/protocol/stealth.hpp>

#include <fc/crypto/sha256.hpp>
#include <fc/crypto/elliptic.hpp>

#include <string>
#include <vector>

namespace graphene { namespace chain {

/**
 * Consensus crypto core for G1 stealth (BSIP-2 §1 + §4).
 *
 * NEW code, not a copy: the CLSAG construction (Goodell et al. 2019-654 §3,
 * curve-generic) and the Bulletproofs+ protocol (2020-735 §3-§4) are
 * re-instantiated over secp256k1. Lineage references vendored under
 * libraries/chain/stealth/vendor/ (S1 monero, S2 mimblewimble/secp256k1-zkp;
 * exact revisions recorded in vendor/README.md). The pre-G1 specialist audit is the
 * acceptance gate for this file's soundness (BSIP-2 §4): every assumption a
 * reviewer must check is cited inline with "AUDIT:".
 *
 * Consensus law: no floats, no unordered_*, no wall-clock, no randomness,
 * bounded loops/allocations everywhere, deterministic across nodes
 * (OpenSSL EC ops + sha256 only). Verification only: this file contains no
 * signing, no key generation, no randomness source.
 */

// ---------------------------------------------------------------------------
// Generators (all secp256k1, compressed 33B)
// ---------------------------------------------------------------------------

/// Standard base point G (blinding base, paper's h / S1's rct::G role).
std::vector<unsigned char> stealth_G_point();

/**
 * Pedersen value base H (paper's g / S1's rct::H role).
 *
 * AUDIT: this is the S2/Elements H constant VERBATIM
 * (secp256k1_generator_const_h, src/modules/generator/main_impl.h; revision recorded in vendor/README.md):
 * reusing it is MANDATORY, not optional, because every legacy fc::blind
 * commitment in history was made under it and turnstile/excess checks must
 * verify those commitments. The quoted Sage NUMS one-liner in that file does
 * NOT reproduce (its G_bytes hex carries a typo'd Y), so H's authority is
 * deployment history (unchanged since Elements Alpha 2016) + on-curve +
 * the blind-equality test (commitments_match_fc_backend). There is no new
 * trusted setup: H is a fixed public constant, never sampled.
 */
std::vector<unsigned char> stealth_H_point();

/// Nullifier-domain bases per proof version (try-and-increment
/// hash-to-point; first success in <=256 tries; seeds in stealth.hpp).
/// AUDIT: J1/J2 MUST differ per version (domain separation of nullifiers
/// across the V1/V2 dual-verify window); pinned by golden tests.
std::vector<unsigned char> stealth_J1_point( uint8_t version );
std::vector<unsigned char> stealth_J2_point( uint8_t version );

/// BP+ vector generators Gi/Hi, i in [0, 64) (same derivation family, BP seed).
std::vector<unsigned char> stealth_BP_G( size_t i );
std::vector<unsigned char> stealth_BP_H( size_t i );
constexpr size_t STEALTH_BP_N = 64;
size_t stealth_BP_count();

// ---------------------------------------------------------------------------
// Fiat-Shamir transcript (sha256, domain-separated; order mirrors S1)
// ---------------------------------------------------------------------------

/// Ring challenge: c_{i+1} = H("G1R2" || m || L_i || R_i || M_i) mod n.
/// G1R2 is the only ring-challenge domain in the tree. It was originally
/// chosen to differ from the G1b-2 "G1R1" pre-kernel domain, but G1R1 no
/// longer exists anywhere under libraries/ — the pre-kernel path was replaced
/// by the bound (pseudo-output-carrying) kernel, so a pre-kernel signature
/// cannot be produced or verified here. The ring message is a different
/// domain entirely ("G1RM").
fc::sha256 stealth_challenge( const std::string& msg32,
                              const std::vector<unsigned char>& L33,
                              const std::vector<unsigned char>& R33,
                              const std::vector<unsigned char>& M33 );

/// BP+ transcript squeeze: sha256(domain || previous || items...) mod n.
/// The BP+ path (R9C) honors this chaining literally: state_0 is the z
/// bytes, e_j = stealth_bp_hash("G1BPr", {state_{j-1}, L_j, R_j}) with
/// state_j = e_j, e = stealth_bp_hash("G1BPf", {state_last, A1, B}).
fc::sha256 stealth_bp_hash( const std::string& domain,
                            const std::vector<std::vector<unsigned char>>& items );

// ---------------------------------------------------------------------------
// Ring signatures over Pedersen openings (linkable, CLSAG-lineage)
// ---------------------------------------------------------------------------

/**
 * Ring message: binds version, asset, image, ring, pseudo-output, outputs, fee.
 * Single-sourced: provers (wallets/tests) and the evaluator call this.
 * The pseudo-output rides the message so the spend authorization covers the
 * exact kernel input the excess equation consumes (defense in depth: the M
 * equation already binds P cryptographically).
 *
 * Preimage (F-03, R13-E): "G1RM" || version || LE64(n) || LE64(m) || asset ||
 * image33 || ring[33n] || pseudo[33] || outputs[33m] || fee.
 *
 * ENCODINGS — a third-party prover has no BP+ prover to copy (none exists under
 * libraries/), so it builds this preimage from this comment alone. Spell it out:
 *   version   1 byte
 *   n, m      fixed-width 64-bit little-endian (fc::raw::pack of uint64_t).
 *             NOT varints: fixed width is canonical by construction, so there
 *             is no alternate encoding of the same count to collide with.
 *   asset     fc::raw::pack(asset_id_type) = fc::varint encoding of the id.
 *             VARIABLE length (1 byte for id 0, 5 bytes for 0x1fffffff) — do
 *             not assume a fixed width here.
 *   image33   the 33 raw bytes, uncompressed-point encoding as carried
 *   ring[]    n x 33 raw bytes
 *   pseudo    33 raw bytes
 *   outputs[] m x 33 raw bytes
 *   fee       fc::raw::pack(share_type) = 8 bytes little-endian, FIXED width
 *
 * The counts MUST be hashed: without them the fixed-stride commitment run is
 * re-partitionable and (n,m)=(k+1,j) collides with (k,j+1) whenever
 * ring[k]==pseudo'. This is a message-hash change, so it is only legal
 * PRE-ACTIVATION.
 */
fc::sha256 stealth_ring_message( uint8_t version,
                                 const protocol::asset_id_type& asset,
                                 const std::vector<char>& image33,
                                 const std::vector<fc::ecc::commitment_type>& ring,
                                 const fc::ecc::commitment_type& pseudo,
                                 const std::vector<fc::ecc::commitment_type>& outputs,
                                 protocol::share_type fee );

/**
 * G2 pool-swap ring message: binds version, input asset, pool, claimed
 * input value, slippage floor, image, ring, pseudo-output, outputs, and the
 * composite fee F. Single-sourced: provers (wallets/tests) and the G2
 * evaluator call this. Design 2026-10-10-stealth-pool-swaps-design §8;
 * F-03 acceptance is the exhaustive re-partition search (0 collisions).
 *
 * Preimage: "G2RM" || version || LE64(n) || LE64(m) || asset_A || pool ||
 * amount || min || image33 || ring[33n] || pseudo[33] || outputs[33m] || F,
 * single sha256. "G2RM" domain — never "G1RM". G1's stealth_ring_message
 * bytes are untouched.
 *
 * ENCODINGS (third-party provers build from this table alone):
 *   version   1 byte
 *   n, m      fixed-width 64-bit little-endian (fc::raw::pack of uint64_t),
 *             canonical by construction (F-03 count binding, same as G1RM)
 *   asset_A   fc::raw::pack(asset_id_type) = fc varint, VARIABLE length
 *   pool      ULEB128 varint, canonical minimal length (same wire as
 *             fc unsigned_int, extended to uint64; see the G2VP comment)
 *   amount    fc::raw::pack(int64) = 8 bytes little-endian, FIXED width
 *   min       fc::raw::pack(int64) = 8 bytes little-endian, FIXED width
 *   image33   33 raw bytes as carried (sizes gated by the caller/verifier,
 *             never by this hash — mirrors G1RM)
 *   ring[]    n x 33 raw bytes
 *   pseudo    33 raw bytes
 *   outputs[] m x 33 raw bytes
 *   F         fc::raw::pack(int64) = 8 bytes little-endian, FIXED width
 *
 * Every variable-length field is length-prefixed (n/m counts) or
 * self-delimiting (varints); fixed-stride runs cannot be re-partitioned.
 */
fc::sha256 stealth_pool_message( uint8_t version,
                                 const protocol::asset_id_type& asset_a,
                                 uint64_t pool_id,
                                 int64_t amount_to_sell, int64_t min_to_receive,
                                 const std::vector<char>& key_image,
                                 const std::vector<fc::ecc::commitment_type>& ring,
                                 const fc::ecc::commitment_type& pseudo,
                                 const std::vector<fc::ecc::commitment_type>& outputs,
                                 int64_t F );

/**
 * Verify one ring, WITH pseudo-output value binding (G1b-3 kernel).
 * The pseudo-output P is read from in.pseudo_output: it must commit to the
 * same value as the real spent member under a fresh blind. Per member i
 * (0-indexed, wrap c_n == c_0), with D_i = P - Q_i:
 *   L_i = rb_i*G + rv_i*H + c_i*Q_i
 *   R_i = rb_i*J1 + rv_i*J2 + c_i*I
 *   M_i = rd_i*G + c_i*D_i
 *   c_{i+1} = stealth_challenge(m || L_i || R_i || M_i)
 * with (J1, J2) = version-domain bases. At the real member s, D_s is a
 * commitment to zero (values cancel) with known blinding (b' - b_s), so
 * the prover closes M_s exactly as it closes L_s/R_s; at every other
 * member the branch is simulated. Inflating P (value != real input value)
 * leaves a non-zero H-multiple in every D_i, whose G-discrete-log the
 * prover cannot know without log_G(H) — the Pedersen binding assumption.
 * Combined with the consensus excess equation over the pseudos (evaluator),
 * unbalanced ring spends cannot mint value.
 *  The pseudo-outputs themselves are NEVER range-proven, and must not be:
 *  each P_i's value bound is inherited transitively from the real spent
 *  member's creation-time range proof through this M leg (P_i.value ==
 *  real_input.value, which that earlier proof bounded). Any future path that
 *  synthesizes a pseudo-output outside this M leg is unsound — it would
 *  enter the conservation kernel with no value bound at all (F-03).
 *
 * AUDIT: this is an adaptation, NOT verbatim CLSAG: CLSAG signs with a
 * spend key whose pubkey is the ring member; here the member is a Pedersen
 * commitment and the witness is its OPENING (blind, value), so each member
 * carries THREE responses (rb, rv, rd). The challenge-ring structure,
 * key-image linkage (I = b*J1 + v*J2), and domain separation are preserved;
 * the per-member statement ("I know an opening (b,v) of Q_i AND of I under
 * (J1,J2) with the same (b,v), AND the G-dlog of (P - Q_i)") is the
 * standard OR-composed Sigma protocol (MLSAG-lineage pseudo-output
 * binding), made non-interactive by Fiat-Shamir. Soundness of the
 * adaptation is a named pre-G1 audit item (report §H carries it).
 * Returns false (never throws) on any malformed input; err describes why.
 */
bool stealth_verify_ring( uint8_t version,
                           const protocol::stealth_ring_input& in,
                           const std::string& msg32,
                           std::string& err );

/**
 * R15: verify Sigma representation proof binding (I1,I2) to C's opening.
 * Deterministic; no secrets; strict canonical parsing throughout.
 */
bool stealth_verify_recovery_proof( const fc::ecc::commitment_type& C,
   const fc::ecc::commitment_type& I1, const fc::ecc::commitment_type& I2,
   const std::vector<char>& proof, uint64_t asset_id, std::string& err );

/**
 * Conservation kernel (Mimblewimble-style):
 *   sum(C_in) - sum(C_out) - fee*H == excess*G
 * All sums bounded (inputs/outputs <= 8 per op, rings <= 32).
 * Callers: turnstile_reproof (explicit old/new commitments, revealed
 * blinds) and stealth_transfer (per-input pseudo-outputs as C_in, each
 * bound to its ring's real input value by the ring's M equation).
 */
bool stealth_verify_excess( const std::vector<fc::ecc::commitment_type>& ins,
                            const std::vector<fc::ecc::commitment_type>& outs,
                            int64_t fee,
                            const fc::sha256& excess,
                            std::string& err );

/**
 * G2 Schnorr value-pin verifier (design 2026-10-10-stealth-pool-swaps-design
 * §3 link 1; proof Lemma 1): proves the pseudo-output P opens to
 * amount_to_sell, i.e. knowledge of b_P with P - amount*H = b_P*G.
 * Verifies s*G == T + e*Y with Y = P - amount*H and
 * e = H(G2VP, P, amount, pool, T).
 *
 * G2VP preimage (third-party provers build from this table alone):
 *   "G2VP" || P(33) || amount(8, fixed LE) || pool(varint) || T(33),
 *   single sha256, scalar mod n (scalar_from_sha semantics).
 *   P, T      33 raw bytes each (compressed-point encoding as carried)
 *   amount    fc::raw::pack(int64) = 8 bytes little-endian, FIXED width.
 *             Only positive bit patterns occur (non-positive rejected
 *             before hashing).
 *   pool      ULEB128 varint, canonical minimal length: 7 bits per byte,
 *             little-endian groups, continuation bit 0x80, last byte plain.
 *             Same wire as fc unsigned_int, extended to the full uint64
 *             range. Minimal length by construction, so the encoding is
 *             canonical: distinct pool ids give distinct bytes.
 *
 * Rejects fail-closed (never throws): non-positive amount, wrong-size T/s,
 * non-canonical s (stealth_verify_ring strictness), bad/off-curve/identity
 * P or T, challenge-zero (R15C-04 discipline: e == 0 would drop the (P,
 * amount, pool) binding; unreachable by grinding, refused anyway).
 * Verification only: no signing, no randomness (the prover lives in tests;
 * wallets reimplement from this spec).
 */
bool stealth_verify_value_pin( const fc::ecc::commitment_type& P,
                               int64_t amount_to_sell, uint64_t pool_id,
                               const std::vector<char>& T_bytes /*33B*/,
                               const std::string& s_bytes /*32B*/,
                               std::string& err );

// ---------------------------------------------------------------------------
// Range proofs
// ---------------------------------------------------------------------------

/// V1 (Borromean, fc backend): thin wrapper so call sites are uniform.
/// Legacy proofs verify forever under this path.
/// Operative range is [0,2^50), NOT [0,2^64): the 4096-byte consensus cap
/// admits the in-tree wallet's 49-bit proofs (3941B, 155B of headroom) up to
/// 50-bit proofs (4005B, last admissible); wider mantissas fail closed at
/// the cap (ADDENDUM A6). Call sites pin min_value==0 fail-closed (no
/// max_value floor: narrow proofs are sound, see the call-site comments),
/// so the claimed range is checked, never ignored (F-05).
bool stealth_verify_range_v1( const fc::ecc::commitment_type& c,
                              const std::vector<char>& proof,
                              uint64_t& min_value, uint64_t& max_value );

/**
 * V2 Bulletproofs+ verifier (2020-735 §3-§4 transcription, single proof,
 * n=64, m wired to 1 only, prime-order form: no cofactor clearing exists on
 * secp256k1 so S1's x8/INV_EIGHT scaling is dropped as identity).
 *
 * R9A (F-02/F-06): the verifier rejects m != 1 ("only m=1 is wired") before
 * any m-sized indexing — the m=2 branch is dead code (no prover, no
 * consensus caller, generator caches hold 64 entries, not 128). m in {1,2}
 * stays valid on the WIRE (stealth_bp_proof_size keeps both exact sizes,
 * 592/658); only verification is weight-1 gated.
 *
 * Wire: m || A || A1 || B || r1 || s1 || d1 || (L_j || R_j per round),
 * rounds = 6 + log2(m). Points 33B compressed, scalars 32B BE canonical.
 *
  * AUDIT: (1) transcript labels differ from S1 (sha256 domains vs ed25519
  * hash-to-scalar of point encodings) — the stage ORDER matches S1
  * (V, A -> y -> z -> rounds -> A1, B) and, since R9C, so does the
  * CHAINING (mimo F-01, space-bunny F-10 closed in code: state_0 = z,
  * rounds under "G1BPr", final under its own label "G1BPf"; pre-R9C
  * flat-"G1BPe" proofs reject — protocol break, pre-activation). The
  * PROVER must use these exact labels and this chaining (in-tree test
  * prover does; wallets reimplement from this spec, not from S1);
  * (2) single-proof weight is fixed to 1 — batch verification
  * (future) MUST use transcript-derived weights, never RNG, or verifiers
  * diverge; (3) soundness of the whole transcription is the pre-G1 audit's
  * headline item.
  */
bool stealth_verify_bp_plus( uint8_t m,
                             const std::vector<char>& proof,
                             const std::vector<fc::ecc::commitment_type>& commits,
                             std::string& err );

/// Exact blob size for (m): rejects padded/ambiguous encodings.
size_t stealth_bp_proof_size( uint8_t m );

// ---------------------------------------------------------------------------
// Decoy policy (pure function of chain-recorded metadata)
// ---------------------------------------------------------------------------

/**
 * Returns false when the ring's decoy set violates BSIP-2 §1 rules:
 * - fewer than GRAPHENE_STEALTH_RING_TARGET members (Task 6, R7 C-01:
 *   the TARGET floor binds deep or thin; MIN-11 is a verifier bound and
 *   a future governance-opened emergency, never accepted here), or
 * - any member younger than GRAPHENE_STEALTH_DECOY_MIN_AGE_SEC, or
 * - any 100-block window contributes > 40% of members (deep pool) or
 *   > 25% of members (thin pool, R-04).
 * heights/times come from blinded_balance_object (chain state), never the
 * wire. Grandfathered (pre-fork, metadata absent) outputs are NOT eligible
 * as decoys at all — enforced by the caller refusing absent metadata before
 * calling here (availability yields to privacy, explicitly).
 * pool_depth is the caller's per-asset unspent count (stealth_pool_depth):
 * below GRAPHENE_STEALTH_THIN_POOL_DEPTH the skew ceiling tightens to
 * GRAPHENE_STEALTH_THIN_SKEW_MAX_PCT. No default: every caller passes its
 * asset's depth explicitly so thin-vs-deep is never assumed.
 */
bool stealth_check_decoy_policy( const std::vector<uint32_t>& heights,
                                 const std::vector<fc::time_point_sec>& times,
                                 fc::time_point_sec now,
                                 uint32_t head_block,
                                 std::string& err,
                                 uint32_t pool_depth );

} } // graphene::chain
