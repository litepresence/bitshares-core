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
#pragma once

#include <graphene/protocol/base.hpp>
#include <graphene/protocol/asset.hpp>

namespace graphene { namespace protocol {

   /// Challenger/dispute base floor proposal: $837.50 in USD cents (BSIP-1 section 7b).
   constexpr uint64_t GRAPHENE_H2_CHALLENGE_BOND_FLOOR_USD_CENTS = 83750;
   /**
    * Raw-vs-USD escrow basis (H2-03/H2-05/H2-06): 1,000,000 raw BTS units per
    * USD cent. Derivation (BSIP-1 section 6 memo): the H2a pilot basis
    * $0.001/BTS — 1000 BTS per USD at BTS precision 5 — so one USD cent is
    * 10 BTS = 10 x 100000 raw units. Enforced at all four lock sites
    * (challenge, dispute, vault lock, producer lock): raw >= usd_cents x
    * BASIS, compared in 128-bit. A fail-closed floor, not a live price: a
    * BTS-price move can only make compliant escrows larger in USD terms, never
    * let a 1-satoshi escrow claim a full USD face. A live bonded-read
    * conversion (h2_read_pair_price) may tighten this later, never loosen it.
    */
   constexpr uint64_t GRAPHENE_H2_USD_BASIS_RAW_PER_CENT = 1000000;
   /// Finder fee cap proposal: $83.75 in USD cents (BSIP-1 sections 2, 7b).
   constexpr uint64_t GRAPHENE_H2_FINDER_CAP_USD_CENTS = 8375;
   /// Dispute rounds hard cap proposal (inventory section 2.4).
   constexpr uint8_t GRAPHENE_H2_DISPUTE_MAX_ROUNDS = 3;
   /// Committee vote window proposal: 48h (BSIP-1 section 2).
   constexpr uint32_t GRAPHENE_H2_VOTE_WINDOW_SEC = 172800;
   /// Per-pair cooldown proposal: 24h (BSIP-1 section 2).
   constexpr uint32_t GRAPHENE_H2_DISPUTE_COOLDOWN_SEC = 86400;
   /// Max concurrent open challenges/disputes per pair proposal (BSIP-1 section 2).
   constexpr uint16_t GRAPHENE_H2_MAX_CONCURRENT_PER_PAIR = 3;
   /// Exoneration/sustain/fast-reject supermajority proposal: 2/3 (BSIP-1 section 2).
   constexpr uint32_t GRAPHENE_H2_SUPERMAJORITY_BPS = 6667;
   /// Published quorum proposal: half the deciding set must have voted (BSIP-1 section 2).
   constexpr uint32_t GRAPHENE_H2_QUORUM_BPS = 5000;
   /// Evidence memo bound proposal (inventory OQ-16): 1..1000 chars, transparent only.
   constexpr size_t GRAPHENE_H2_EVIDENCE_MAX_LENGTH = 1000;
   /**
    * Same-authority ban walk bounds (H2 plan Task H2b): the authority-graph check
    * walks at most 2 hops out from each side and visits at most 15 entries per
    * level, matching the vault authority member cap. Anything linked only deeper
    * than 2 hops is out of reach by construction, never by accident.
    */
   constexpr uint32_t GRAPHENE_H2_AUTHORITY_GRAPH_MAX_DEPTH = 2;
   constexpr uint32_t GRAPHENE_H2_AUTHORITY_GRAPH_MAX_WIDTH = 15;
   /// Forfeit split proposals (BSIP-1 section 2): 80% burn, 15% reward pool,
   /// remainder finder (capped at GRAPHENE_H2_FINDER_CAP_USD_CENTS).
   constexpr uint16_t GRAPHENE_H2_FORFEIT_BURN_BPS = 8000;
   constexpr uint16_t GRAPHENE_H2_FORFEIT_POOL_BPS = 1500;

    /// Challenge/dispute lifecycle states. Terminal states never transition.
    /// EXPIRED_FROZEN is inconclusive, never exoneration: the 48h window
    /// closed with no supermajority, which can be cartel-abstention
    /// (withholding votes past the deadline vetoes sustain at the 5000bps
    /// quorum gate). It therefore pins fail-closed (frozen stays, guilty
    /// history sticks) — but it is exit-only resolvable: vault_resolve
    /// accepts EXPIRED_FROZEN into the identical wind-down path as SUSTAINED
    /// (R5C fail-closed split). There is NO path back to operation except
    /// fresh re-registration (new vault object, new bonds).
    constexpr uint8_t GRAPHENE_H2_CHALLENGE_OPEN = 0;
   constexpr uint8_t GRAPHENE_H2_CHALLENGE_EXONERATED = 1;
   constexpr uint8_t GRAPHENE_H2_CHALLENGE_SUSTAINED = 2;
   constexpr uint8_t GRAPHENE_H2_CHALLENGE_FAST_REJECTED = 3;
   constexpr uint8_t GRAPHENE_H2_CHALLENGE_EXPIRED_FROZEN = 4;

   /// Committee vote decisions carried by challenge_vote_operation.
   constexpr uint8_t GRAPHENE_H2_DISPUTE_EXONERATE = 0;
   constexpr uint8_t GRAPHENE_H2_DISPUTE_SUSTAIN = 1;
   constexpr uint8_t GRAPHENE_H2_DISPUTE_FAST_REJECT = 2;

   /**
    * @brief Opens a theft/failure challenge against a vault, posting bond.
    * @ingroup operations
    *
    * Anyone may challenge; the committee resolves by on-chain vote inside the
    * 48h window. The bond escrows from the challenger's transparent core
    * balance only: blind money cannot enter escrow because no code path reads
    * confidential balances. Same-authority pairings (challenger linked into the
    * vault authority within the bounded walk) are banned in consensus.
    * Challenges never halt consumption: only coverage or the tripwire does that.
    */
   struct vault_challenge_operation : public base_operation
   {
      struct fee_params_t {
         uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION;
         uint32_t price_per_kbyte = GRAPHENE_BLOCKCHAIN_PRECISION;
      };

      asset           fee;
      account_id_type challenger;   ///< Posts the bond; must exist
      vault_id_type   vault;        ///< Target vault; must be live
      share_type      challenge_bond;         ///< Escrowed; raw BTS smallest units
      uint64_t        challenge_bond_usd_cents = 0; ///< USD-terms record; floor $837.50
      string          evidence_memo;///< Transparent evidence carrier, 1..1000 chars
      extensions_type extensions;   ///< Appended-last rule

      account_id_type fee_payer()const { return challenger; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Opens a round-1 dispute against a retained oracle aggregate.
    * @ingroup operations
    *
    * Disputes a recorded aggregate (never a live submission) named by its
    * history timestamp plus series index, and names the accused producer as
    * defender. Same bond floor, evidence bounds, transparency rule, and
    * same-authority ban as vault challenges, with the producer's account
    * authority graph on the defender side.
    */
   struct oracle_dispute_operation : public base_operation
   {
      struct fee_params_t {
         uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION;
         uint32_t price_per_kbyte = GRAPHENE_BLOCKCHAIN_PRECISION;
      };

      asset           fee;
      account_id_type challenger;   ///< Posts the round-1 bond; must exist
      oracle_id_type  oracle;       ///< Target oracle; must exist
      account_id_type defender;     ///< Accused producer; must be in the producer set
      time_point_sec  accused_time; ///< Must name a retained history entry
      uint16_t        accused_series = 0; ///< Series index inside that entry
      share_type      dispute_bond;         ///< Round-1 escrow; raw BTS smallest units
      uint64_t        dispute_bond_usd_cents = 0; ///< USD-terms record; floor $837.50
      string          evidence_memo;///< Transparent evidence carrier, 1..1000 chars
      extensions_type extensions;   ///< Appended-last rule

      account_id_type fee_payer()const { return challenger; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Escalates an open dispute one round, doubling the round bond.
    * @ingroup operations
    *
    * Either side may escalate (inventory OQ-29 reversible minimum): the
    * escalator posts round_bond = round-1 base x 2^(new round - 1), so round 2
    * costs twice the base and round 3 four times it. Rounds cap at 3: a round 4
    * would cost a vault bond and bankrupt honest defenders first. Each
    * escalation opens a fresh 48h vote window. The ladder climbs one rung at a
    * time: skipping rounds is refused.
    */
   struct oracle_dispute_escalate_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset                   fee;
      account_id_type         escalator;  ///< Must be the challenger or the defender
      oracle_dispute_id_type  dispute;    ///< Must be open
      share_type              round_bond;         ///< Exact doubled rung; escrowed
      uint64_t                round_bond_usd_cents = 0; ///< USD-terms record of the rung
      extensions_type         extensions; ///< Appended-last rule

      account_id_type fee_payer()const { return escalator; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Records one seated committee member's vote on an open challenge/dispute.
    * @ingroup operations
    *
    * Every vote is on-chain (inventory section 1.6). One vote per member per
    * target; duplicates are refused. The first decision to reach a 2/3
    * supermajority of the seated deciding set resolves the target immediately
    * in the vote's apply step: exonerate and fast-reject forfeit the
    * challenger's full posted total, sustain returns it. Votes after the window
    * are refused; silence fails closed through the maintenance sweep.
    */
   struct challenge_vote_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset           fee;
      account_id_type voter;      ///< Must be a seated committee member
      object_id_type  target;     ///< An open vault challenge or oracle dispute
      uint8_t         decision = 0; ///< 0 exonerate, 1 sustain, 2 fast-reject
      extensions_type extensions; ///< Appended-last rule

      account_id_type fee_payer()const { return voter; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

} } // graphene::protocol

FC_REFLECT( graphene::protocol::vault_challenge_operation::fee_params_t, (fee)(price_per_kbyte) )
FC_REFLECT( graphene::protocol::oracle_dispute_operation::fee_params_t, (fee)(price_per_kbyte) )
FC_REFLECT( graphene::protocol::oracle_dispute_escalate_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::challenge_vote_operation::fee_params_t, (fee) )

FC_REFLECT( graphene::protocol::vault_challenge_operation,
            (fee)(challenger)(vault)(challenge_bond)(challenge_bond_usd_cents)
            (evidence_memo)(extensions) )
FC_REFLECT( graphene::protocol::oracle_dispute_operation,
            (fee)(challenger)(oracle)(defender)(accused_time)(accused_series)
            (dispute_bond)(dispute_bond_usd_cents)(evidence_memo)(extensions) )
FC_REFLECT( graphene::protocol::oracle_dispute_escalate_operation,
            (fee)(escalator)(dispute)(round_bond)(round_bond_usd_cents)(extensions) )
FC_REFLECT( graphene::protocol::challenge_vote_operation,
            (fee)(voter)(target)(decision)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::vault_challenge_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_dispute_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_dispute_escalate_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::challenge_vote_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::vault_challenge_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_dispute_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_dispute_escalate_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::challenge_vote_operation )
