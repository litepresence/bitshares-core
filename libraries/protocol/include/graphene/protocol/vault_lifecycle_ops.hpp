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
#include <graphene/protocol/authority.hpp>
#include <graphene/protocol/vault_ops.hpp>

namespace graphene { namespace protocol {

   /// Maintenance trigger proposal: coverage below 150% halts mints (BSIP-1 section 7b).
   constexpr uint32_t GRAPHENE_H2_MAINTENANCE_TRIGGER_BPS = 15000;
   /// Top-up window proposal: 36h to restore coverage before auto wind-down (BSIP-1 section 7b).
   constexpr uint32_t GRAPHENE_H2_TOP_UP_WINDOW_SEC = 129600;
   /// Wind-down haircut proposal: seniors paid at last-good-minus-15% (BSIP-1 section 2).
   constexpr uint32_t GRAPHENE_H2_WINDDOWN_HAIRCUT_BPS = 1500;
   /// Junior dilution cap proposal: junior-paid may never exceed 2x senior-paid (rmax).
   constexpr uint32_t GRAPHENE_H2_WINDDOWN_RMAX_JUNIOR_X = 2;
   /// Sub-vault bound proposal: at most 64 bond locks per vault (inventory OQ-10).
   constexpr uint32_t GRAPHENE_H2_SUBVAULT_CAP = 64;
   /// Griefing amount proposal: $83.75 per direction in USD cents (BSIP-1 sections 2, 7b).
   constexpr uint64_t GRAPHENE_H2_GRIEFING_BOND_USD_CENTS = 8375;

   /// Vault maintenance states (stored on vault_object, appended-last).
   constexpr uint8_t GRAPHENE_H2_VAULT_HEALTHY = 0;
   constexpr uint8_t GRAPHENE_H2_VAULT_TOPUP = 1;
   constexpr uint8_t GRAPHENE_H2_VAULT_WINDDOWN = 2;

   /// Wind-down states (stored on winddown_vault_object).
   constexpr uint8_t GRAPHENE_H2_WINDDOWN_OPEN = 0;
   constexpr uint8_t GRAPHENE_H2_WINDDOWN_SETTLING = 1;
   constexpr uint8_t GRAPHENE_H2_WINDDOWN_COMPLETE = 2;

   /// Claim tranches: seniors settle first, juniors dilute behind them.
   constexpr uint8_t GRAPHENE_H2_WINDDOWN_SENIOR = 0;
   constexpr uint8_t GRAPHENE_H2_WINDDOWN_JUNIOR = 1;

    /**
     * @brief Rotates a vault's threshold set in place; liabilities migrate by staying put.
     * @ingroup operations
     *
     * The incoming set proves capital first (at least one bond must already be
     * locked against the vault). Rotation must carry the FULL weight of the
     * old threshold: the rotator plus the named co-signers must sum to at
     * least the old authority's weight_threshold, and every named account's
     * ACTIVE authority is required on the transaction (signature-verified by
     * consensus, not merely asserted). Rotation is refused while any
     * challenge against the vault is open. Outstanding liabilities carry over
     * unchanged; the old bonds release only through vault_bond_release once the
     * challenge window has passed at zero open liabilities.
     */
    struct vault_rotate_operation : public base_operation
    {
       struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

       asset           fee;
       account_id_type rotator;       ///< Pays the fee; must sit in the old authority
       vault_id_type   vault;         ///< Target vault; must exist
       authority       new_authority; ///< Replaces vault_authority in full
        optional<string> memo;         ///< Rotation rationale carrier; never authorizes mint
        /// Old-set co-signers (E-04: moved before extensions so the
        /// append-last rule holds; pre-activation wire change, unactivated tags
        /// shift freely). Each named account's active authority is
        /// signature-required; the evaluator sums rotator + co-signer weights
        /// against the old threshold.
        flat_set<account_id_type> co_signers;
        extensions_type extensions;    ///< Appended-last rule

       account_id_type fee_payer()const { return rotator; }
       void            validate()const;
       share_type      calculate_fee( const fee_params_t& k )const;
       void get_required_active_authorities( flat_set<account_id_type>& a )const
       {
          for( const account_id_type& co : co_signers )
             a.insert( co );
       }
    };

   /**
    * @brief Releases a vault bond once its unlock has passed at zero open liabilities.
    * @ingroup operations
    *
    * Lifts the encumbrance only: funds stay in the vesting balance under normal
    * vesting rules. Seized bonds never release. This is the old-set exit of the
    * rotate lifecycle and the healthy-vault exit path; distressed exits go
    * through wind-down claims, never here.
    */
   struct vault_bond_release_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset              fee;
      account_id_type    owner; ///< Must equal the bond owner
      vault_bond_id_type bond;  ///< Must be unseized, unlocked, and liability-free
      extensions_type    extensions; ///< Appended-last rule

      account_id_type fee_payer()const { return owner; }
      void            validate()const;
   };

    /**
     * @brief Executes a sustained OR expired-frozen vault challenge into a segregated wind-down.
     * @ingroup operations
     *
     * Committee 2/3 execution path: the resolver must be a seated committee
     * member. The challenge must be in a terminal guilty-or-inconclusive
     * state — SUSTAINED (the vote proved the supermajority) or
     * EXPIRED_FROZEN (the window closed with no supermajority, which can be
     * cartel-abstention, so it is never exoneration). Both execute into the
     * identical exit-only wind-down: the vault's bonds segregate into a
     * wind-down vault that only ever pays from that slice — never another
     * vault's bonds, never the issuance reserve — and the vault never
     * returns to operation except through fresh re-registration.
     */
   struct vault_resolve_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

       asset                    fee;
       account_id_type          resolver;  ///< Must be a seated committee member
       vault_challenge_id_type  challenge; ///< Must be sustained or expired-frozen, unexecuted
       extensions_type          extensions; ///< Appended-last rule

      account_id_type fee_payer()const { return resolver; }
      void            validate()const;
   };

   /**
    * @brief Freezes a vault door AND its oracle debt tap in one atomic apply.
    * @ingroup operations
    *
    * Only a seated committee member may freeze. Both flags flip in the same
    * apply step, so no block can ever observe the door closed with debt still
    * open (or the reverse): atomicity is structural, not conventional.
    */
   struct pair_freeze_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset           fee;
      account_id_type freezer; ///< Must be a seated committee member
      vault_id_type   vault;   ///< Door: frozen blocks mints
      oracle_id_type  oracle;  ///< Debt tap: frozen stops value promotion
      extensions_type extensions; ///< Appended-last rule

      account_id_type fee_payer()const { return freezer; }
      void            validate()const;
   };

   /**
    * @brief Claims a wind-down share from the failed vault's segregated bond only.
    * @ingroup operations
    *
    * One claim per (winddown, claimant): a second claim by the same account is
    * refused as a double-claim (inventory OQ-21 reversible minimum; partial
    * claims are a follow-on). Seniors settle first at
    * last-good-minus-haircut; juniors dilute behind them with junior-paid
    * capped at rmax times senior-paid. Payout math (declared, rounding DOWN
    * against claimants): payout = min(claim * (10000 - haircut) / 10000,
    * claim * segregated / total), all intermediates 128-bit, same-asset units
    * in H2c (the live price leg is H2d).
    */
   struct winddown_claim_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset                   fee;
      account_id_type         claimant;     ///< Pays the fee; receives the payout
      winddown_vault_id_type  winddown;     ///< Must be open (never complete)
      share_type              claim_amount; ///< Face amount claimed, > 0
      uint8_t                 tranche = 0;  ///< 0 senior, 1 junior
      extensions_type         extensions;   ///< Appended-last rule

      account_id_type fee_payer()const { return claimant; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

} } // graphene::protocol

FC_REFLECT( graphene::protocol::vault_rotate_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::vault_bond_release_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::vault_resolve_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::pair_freeze_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::winddown_claim_operation::fee_params_t, (fee) )

FC_REFLECT( graphene::protocol::vault_rotate_operation,
             (fee)(rotator)(vault)(new_authority)(memo)(co_signers)(extensions) )
FC_REFLECT( graphene::protocol::vault_bond_release_operation,
            (fee)(owner)(bond)(extensions) )
FC_REFLECT( graphene::protocol::vault_resolve_operation,
            (fee)(resolver)(challenge)(extensions) )
FC_REFLECT( graphene::protocol::pair_freeze_operation,
            (fee)(freezer)(vault)(oracle)(extensions) )
FC_REFLECT( graphene::protocol::winddown_claim_operation,
            (fee)(claimant)(winddown)(claim_amount)(tranche)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::vault_rotate_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::vault_bond_release_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::vault_resolve_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::pair_freeze_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::winddown_claim_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::vault_rotate_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::vault_bond_release_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::vault_resolve_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::pair_freeze_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::winddown_claim_operation )
