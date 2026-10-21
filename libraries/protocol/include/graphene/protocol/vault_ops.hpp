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
#include <graphene/protocol/oracle.hpp>

namespace graphene { namespace protocol {

   /// Vault min_bond proposal: $13,400 in USD cents (BSIP-1 section 7b).
   constexpr uint64_t GRAPHENE_H2_VAULT_MIN_BOND_USD_CENTS = 1340000;
   /// Oracle min_bond proposal: $10,050 in USD cents (BSIP-1 section 7b).
   constexpr uint64_t GRAPHENE_H2_ORACLE_MIN_BOND_USD_CENTS = 1005000;
   /// Unbond delay proposal: 7 days (inventory sections 1.3, 2.1).
   constexpr uint32_t GRAPHENE_H2_BOND_UNBOND_DELAY_SEC = 604800;
   /**
    * Publication advance (inventory OQ-23 was open with no proposal): each live
    * publication pushes a producer bond's unlock out by 24h. Reversible minimum,
    * chosen and logged in the H2a report.
    */
   constexpr uint32_t GRAPHENE_H2_BOND_ADVANCE_SEC = 86400;
   /// Vault authority size cap proposal (inventory OQ-04): 15 members.
   constexpr uint32_t GRAPHENE_H2_VAULT_MAX_AUTHORITY_MEMBERS = 15;
   /// Challenge-window upper-bound proposal (inventory OQ-06): 14 days.
   constexpr uint32_t GRAPHENE_H2_VAULT_MAX_CHALLENGE_WINDOW_SEC = 1209600;
   /// Vault memo bound proposal (inventory section 1.1): 1000 chars.
   constexpr size_t GRAPHENE_H2_VAULT_MAX_MEMO_LENGTH = 1000;
   /// Max outstanding foreign redeems a vault may carry (H3). The pending
   /// redeem vector is bounded by this, so it cannot grow without limit.
   constexpr size_t GRAPHENE_H3_MAX_PENDING_REDEEMS = 16;
   /// Max foreign deposit records a vault may carry (H3). The mint-side
   /// deposit set is bounded by this, so it cannot grow without limit.
   constexpr size_t GRAPHENE_H3_MAX_MINT_DEPOSITS = 1024;
   /// Foreign redeem SLA (H3): 72h, matching the Track A social-slash bond's
   /// redemption window.
   constexpr uint32_t GRAPHENE_H3_FOREIGN_REDEEM_SLA_SEC = 259200;

   /**
    * @brief Binds a threshold-authority vault set to a pair and commits its terms.
    * @ingroup operations
    *
    * Mint authority sits with the vault authority, never an issuer key. The raw
    * min_bond travels with its USD-terms record (min_bond_usd_cents) so a
    * BTS-price move cannot silently re-size the lock; both are committed here
    * and re-checked at every bond lock.
    */
   struct vault_register_operation : public base_operation
   {
      struct fee_params_t {
         uint64_t fee = 500 * GRAPHENE_BLOCKCHAIN_PRECISION;
         uint32_t price_per_kbyte = GRAPHENE_BLOCKCHAIN_PRECISION;
      };

      asset           fee;
       account_id_type registrar;        ///< Pays the fee; must be the pair asset's
                                         ///< issuer (LEG-R11-01 legacy attach gate);
                                         ///< need not equal the vault authority
      asset_id_type   pair;             ///< The vault-backed UIA this set secures
      authority       vault_authority;  ///< Threshold custody set
      share_type      min_bond;         ///< Raw lock floor, in bond_asset smallest units
      uint64_t        min_bond_usd_cents = 0; ///< USD-terms denomination record at lock
      asset_id_type   bond_asset;       ///< BTS at genesis (basket timing is a later task)
      uint32_t        secure_ratio_bps = 0;   ///< Must exceed 10000; genesis proposal 20000
      uint32_t        challenge_window_sec = 0;   ///< unbond-delay FLOOR only (PS-10)
      optional<string> memo;            ///< Lock-proof attestation carrier; never authorizes mint
      /// H3 foreign backing asset (appended-last): 0/empty = BitShares (H2 vault).
      uint8_t         backing_chain = 0;
      std::string     backing_asset;
      /// H3 committed exchange rate (appended-last): one foreign unit is worth
      /// backing_rate_num / backing_rate_den bond-asset raw units. Committed
      /// at registration and immutable for the life of the vault. A
      /// foreign-backed vault must carry a non-zero denominator.
      uint64_t        backing_rate_num = 0;
      uint64_t        backing_rate_den = 1;
      extensions_type extensions;       ///< Wire space only at H2 genesis (appended-last rule)
      account_id_type fee_payer()const { return registrar; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Locks a vault bond against an existing CDD vesting balance.
    * @ingroup operations
    *
    * Funds never move into the bond object: the bond encumbers the vesting
    * balance, whose pointer is immutable (no update operation exists). The lock
    * must equal the vault's registered min_bond exactly, raw and USD-terms.
    */
   struct vault_bond_lock_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset                   fee;
      account_id_type         owner;
      vault_id_type           vault;
      vesting_balance_id_type vesting_balance;
      share_type              bond_amount;
      uint64_t                bond_usd_cents = 0;
      extensions_type         extensions;

      account_id_type fee_payer()const { return owner; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Locks a producer bond against an existing CDD vesting balance.
    * @ingroup operations
    *
    * Flat min_bond (the $10,050 USD-terms proposal), 7-day unbond, advancing
    * unlock: each live publication pushes unlock_time out by
    * GRAPHENE_H2_BOND_ADVANCE_SEC. Weights stay owner-set, never earned.
    */
   struct oracle_bond_lock_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset                   fee;
      account_id_type         producer;
      oracle_id_type          oracle;
      vesting_balance_id_type vesting_balance;
      share_type              bond_amount;
      uint64_t                bond_usd_cents = 0;
      uint16_t                bootstrap_weight = 0;
      extensions_type         extensions;

      account_id_type fee_payer()const { return producer; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Releases a producer bond once its unlock has passed.
    * @ingroup operations
    *
    * Refused before unlock_time. Lifts the encumbrance only: funds stay in the
    * vesting balance under normal vesting rules.
    */
   struct oracle_bond_release_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset                 fee;
      account_id_type       producer;
      producer_bond_id_type bond;
      extensions_type       extensions;

      account_id_type fee_payer()const { return producer; }
      void            validate()const;
   };

} } // graphene::protocol

FC_REFLECT( graphene::protocol::vault_register_operation::fee_params_t, (fee)(price_per_kbyte) )
FC_REFLECT( graphene::protocol::vault_bond_lock_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::oracle_bond_lock_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::oracle_bond_release_operation::fee_params_t, (fee) )

FC_REFLECT( graphene::protocol::vault_register_operation,
            (fee)(registrar)(pair)(vault_authority)(min_bond)(min_bond_usd_cents)
            (bond_asset)(secure_ratio_bps)(challenge_window_sec)(memo)(backing_chain)(backing_asset)
            (backing_rate_num)(backing_rate_den)(extensions) )FC_REFLECT( graphene::protocol::vault_bond_lock_operation,
            (fee)(owner)(vault)(vesting_balance)(bond_amount)(bond_usd_cents)(extensions) )
FC_REFLECT( graphene::protocol::oracle_bond_lock_operation,
            (fee)(producer)(oracle)(vesting_balance)(bond_amount)(bond_usd_cents)
            (bootstrap_weight)(extensions) )
FC_REFLECT( graphene::protocol::oracle_bond_release_operation,
            (fee)(producer)(bond)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::vault_register_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::vault_bond_lock_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_bond_lock_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_bond_release_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::vault_register_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::vault_bond_lock_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_bond_lock_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_bond_release_operation )
