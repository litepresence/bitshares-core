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

   /// ACCS min offer lifetime: 100 blocks (~5 minutes at 3s/block).
   constexpr uint32_t GRAPHENE_ACCS_MIN_OFFER_LIFETIME = 100;
   /// ACCS SLA: 86400 blocks (~3 days at 3s/block).
   constexpr uint32_t GRAPHENE_ACCS_SLA_BLOCKS = 86400;
   /// ACCS min griefing bond: $83.75 in USD cents (base asset units at committed rate).
   constexpr uint64_t GRAPHENE_ACCS_MIN_GRIEFING_BOND_USD_CENTS = 8375;
   /// ACCS offer cleanup age: 100800 blocks (~3.5 days).
   constexpr uint32_t GRAPHENE_ACCS_OFFER_CLEANUP_AGE = 100800;
   /// ACCS max open offers per orderbook (state bound).
   constexpr uint32_t GRAPHENE_ACCS_MAX_OPEN_OFFERS_PER_ORDERBOOK = 1000;

   /**
    * @brief Declares a foreign-chain or foreign-subtoken ACCS gateway.
    * @ingroup operations
    *
    * Committee member declares that a foreign chain (and optionally a foreign
    * subtoken on that chain) is a supported ACCS gateway. After declaration,
    * any BitShares base asset can have an ACCS orderbook against this gateway.
    * No per-base-asset committee approval is needed.
    */
   struct accs_declare_gateway_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset           fee;
      account_id_type committee_member;  ///< Must be a seated committee member
      uint8_t         chain_id;          ///< Foreign chain enum (BTC, ETH, SOL, etc.)
      std::string     foreign_asset_id;  ///< Empty = native asset; contract address for subtokens
      uint8_t         foreign_asset_code; ///< F1 foreign asset index (0 = native)
      oracle_id_type  oracle_id;         ///< Bound F1 foreign-tx oracle
      extensions_type extensions;         ///< Appended-last rule

      account_id_type fee_payer()const { return committee_member; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Deactivates an ACCS gateway (no new offers, existing offers remain).
    * @ingroup operations
    */
   struct accs_deactivate_gateway_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset           fee;
      account_id_type committee_member;  ///< Must be a seated committee member
      uint8_t         chain_id;          ///< Foreign chain enum
      std::string     foreign_asset_id;  ///< Foreign asset identifier
      extensions_type extensions;         ///< Appended-last rule

      account_id_type fee_payer()const { return committee_member; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Creates an ACCS offer: Alice locks base asset in escrow.
    * @ingroup operations
    *
    * Alice sells base_asset for a foreign asset on a declared gateway. The base
    * asset is locked in escrow on the offer object. Alice sets a minimum foreign
    * amount (price = base/foreign). Optional expiry block for auto-cancel.
    */
   struct accs_create_offer_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset            fee;
      account_id_type  seller;           ///< Alice; pays fee, must have base asset balance
      asset_id_type    base_asset;       ///< BitShares asset being sold
      uint8_t          chain_id;         ///< Foreign chain (must have active gateway)
      std::string      foreign_asset_id; ///< Foreign token identifier (must match gateway)
      share_type       base_amount;       ///< Amount of base asset offered (> 0)
      share_type       foreign_amount;    ///< Minimum foreign asset wanted (> 0)
      std::string      foreign_recipient; ///< Alice's foreign-chain address
      uint32_t         expiry;           ///< 0 = no expiry; else block number
      extensions_type  extensions;        ///< Appended-last rule

      account_id_type fee_payer()const { return seller; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Cancels an unmatched ACCS offer: escrow released to Alice.
    * @ingroup operations
    */
   struct accs_cancel_offer_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset            fee;
      account_id_type  seller;           ///< Must equal offer.seller
      accs_offer_id_type  offer_id;         ///< The offer to cancel
      extensions_type  extensions;        ///< Appended-last rule

      account_id_type fee_payer()const { return seller; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Matches an open ACCS offer: Bob bonds griefing fee.
    * @ingroup operations
    */
   struct accs_match_offer_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset            fee;
      account_id_type  buyer;            ///< Bob; pays fee + griefing bond
      accs_offer_id_type  offer_id;        ///< The offer to match
      share_type       griefing_bond;    ///< Bob's bond (must be >= minimum)
      extensions_type  extensions;       ///< Appended-last rule

      account_id_type fee_payer()const { return buyer; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Fulfills a matched ACCS offer: attestor publishes foreign tx proof.
    * @ingroup operations
    *
    * Base asset released to Bob, griefing bond returned to Bob. Requires F1
    * oracle equality match (tx_id, amount, foreign_asset_id, recipient,
    * event_kind, confirmations).
    */
   struct accs_fulfill_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset            fee;
      account_id_type  publisher;        ///< The attestor publishing the proof
      accs_offer_id_type  offer_id;        ///< The matched offer
      std::string      foreign_tx_hash;  ///< Foreign chain transaction hash
      share_type       amount;           ///< Foreign amount sent (must equal offer.foreign_amount)
      extensions_type  extensions;       ///< Appended-last rule

      account_id_type fee_payer()const { return publisher; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Claims griefing bond on SLA timeout: Alice reclaims bond + escrow.
    * @ingroup operations
    */
   struct accs_claim_griefing_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset            fee;
      account_id_type  claimer;          ///< Alice; must equal offer.seller
      accs_offer_id_type  offer_id;        ///< The matched offer
      extensions_type  extensions;       ///< Appended-last rule

      account_id_type fee_payer()const { return claimer; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

 } } // graphene::protocol

FC_REFLECT( graphene::protocol::accs_declare_gateway_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::accs_deactivate_gateway_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::accs_create_offer_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::accs_cancel_offer_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::accs_match_offer_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::accs_fulfill_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::accs_claim_griefing_operation::fee_params_t, (fee) )

FC_REFLECT( graphene::protocol::accs_declare_gateway_operation,
            (fee)(committee_member)(chain_id)(foreign_asset_id)(foreign_asset_code)(oracle_id)(extensions) )
FC_REFLECT( graphene::protocol::accs_deactivate_gateway_operation,
            (fee)(committee_member)(chain_id)(foreign_asset_id)(extensions) )
FC_REFLECT( graphene::protocol::accs_create_offer_operation,
            (fee)(seller)(base_asset)(chain_id)(foreign_asset_id)(base_amount)
            (foreign_amount)(foreign_recipient)(expiry)(extensions) )
FC_REFLECT( graphene::protocol::accs_cancel_offer_operation,
            (fee)(seller)(offer_id)(extensions) )
FC_REFLECT( graphene::protocol::accs_match_offer_operation,
            (fee)(buyer)(offer_id)(griefing_bond)(extensions) )
FC_REFLECT( graphene::protocol::accs_fulfill_operation,
            (fee)(publisher)(offer_id)(foreign_tx_hash)(amount)(extensions) )
FC_REFLECT( graphene::protocol::accs_claim_griefing_operation,
            (fee)(claimer)(offer_id)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::accs_declare_gateway_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::accs_deactivate_gateway_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::accs_create_offer_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::accs_cancel_offer_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::accs_match_offer_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::accs_fulfill_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::accs_claim_griefing_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::accs_declare_gateway_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::accs_deactivate_gateway_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::accs_create_offer_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::accs_cancel_offer_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::accs_match_offer_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::accs_fulfill_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::accs_claim_griefing_operation )
