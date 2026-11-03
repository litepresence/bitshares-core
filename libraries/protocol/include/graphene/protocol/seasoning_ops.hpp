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

   /**
    * 90-day seasoning window (BSIP-1 section 5 staging): a BTC ACCS pair must
    * hold vault coverage >= 2.0 and oracle coverage >= 1.0 continuously for
    * this long, with the independent-verifier bit set, before USD issuance.
    * 90 * 86400 = 7776000 seconds. Read from head-block time only: H1 inputs
    * are absent by construction, so H1 freezes can neither pause nor extend
    * the clock (that isolation is the point).
    */
   constexpr uint32_t GRAPHENE_H2_SEASONING_WINDOW_SEC = 7776000;
   /// Vault-leg floor: vault_bonds / outstanding >= 2.0 (BSIP-1 section 5).
   constexpr uint32_t GRAPHENE_H2_SEASONING_VAULT_MIN_BPS = 20000;
   /// Oracle-leg floor: oracle_bonds / secured_debt >= 1.0 (BSIP-1 section 5).
   constexpr uint32_t GRAPHENE_H2_SEASONING_ORACLE_MIN_BPS = 10000;

   /**
    * @brief Records an independent verifier's attestation that a seasoned
    * pair's coverage held, setting the verifier bit once.
    * @ingroup operations
    *
    * Only a seated committee member may verify (like `oracle_unfreeze`: the
    * attestation judges bonded backing, so it admits at the price leg), and
    * only once per pair: a second attestation is refused as a double-set, so
    * no anonymous or rotating attestation can overwrite the recorded
    * identity. The bit is one of four conjuncts in `h2_seasoning_complete`
    * (90 days elapsed, minimums intact, verifier bit set); no mint/convert
    * op reads it yet -- the issuance phase will.
    */
   struct seasoning_verify_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset           fee;
      account_id_type verifier; ///< Must be a seated committee member; pays the fee; recorded
      asset_id_type   pair;     ///< Seasoned pair; must carry a seasoning record
      extensions_type extensions; ///< Appended-last rule

      account_id_type fee_payer()const { return verifier; }
      void            validate()const;
   };

} } // graphene::protocol

FC_REFLECT( graphene::protocol::seasoning_verify_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::seasoning_verify_operation,
            (fee)(verifier)(pair)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::seasoning_verify_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::seasoning_verify_operation )
