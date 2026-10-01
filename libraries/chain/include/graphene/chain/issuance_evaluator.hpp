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
#include <graphene/chain/evaluator.hpp>

#include <graphene/protocol/issuance_ops.hpp>

namespace graphene { namespace chain {

   class reserve_object;
   class vault_object;

   class hybrid_mint_evaluator : public evaluator<hybrid_mint_evaluator>
   {
      public:
         using operation_type = hybrid_mint_operation;

         void_result do_evaluate( const hybrid_mint_operation& op );
         object_id_type do_apply( const hybrid_mint_operation& op );

         const vault_object*   _vault = nullptr;
         const reserve_object* _reserve = nullptr; ///< Null when this mint creates it
         bool                  _creates_reserve = false;
         share_type            _fxr_to_mint = share_type( 0 );
         protocol::oracle_value _price; ///< Bonded price proven in evaluate, reused in apply
   };

   class hybrid_redeem_evaluator : public evaluator<hybrid_redeem_evaluator>
   {
      public:
         using operation_type = hybrid_redeem_operation;

         void_result do_evaluate( const hybrid_redeem_operation& op );
         object_id_type do_apply( const hybrid_redeem_operation& op ) const;

         const vault_object*   _vault = nullptr;
         const reserve_object* _reserve = nullptr;
         share_type            _payout = share_type( 0 );
   };

   /**
    * Exact face value of @p bts_raw bond units at @p price (bond-per-pair),
    * rounding DOWN (favoring the protocol): floor(bts_raw * quote / base)
    * in 256-bit. Returns 0 on non-positive input or degenerate price.
    */
   share_type h2_issue_bts_to_face( share_type bts_raw,
                                    const protocol::oracle_value& price );

   /**
    * Exact bond payout for @p face_raw face units at @p price,
    * rounding DOWN (favoring the protocol): floor(face_raw * base / quote)
    * in 256-bit. Returns 0 on non-positive input or degenerate price.
    */
   share_type h2_issue_face_to_bts( share_type face_raw,
                                    const protocol::oracle_value& price );

   /**
    * Coverage in saturating basis points: floor(value_face * 10000 /
    * supply_face) capped at 0xFFFFFFFF, exact 128-bit division. Zero (or
    * negative) supply saturates (nothing to secure); non-positive value
    * reads 0. Deterministic on every node.
    */
   uint32_t h2_issue_coverage_bps( share_type value_face, share_type supply_face );

   /// @return the issuance reserve for @p pair, or null when none exists.
   const reserve_object* h2_find_reserve( const database& d, asset_id_type pair );

} } // graphene::chain
