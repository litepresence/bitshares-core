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

#include <graphene/protocol/oracle.hpp>

namespace graphene { namespace chain {

   class oracle_object;
   class reference_asset_object;

   /**
    * Bond-ready oracle evaluators (BSIP-1 §2, Phase 1).
    *
    * Junior-dev map: `reference_asset_create` (op 82, committee-gated) registers
    * a canonical reference unit (e.g. USD with precision); `oracle_create`
    * (op 78) opens a price oracle over a base/quote reference pair with an
    * expiry height; `oracle_publish` (op 81) is how a bonded producer submits
    * one price observation per series per window; `oracle_update` (op 79)
    * rotates parameters; `oracle_delete` (op 80) retires the oracle. All five
    * refuse pre-`HARDFORK_ORACLE_TIME` in the evaluator AND the proposal
    * visitor. Guards (rate-limit, OSM-style delay, freeze) are OPT-IN per
    * oracle — legacy feed paths are byte-identical and untouched.
    * Aggregation is select-don't-compute (weighted median, per-producer
    * outlier exclusion); drifted/expired bindings yield NO price (fail-closed).
    */

   /**
    * Register a reference asset (op 82, committee authority only).
    * Refuses duplicates and non-BTS precisions outside the registered
    * schedule. Wallet entry point: `create_reference_asset`.
    */
   class reference_asset_create_evaluator : public evaluator<reference_asset_create_evaluator>
   {
      public:
         using operation_type = reference_asset_create_operation;

         void_result    do_evaluate( const reference_asset_create_operation& op ) const;
         object_id_type do_apply( const reference_asset_create_operation& op ) const;
   };

   /**
    * Open a price oracle (op 78).
    * Binds base/quote reference assets with an explicit series list and a
    * mandatory strictly-future expiry height (immutable while bound).
    * Rejects bid>ask series, unknown references, and past expiry.
    */
   class oracle_create_evaluator : public evaluator<oracle_create_evaluator>
   {
      public:
         using operation_type = oracle_create_operation;

         void_result    do_evaluate( const oracle_create_operation& op ) const;
         object_id_type do_apply( const oracle_create_operation& op ) const;
   };

   /**
    * Rotate oracle parameters (op 79). Never widens a binding past its
    * expiry; expiry itself is immutable (close + recreate instead).
    */
   class oracle_update_evaluator : public evaluator<oracle_update_evaluator>
   {
      public:
         using operation_type = oracle_update_operation;

         void_result do_evaluate( const oracle_update_operation& op );
         void_result do_apply( const oracle_update_operation& op ) const;

         const oracle_object* _oracle = nullptr;
   };

   /**
    * Retire an oracle (op 80, zero-fee: cleanup must never be priced out).
    * Existing bindings keep consuming the last-good median — deletion stops
    * new observations, it does not reprice settled positions.
    */
   class oracle_delete_evaluator : public evaluator<oracle_delete_evaluator>
   {
      public:
         using operation_type = oracle_delete_operation;

         void_result do_evaluate( const oracle_delete_operation& op );
         void_result do_apply( const oracle_delete_operation& op ) const;

         const oracle_object* _oracle = nullptr;
   };

   /**
    * Publish one price observation (op 81).
    * One submission per producer per series per window; late, duplicate, or
    * off-series observations are refused (never queued). Feeds the median
    * that margin, vault coverage, and issuance consume — delayed by the
    * oracle's configured guard delay, if any.
    */
   class oracle_publish_evaluator : public evaluator<oracle_publish_evaluator>
   {
      public:
         using operation_type = oracle_publish_operation;

         void_result do_evaluate( const oracle_publish_operation& op );
         void_result do_apply( const oracle_publish_operation& op ) const;

         const oracle_object* _oracle = nullptr;
   };

} } // graphene::chain
