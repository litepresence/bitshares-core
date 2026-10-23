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

#include <graphene/chain/accs_object.hpp>
#include <graphene/protocol/accs_ops.hpp>

namespace graphene { namespace chain {

   class accs_gateway_object;
   class accs_orderbook_object;
   class accs_offer_object;

   class accs_declare_gateway_evaluator : public evaluator<accs_declare_gateway_evaluator>
   {
      public:
         using operation_type = accs_declare_gateway_operation;

         void_result    do_evaluate( const accs_declare_gateway_operation& op );
         object_id_type do_apply( const accs_declare_gateway_operation& op );
   };

   class accs_deactivate_gateway_evaluator : public evaluator<accs_deactivate_gateway_evaluator>
   {
      public:
         using operation_type = accs_deactivate_gateway_operation;

         void_result do_evaluate( const accs_deactivate_gateway_operation& op );
         void_result do_apply( const accs_deactivate_gateway_operation& op );
   };

   class accs_create_offer_evaluator : public evaluator<accs_create_offer_evaluator>
   {
      public:
         using operation_type = accs_create_offer_operation;

         void_result    do_evaluate( const accs_create_offer_operation& op );
         object_id_type do_apply( const accs_create_offer_operation& op );
   };

   class accs_cancel_offer_evaluator : public evaluator<accs_cancel_offer_evaluator>
   {
      public:
         using operation_type = accs_cancel_offer_operation;

         void_result do_evaluate( const accs_cancel_offer_operation& op );
         void_result do_apply( const accs_cancel_offer_operation& op );
   };

   class accs_match_offer_evaluator : public evaluator<accs_match_offer_evaluator>
   {
      public:
         using operation_type = accs_match_offer_operation;

         void_result do_evaluate( const accs_match_offer_operation& op );
         void_result do_apply( const accs_match_offer_operation& op );
   };

   class accs_fulfill_evaluator : public evaluator<accs_fulfill_evaluator>
   {
      public:
         using operation_type = accs_fulfill_operation;

         void_result do_evaluate( const accs_fulfill_operation& op );
         void_result do_apply( const accs_fulfill_operation& op );
   };

   class accs_claim_griefing_evaluator : public evaluator<accs_claim_griefing_evaluator>
   {
      public:
         using operation_type = accs_claim_griefing_operation;

         void_result do_evaluate( const accs_claim_griefing_operation& op );
         void_result do_apply( const accs_claim_griefing_operation& op );
   };

} } // graphene::chain
