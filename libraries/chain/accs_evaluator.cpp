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
#include <graphene/chain/accs_evaluator.hpp>
#include <graphene/chain/accs_object.hpp>
#include <graphene/chain/database.hpp>
#include <graphene/chain/account_object.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/chain/committee_member_object.hpp>

#include <graphene/chain/hardfork.hpp>

namespace graphene { namespace chain {

void_result accs_declare_gateway_evaluator::do_evaluate( const accs_declare_gateway_operation& op )
{
   return void_result();
}

object_id_type accs_declare_gateway_evaluator::do_apply( const accs_declare_gateway_operation& op )
{
   return object_id_type();
}

void_result accs_deactivate_gateway_evaluator::do_evaluate( const accs_deactivate_gateway_operation& op )
{
   return void_result();
}

void_result accs_deactivate_gateway_evaluator::do_apply( const accs_deactivate_gateway_operation& op )
{
   return void_result();
}

void_result accs_create_offer_evaluator::do_evaluate( const accs_create_offer_operation& op )
{
   return void_result();
}

object_id_type accs_create_offer_evaluator::do_apply( const accs_create_offer_operation& op )
{
   return object_id_type();
}

void_result accs_cancel_offer_evaluator::do_evaluate( const accs_cancel_offer_operation& op )
{
   return void_result();
}

void_result accs_cancel_offer_evaluator::do_apply( const accs_cancel_offer_operation& op )
{
   return void_result();
}

void_result accs_match_offer_evaluator::do_evaluate( const accs_match_offer_operation& op )
{
   return void_result();
}

void_result accs_match_offer_evaluator::do_apply( const accs_match_offer_operation& op )
{
   return void_result();
}

void_result accs_fulfill_evaluator::do_evaluate( const accs_fulfill_operation& op )
{
   return void_result();
}

void_result accs_fulfill_evaluator::do_apply( const accs_fulfill_operation& op )
{
   return void_result();
}

void_result accs_claim_griefing_evaluator::do_evaluate( const accs_claim_griefing_operation& op )
{
   return void_result();
}

void_result accs_claim_griefing_evaluator::do_apply( const accs_claim_griefing_operation& op )
{
   return void_result();
}

} } // graphene::chain
