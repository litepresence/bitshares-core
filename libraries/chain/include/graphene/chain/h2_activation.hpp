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

#include <graphene/chain/hardfork.hpp>
#include <graphene/chain/types.hpp>

#include <fc/time.hpp>

namespace graphene { namespace chain {

class asset_object;
class database;

/**
 * @brief H2 activation legs (BSIP-1 section 6: gateway Track B before price
 * Track B, enforced as consensus-reject rules, never a sequencing promise).
 *
 * Three gates, one invariant (E-03 audit-round-2: BONDS < GATEWAY < PRICE):
 * - Primitives gate (`HARDFORK_H2_BONDS_TIME`, 2029-11-01): the shared
 *   bond/dispute/challenge primitives built once (vault_challenge,
 *   oracle_dispute, oracle_dispute_escalate, challenge_vote). Usable by both
 *   tracks. Must precede gateway so custody never forms unchallengeable.
 * - Gateway leg (`HARDFORK_H2_GATEWAY_TIME`, 2029-12-01): bonded custody
 *   formation and rotation (vault_register, vault_bond_lock,
 *   vault_bond_release, vault_rotate). Requires BONDS passed: the gateway
 *   window seasons custody with challenge machinery live.
 * - Price leg (`HARDFORK_H2_PRICE_TIME`, 2030-01-01): everything that values
 *   through bonded prices or judges through stake (oracle_bond_lock,
 *   oracle_bond_release, vault_resolve, pair_freeze, winddown_claim,
 *   oracle_fallback_set, oracle_unfreeze).
 *
 * Maintenance sweeps and observation hooks stay on the primitives gate: they
 * act only on state the leg-gated ops created, so they need no independent
 * activation (and lose none).
 *
 * The invariant -- bonds strictly before gateway strictly before price -- is
 * asserted by every helper below, so an inverted schedule refuses ALL H2
 * paths fail-closed (inversion refused, never silently staged).
 */

/// @return whether @p bonds strictly precedes @p gateway strictly precedes
/// @p price. Unit-testable; every gate helper asserts it over the configured
/// heights. R3-04: the legacy two-argument form is removed — no caller may
/// assert gateway<price while bypassing the BONDS leg; the three-argument
/// form is the only ordering predicate (E-03: BONDS leg included).
bool h2_legs_ordered( const fc::time_point_sec& bonds,
                       const fc::time_point_sec& gateway,
                       const fc::time_point_sec& price );

/// Shared primitives gate + ordering invariant.
void h2_require_primitives( const fc::time_point_sec& now );
/// Gateway-leg gate + ordering invariant.
void h2_require_gateway_leg( const fc::time_point_sec& now );
/// Price-leg gate + ordering invariant.
void h2_require_price_leg( const fc::time_point_sec& now );

/**
 * @return whether @p pair carries an H1 price binding (an explicit
 * price_oracle_binding on its bitasset options). Non-market-issued assets
 * carry no bitasset options and report false. H1-exclusion is consensus-
 * reject at vault_register: an H1-priced pair can never migrate into H2
 * bonded custody, so unbonded inputs can never move bonded medians.
 */
bool h2_pair_has_h1_binding( const asset_object& pair, const database& d );

/**
 * @return whether @p oid is referenced by any live bitasset binding: some
 * market-issued asset's current options name it through the explicit
 * price_oracle_binding or the legacy expiry-free price_oracle_id. X-02
 * (R9-I4): such an oracle prices an H1 smartcoin, so H2 freeze machinery
 * (oracle_dispute, pair_freeze) must never reach it -- dispute expiry
 * freezes unconditionally, and the H1 bound-consumer read guards on the
 * same frozen flag, so a frozen legacy oracle would null H1 feeds.
 * H2-bonded oracles carry no bitasset binding and report false.
 */
bool h2_oracle_referenced_by_bitasset( const database& d, oracle_id_type oid );

} } // graphene::chain
