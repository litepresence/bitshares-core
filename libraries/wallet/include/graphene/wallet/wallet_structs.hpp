/*
 * Copyright (c) 2017 Cryptonomex, Inc., and contributors.
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

#include <string>
#include <vector>

#include <fc/optional.hpp>

using namespace graphene::app;
using namespace graphene::chain;
using namespace graphene::utilities;
using std::string;
using std::vector;

namespace graphene { namespace wallet {

using transaction_handle_type = uint32_t;

struct plain_keys
{
   map<public_key_type, string>  keys;
   fc::sha512                    checksum;
};

struct brain_key_info
{
   string brain_priv_key;
   string wif_priv_key;
   public_key_type pub_key;
};


/**
 *  Contains the confirmation receipt the sender must give the receiver and
 *  the meta data about the receipt that helps the sender identify which receipt is
 *  for the receiver and which is for the change address.
 */
struct blind_confirmation
{
   struct output
   {
      string                          label;
      public_key_type                 pub_key;
      stealth_confirmation::memo_data decrypted_memo;
      stealth_confirmation            confirmation;
      authority                       auth;
      string                          confirmation_receipt;
   };

   signed_transaction     trx;
   vector<output>         outputs;
};

struct blind_balance
{
   asset                     amount;
   public_key_type           from; ///< the account this balance came from
   public_key_type           to; ///< the account this balance is logically associated with
   public_key_type           one_time_key; ///< used to derive the authority key and blinding factor
   fc::sha256                blinding_factor;
   fc::ecc::commitment_type  commitment;
   bool                      used = false;
};

struct blind_receipt
{
   std::pair<public_key_type,fc::time_point>        from_date()const { return std::make_pair(from_key,date); }
   std::pair<public_key_type,fc::time_point>        to_date()const   { return std::make_pair(to_key,date);   }
   std::tuple<public_key_type,asset_id_type,bool>   to_asset_used()const
   { return std::make_tuple(to_key,amount.asset_id,used);   }

   const commitment_type& commitment()const        { return data.commitment; }

   fc::time_point                  date;
   public_key_type                 from_key;
   string                          from_label;
   public_key_type                 to_key;
   string                          to_label;
   asset                           amount;
   string                          memo;
   authority                       control_authority;
   stealth_confirmation::memo_data data;
   bool                            used = false;
   stealth_confirmation            conf;
   /// Head-block number when this receipt was recorded (best-effort: 0 when
   /// the wallet was offline or the remote was unreachable = unknown age).
   /// input selection enforces min_mix_blocks against this field —
   /// unknown-age receipts are ineligible while a hold is configured
   /// (fail-closed; 0 with min_mix_blocks == 0 (default off) behaves as
   /// before). Appended-last: old wallet files load with 0.
   uint32_t                        received_block = 0;
   /// RP4: the wallet address key this output was addressed to. Equals to_key
   /// for legacy receipts (address-key `to`); the scanned address key for
   /// AuthKey receipts. Balance/spend/history queries match to_key OR
   /// address_key, so AuthKey outputs stay visible under the address label
   /// (and survive label renames). Appended-last: old files load empty, and
   /// empty matches nothing (legacy receipts already match via to_key).
   public_key_type                 address_key;
   /// TALLY-ONLY marker: this receipt was recognized with a VIEW key only
   /// (no spend key), so it carries NO spend authority — the output can be
   /// tallied but never spent. Every spend builder must refuse it (see
   /// blind_receipt_spendable): the marker is explicit, not implied by the
   /// absence of an authority key.
   /// Appended-last: old wallet files load with false (their watch-only
   /// receipts are still caught by the empty-authority check).
   bool                            tally_only = false;
   /// PENDING marker: this receipt was recorded for an output that is not
   /// (yet) on chain — the change output of an op40/op41 build the wallet
   /// has not broadcast, or has broadcast but whose block has not arrived.
   ///
   /// The change output's opening is a conservation difference (the sum of
   /// the spent inputs' openings minus the to-output's), so it is NOT
   /// derivable from the chain: the wallet computed it when it built the
   /// operation, and it is durable only in this receipt. The marker keeps the
   /// balance query from retiring the receipt as "spent" while the output is
   /// still in flight (a retired receipt is excluded from the spend
   /// selection, which would strand the sender's change).
   /// Appended-last: old wallet files load with false.
   bool                            pending = false;
};

struct by_from;
struct by_to;
struct by_to_asset_used;
struct by_commitment;

typedef multi_index_container< blind_receipt,
   indexed_by<
      ordered_unique< tag<by_commitment>,
                      const_mem_fun< blind_receipt, const commitment_type&, &blind_receipt::commitment > >,
      ordered_unique< tag<by_to>,
                      const_mem_fun< blind_receipt,
                                     std::pair<public_key_type,fc::time_point>,
                                     &blind_receipt::to_date > >,
      ordered_non_unique< tag<by_to_asset_used>,
                          const_mem_fun< blind_receipt,
                                         std::tuple<public_key_type,asset_id_type,bool>,
                                         &blind_receipt::to_asset_used > >,
      ordered_unique< tag<by_from>,
                      const_mem_fun< blind_receipt,
                                     std::pair<public_key_type,fc::time_point>,
                                     &blind_receipt::from_date > >
   >
> blind_receipt_index_type;


struct key_label
{
   string          label;
   public_key_type key;
};


struct by_label;
struct by_key;
typedef multi_index_container<
   key_label,
   indexed_by<
      ordered_unique< tag<by_label>, member< key_label, string, &key_label::label > >,
      ordered_unique< tag<by_key>, member< key_label, public_key_type, &key_label::key > >
   >
> key_label_index_type;


/// RP5: dual-key stealth address book entry (view/spend pubs; watch-only when
/// the spend priv is absent from _keys). address_key for receipts = view_pub.
struct stealth_address_record
{
   string          label;
   public_key_type view_pub;
   public_key_type spend_pub;
   bool            watch_only = false;
};


/// How a blind-transfer counterparty was classified.
///
/// The classification is dual-first (a dual-key address is never silently
/// degraded to the single-key path) and it is the SAME on both sender paths
/// (the op39 deposit and the op40 blind transfer), so a remote dual-key
/// recipient cannot be degraded on one path and not on the other.
///
/// Spec: docs/superpowers/specs/2026-10-19-viewkey-ring-auth-construction.md section 1
struct blind_counterparty
{
   public_key_type key;                   // the single-key address (view == spend)
   fc::optional<public_key_type> view_pub, spend_pub;
   bool dual = false;                     // a dual-key address (spend-derived opening)
   bool from_address_book = false;        // the wallet's own labeled key
   bool wallet_owned = false;             // the wallet holds the private key

   /// The HOLDER identity.
   ///
   /// Every output of one operation must go to the SAME holder: the
   /// operation publishes the sum of the outputs' openings, so a co-recipient
   /// recovers the other holder's opening from that sum (and the opening is
   /// the credential the ring spend authorizes by).
   /// Spec: docs/superpowers/specs/2026-10-19-viewkey-ring-auth-construction.md section 1
   std::string holder()const
   {
      if( dual && view_pub.valid() && spend_pub.valid() )
         return "dual:" + std::string( *view_pub ) + ":" + std::string( *spend_pub );
      return "single:" + std::string( key );
   }
};

struct wallet_data
{   /** Chain ID this wallet is used with */
   chain_id_type chain_id;
   account_multi_index_type my_accounts;
   /// @return IDs of all accounts in @ref my_accounts
   vector<object_id_type> my_account_ids()const
   {
      vector<object_id_type> ids;
      ids.reserve(my_accounts.size());
      std::transform(my_accounts.begin(), my_accounts.end(), std::back_inserter(ids),
                     [](const account_object& ao) { return ao.id; });
      return ids;
   }
   /// Add acct to @ref my_accounts, or update it if it is already in @ref my_accounts
   /// @return true if the account was newly inserted; false if it was only updated
   bool update_account(const account_object& acct)
   {
      auto& idx = my_accounts.get<by_id>();
      auto itr = idx.find(acct.id);
      if( itr != idx.end() )
      {
         idx.replace(itr, acct);
         return false;
      } else {
         idx.insert(acct);
         return true;
      }
   }

   /** encrypted keys */
   vector<char>              cipher_keys;

   /** map an account to a set of extra keys that have been imported for that account */
   map<account_id_type, set<public_key_type> >  extra_keys;

   // map of account_name -> base58_private_key for
   //    incomplete account regs
   map<string, vector<string> > pending_account_registrations;
   map<string, string> pending_witness_registrations;

   key_label_index_type                                              labeled_keys;
   blind_receipt_index_type                                          blind_receipts;
   /// RP5 dual-key address book (appended-last; old files load empty).
   vector<stealth_address_record>                                    stealth_addresses;

   string                    ws_server = "ws:// localhost:8090";
   string                    ws_user;
   string                    ws_password;
};

struct exported_account_keys
{
    string account_name;
    vector<vector<char>> encrypted_private_keys;
    vector<public_key_type> public_keys;
};

struct exported_keys
{
    fc::sha512 password_checksum;
    vector<exported_account_keys> account_keys;
};

struct approval_delta
{
   vector<string> active_approvals_to_add;
   vector<string> active_approvals_to_remove;
   vector<string> owner_approvals_to_add;
   vector<string> owner_approvals_to_remove;
   vector<string> key_approvals_to_add;
   vector<string> key_approvals_to_remove;
};

struct worker_vote_delta
{
   flat_set<worker_id_type> vote_for;
   flat_set<worker_id_type> vote_against;
   flat_set<worker_id_type> vote_abstain;
};

struct signed_block_with_info : public signed_block
{
   explicit signed_block_with_info( const signed_block& block );

   block_id_type block_id;
   public_key_type signing_key;
   vector< transaction_id_type > transaction_ids;
};

struct vesting_balance_object_with_info : public vesting_balance_object
{
   vesting_balance_object_with_info( const vesting_balance_object& vbo, const fc::time_point_sec& now );

   /**
    * How much is allowed to be withdrawn.
    */
   asset allowed_withdraw;

   /**
    * The time at which allowed_withdrawal was calculated.
    */
   fc::time_point_sec allowed_withdraw_time;
};

struct signed_message_meta {
   string account;
   public_key_type memo_key;
   uint32_t block;
   string time;
};

class signed_message {
public:
   string message;
   signed_message_meta meta;
   fc::optional<fc::ecc::compact_signature> signature;

   fc::sha256 digest()const;
};

namespace detail {
class wallet_api_impl;
}

/***
 * A utility class for performing various state-less actions that are related to wallets
 */
class utility {
   public:
      /**
       * Derive any number of *possible* owner keys from a given brain key.
       *
       * NOTE: These keys may or may not match with the owner keys of any account.
       * This function is merely intended to assist with account or key recovery.
       *
       * @see suggest_brain_key()
       *
       * @param brain_key    Brain key
       * @param number_of_desired_keys  Number of desired keys
       * @return A list of keys that are deterministically derived from the brainkey
       */
      static vector<brain_key_info> derive_owner_keys_from_brain_key( const string& brain_key,
                                                                      uint32_t number_of_desired_keys = 1 );

      /** Suggests a safe brain key to use for creating your account.
       * \c create_account_with_brain_key() requires you to specify a 'brain key',
       * a long passphrase that provides enough entropy to generate cyrptographic
       * keys.  This function will suggest a suitably random string that should
       * be easy to write down (and, with effort, memorize).
       * @returns a suggested brain_key
       */
      static brain_key_info suggest_brain_key();
};

struct operation_detail {
   string                   memo;
   string                   description;
   operation_history_object op;
};

struct operation_detail_ex {
    string                   memo;
    string                   description;
    operation_history_object op;
    transaction_id_type      transaction_id;
};

struct account_history_operation_detail {
   uint32_t                     total_count = 0;
   uint32_t                     result_count = 0;
   vector<operation_detail_ex>  details;
};

/**
 * @brief Blind-by-default wallet settings (BSIP-2 §2).
 *
 * Reference (cli) wallet creates blinded change and defaults new transfers
 * to blind, with one-tap transparent opt-out. Network hygiene (decoy-fetch
 * batching, minimum broadcast delay, RPC rules) is required behavior with
 * conformance tests — see BLIND_DEFAULTS_CONTRACT.md, which is the
 * browser-wallet (separate repo) binding spec for the same values.
 */
struct blind_transfer_defaults
{
   /// New transfers default to blind (transfer_default routes blind unless
   /// the caller passes transparent_opt_out).
   bool     blind_by_default = true;
   /// Decoy/confirmation fetches are batched in chunks of this size: one
   /// RPC round-trip per chunk, never one per decoy (timing-link defense).
   uint32_t decoy_fetch_batch_size = 32;
   /// Seconds to wait after signing before broadcasting a blind transfer
   /// (propagation-timing defense against few DPOS producers). Applies only
   /// when broadcast=true; 0 disables (explicit, logged choice).
   uint32_t min_broadcast_delay_sec = 3;
   /// Optional N-block holding before a received blind output is spent.
   /// ENFORCED by cli_wallet input selection (): a receipt may fund a
   /// blind spend only once head_block - received_block >= min_mix_blocks;
   /// receipts with unknown age (received_block == 0, e.g. recorded offline
   /// or by an older wallet) are ineligible while the hold is configured.
   /// Consensus never enforces a hold (it cannot see wallet receipt age).
   /// 0 = off (the default).
   uint32_t min_mix_blocks = 0;
};

/**
 * Mix-hold eligibility (BSIP-2 §1): pure decision rule behind
 * min_mix_blocks, unit-testable without a node. head_block comes from the
 * remote database_api; received_block from the receipt (0 = unknown age).
 * - min_mix_blocks == 0 (default off): everything eligible (legacy path).
 * - otherwise: eligible iff received_block != 0 (known age, fail-closed)
 *   AND head_block - received_block >= min_mix_blocks (no underflow: a
 *   receipt from the future is ineligible).
 * No consensus effect.
 */
inline bool blind_receipt_mix_eligible( uint32_t received_block,
                                        uint32_t head_block,
                                        uint32_t min_mix_blocks )
{
   if( min_mix_blocks == 0 )
      return true;
   if( received_block == 0 || received_block > head_block )
      return false;
   return ( head_block - received_block ) >= min_mix_blocks;
}

/**
 * Number of RPC round-trips needed to cover n decoy candidates at
 * batch_size per trip (decoy-fetch batching, BSIP-2 §1). Pure helper
 * so the chunking math is unit-testable without a node: batch 0 is
 * treated as 1 (same guard as get_blind_balances). No consensus effect.
 */
inline size_t blind_batch_chunk_count( size_t n, uint32_t batch_size )
{
   if( batch_size == 0 )
      batch_size = 1;
   return ( n + batch_size - 1 ) / batch_size;
}

/**
 * A receipt may be SPENT only when it was recognized with a spend key.
 *
 * Two independent reasons, both checked here so that every spend builder
 * refuses the same receipts:
 *  - the explicit TALLY-ONLY marker (a watch-only recognition: the wallet
 *    can count the output but holds no spend authority for it), and
 *  - an empty control authority (a receipt with no owner key cannot be
 *    authorized by any signature) — this also covers receipts written by an
 *    older wallet, which has no tally_only field.
 *
 * Spec: docs/superpowers/specs/2026-10-19-viewkey-ring-auth-construction.md section 1
 */
inline bool blind_receipt_spendable( const blind_receipt& r )
{
   return !r.tally_only && !( r.control_authority == authority() );
}

}} // namespace graphene::wallet

FC_REFLECT( graphene::wallet::blind_transfer_defaults,
            (blind_by_default)(decoy_fetch_batch_size)
            (min_broadcast_delay_sec)(min_mix_blocks) )

FC_REFLECT( graphene::wallet::key_label, (label)(key) )
FC_REFLECT( graphene::wallet::stealth_address_record, (label)(view_pub)(spend_pub)(watch_only) )
FC_REFLECT( graphene::wallet::blind_balance, (amount)(from)(to)(one_time_key)(blinding_factor)(commitment)(used) )
FC_REFLECT( graphene::wallet::blind_confirmation::output,
            (label)(pub_key)(decrypted_memo)(confirmation)(auth)(confirmation_receipt) )
FC_REFLECT( graphene::wallet::blind_confirmation, (trx)(outputs) )

FC_REFLECT( graphene::wallet::plain_keys, (keys)(checksum) )

FC_REFLECT( graphene::wallet::wallet_data,
            (chain_id)
            (my_accounts)
            (cipher_keys)
            (extra_keys)
            (pending_account_registrations)(pending_witness_registrations)
            (labeled_keys)
            (blind_receipts)
            (stealth_addresses)
            (ws_server)
            (ws_user)
            (ws_password)
          )

FC_REFLECT( graphene::wallet::brain_key_info,
            (brain_priv_key)
            (wif_priv_key)
            (pub_key)
          )

FC_REFLECT( graphene::wallet::exported_account_keys, (account_name)(encrypted_private_keys)(public_keys) )

FC_REFLECT( graphene::wallet::exported_keys, (password_checksum)(account_keys) )

FC_REFLECT( graphene::wallet::blind_receipt,
            (date)(from_key)(from_label)(to_key)(to_label)(amount)(memo)(control_authority)(data)(used)(conf)
            (received_block)(address_key)(tally_only)(pending) )

FC_REFLECT( graphene::wallet::approval_delta,
   (active_approvals_to_add)
   (active_approvals_to_remove)
   (owner_approvals_to_add)
   (owner_approvals_to_remove)
   (key_approvals_to_add)
   (key_approvals_to_remove)
)

FC_REFLECT( graphene::wallet::worker_vote_delta,
   (vote_for)
   (vote_against)
   (vote_abstain)
)

FC_REFLECT_DERIVED( graphene::wallet::signed_block_with_info, (graphene::chain::signed_block),
   (block_id)(signing_key)(transaction_ids) )

FC_REFLECT_DERIVED( graphene::wallet::vesting_balance_object_with_info, (graphene::chain::vesting_balance_object),
   (allowed_withdraw)(allowed_withdraw_time) )

FC_REFLECT( graphene::wallet::operation_detail,
            (memo)(description)(op) )

FC_REFLECT(graphene::wallet::operation_detail_ex,
            (memo)(description)(op)(transaction_id))

FC_REFLECT( graphene::wallet::account_history_operation_detail,
        (total_count)(result_count)(details))

FC_REFLECT( graphene::wallet::signed_message_meta, (account)(memo_key)(block)(time) )
FC_REFLECT( graphene::wallet::signed_message, (message)(meta)(signature) )
