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
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <sstream>
#include <string>
#include <list>

#include <boost/version.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/replace.hpp>

#include <boost/range/adaptor/map.hpp>
#include <boost/range/algorithm_ext/erase.hpp>
#include <boost/range/algorithm/unique.hpp>
#include <boost/range/algorithm/sort.hpp>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/random_access_index.hpp>
#include <boost/multi_index/tag.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/hashed_index.hpp>

#include <fc/git_revision.hpp>
#include <fc/io/fstream.hpp>
#include <fc/io/json.hpp>
#include <fc/io/stdio.hpp>
#include <fc/network/http/websocket.hpp>
#include <fc/rpc/cli.hpp>
#include <fc/rpc/websocket_api.hpp>
#include <fc/crypto/hex.hpp>
#include <fc/thread/mutex.hpp>
#include <fc/thread/scoped_lock.hpp>
#include <fc/crypto/base58.hpp>
#include <fc/crypto/aes.hpp>

#include <graphene/app/api.hpp>
#include <graphene/app/util.hpp>
#include <graphene/chain/asset_object.hpp>
#include <graphene/protocol/fee_schedule.hpp>
#include <graphene/protocol/pts_address.hpp>
#include <graphene/chain/hardfork.hpp>
#include <graphene/utilities/git_revision.hpp>
#include <graphene/utilities/key_conversion.hpp>
#include <graphene/utilities/words.hpp>
#include <graphene/wallet/wallet.hpp>
#include <graphene/wallet/stealth_receive.hpp>
#include <graphene/wallet/api_documentation.hpp>
#include "wallet_api_impl.hpp"
#include <graphene/debug_witness/debug_api.hpp>

#include "operation_printer.hpp"
#include <graphene/wallet/reflect_util.hpp>

#define BRAIN_KEY_WORD_COUNT 16
#define RANGE_PROOF_MANTISSA 49 // Minimum mantissa bits to "hide" in the range proof.
                                // If this number is set too low, then for large value
                                // commitments the length of the range proof will hint
                                // strongly at the value amount that is being hidden.

namespace graphene { namespace wallet {
   fc::sha256 signed_message::digest()const
   {
      fc::stringstream to_sign;
      to_sign << message << '\n';
      to_sign << "account=" << meta.account << '\n';
      to_sign << "memokey=" << string( meta.memo_key ) << '\n';
      to_sign << "block=" << meta.block << '\n';
      to_sign << "timestamp=" << meta.time;

      return fc::sha256::hash( to_sign.str() );
   }
   vector<brain_key_info> utility::derive_owner_keys_from_brain_key( const string& brain_key,
                                                                     uint32_t number_of_desired_keys )
   {
      // Safety-check
      FC_ASSERT( number_of_desired_keys >= 1, "number_of_desired_keys should be at least 1" );

      // Create as many derived owner keys as requested
      vector<brain_key_info> results;
      for( uint32_t i = 0; i < number_of_desired_keys; ++i )
      {
        fc::ecc::private_key priv_key = graphene::wallet::detail::derive_private_key( brain_key, i );

        brain_key_info result;
        result.brain_priv_key = brain_key;
        result.wif_priv_key = key_to_wif( priv_key );
        result.pub_key = priv_key.get_public_key();

        results.push_back(result);
      }

      return results;
   }

   brain_key_info utility::suggest_brain_key()
   {
      brain_key_info result;
      // create a private key for secure entropy
      fc::sha256 sha_entropy1 = fc::ecc::private_key::generate().get_secret();
      fc::sha256 sha_entropy2 = fc::ecc::private_key::generate().get_secret();
      fc::bigint entropy1(sha_entropy1.data(), sha_entropy1.data_size());
      fc::bigint entropy2(sha_entropy2.data(), sha_entropy2.data_size());
      fc::bigint entropy(entropy1);
      entropy <<= 8 * sha_entropy1.data_size();
      entropy += entropy2;
      string brain_key = "";

      for( uint32_t i = 0; i < BRAIN_KEY_WORD_COUNT; ++i )
      {
         fc::bigint choice = entropy % graphene::words::word_list_size;
         entropy /= graphene::words::word_list_size;
         if (i > 0)
            brain_key += " ";
         brain_key += graphene::words::word_list[choice.to_int64()];
      }

      brain_key = detail::normalize_brain_key(brain_key);
      fc::ecc::private_key priv_key = detail::derive_private_key(brain_key, 0);
      result.brain_priv_key = brain_key;
      result.wif_priv_key = key_to_wif(priv_key);
      result.pub_key = priv_key.get_public_key();
      return result;
   }
}}

namespace graphene { namespace wallet {

wallet_api::wallet_api( const wallet_data& initial_data, const fc::api<login_api>& rapi )
   : my( std::make_unique<detail::wallet_api_impl>(*this, initial_data, rapi) )
{
}

wallet_api::~wallet_api() = default;

bool wallet_api::copy_wallet_file( const string& destination_filename )const
{
   return my->copy_wallet_file(destination_filename);
}

optional<signed_block_with_info> wallet_api::get_block(uint32_t num)const
{
   return my->_remote_db->get_block(num);
}

uint64_t wallet_api::get_account_count() const
{
   return my->_remote_db->get_account_count();
}

vector<account_object> wallet_api::list_my_accounts()const
{
   return vector<account_object>(my->_wallet.my_accounts.begin(), my->_wallet.my_accounts.end());
}

map<string, account_id_type, std::less<>> wallet_api::list_accounts( const string& lowerbound, uint32_t limit )const
{
   return my->_remote_db->lookup_accounts(lowerbound, limit, {});
}

vector<asset> wallet_api::list_account_balances( const string& id )const
{
   return my->_remote_db->get_account_balances(id, flat_set<asset_id_type>());
}

vector<extended_asset_object> wallet_api::list_assets( const string& lowerbound, uint32_t limit )const
{
   return my->_remote_db->list_assets( lowerbound, limit );
}

uint64_t wallet_api::get_asset_count()const
{
   return my->_remote_db->get_asset_count();
}

signed_transaction wallet_api::htlc_create( const string& source, const string& destination,
         const string& amount, const string& asset_symbol, const string& hash_algorithm,
         const string& preimage_hash, uint32_t preimage_size,
         uint32_t claim_period_seconds, const string& memo, bool broadcast ) const
{
   return my->htlc_create(source, destination, amount, asset_symbol, hash_algorithm, preimage_hash, preimage_size,
         claim_period_seconds, memo, broadcast);
}

fc::optional<fc::variant> wallet_api::get_htlc(const htlc_id_type& htlc_id) const
{
   fc::optional<htlc_object> optional_obj = my->get_htlc(htlc_id);
   if ( optional_obj.valid() )
   {
      const htlc_object& obj = *optional_obj;
      // convert to formatted variant
      fc::mutable_variant_object transfer;
      const auto& from = my->get_account( obj.transfer.from );
      transfer["from"] = from.name;
      const auto& to = my->get_account( obj.transfer.to );
      transfer["to"] = to.name;
      const auto& asset = my->get_asset( obj.transfer.asset_id );
      transfer["asset"] = asset.symbol;
      transfer["amount"] = graphene::app::uint128_amount_to_string( obj.transfer.amount.value, asset.precision );
      if (obj.memo.valid())
         transfer["memo"] = my->read_memo( *obj.memo );
      class htlc_hash_to_variant_visitor
      {
         public:
         typedef fc::mutable_variant_object result_type;

         result_type operator()(const fc::ripemd160& obj)const
         { return convert("RIPEMD160", obj.str()); }
         result_type operator()(const fc::sha1& obj)const
         { return convert("SHA1", obj.str()); }
         result_type operator()(const fc::sha256& obj)const
         { return convert("SHA256", obj.str()); }
         result_type operator()(const fc::hash160& obj)const
         { return convert("HASH160", obj.str()); }
         private:
         result_type convert(const string& type, const string& hash)const
         {
            fc::mutable_variant_object ret_val;
            ret_val["hash_algo"] = type;
            ret_val["preimage_hash"] = hash;
            return ret_val;
         }
      };
      static htlc_hash_to_variant_visitor hash_visitor;
      fc::mutable_variant_object htlc_lock = obj.conditions.hash_lock.preimage_hash.visit(hash_visitor);
      htlc_lock["preimage_size"] = obj.conditions.hash_lock.preimage_size;
      fc::mutable_variant_object time_lock;
      time_lock["expiration"] = obj.conditions.time_lock.expiration;
      time_lock["time_left"] = fc::get_approximate_relative_time_string(obj.conditions.time_lock.expiration);
      fc::mutable_variant_object conditions;
      conditions["htlc_lock"] = htlc_lock;
      conditions["time_lock"] = time_lock;
      fc::mutable_variant_object result;
      result["transfer"] = transfer;
      result["conditions"] = conditions;
      return fc::optional<fc::variant>(result);
   }
   return fc::optional<fc::variant>();
}

signed_transaction wallet_api::htlc_redeem( const htlc_id_type& htlc_id, const string& issuer,
      const string& preimage, bool broadcast ) const
{

   return my->htlc_redeem(htlc_id, issuer, std::vector<char>(preimage.begin(), preimage.end()), broadcast);
}

signed_transaction wallet_api::htlc_extend( const htlc_id_type& htlc_id, const string& issuer,
      uint32_t seconds_to_add, bool broadcast ) const
{
   return my->htlc_extend(htlc_id, issuer, seconds_to_add, broadcast);
}

vector<operation_detail> wallet_api::get_account_history( const string& name, uint32_t limit )const
{
   vector<operation_detail> result;

   while( limit > 0 )
   {
      bool skip_first_row = false;
      operation_history_id_type start;
      if( result.size() )
      {
         start = result.back().op.id;
         if( start == operation_history_id_type() ) // no more data
            break;
         start = start + (-1);
         if( start == operation_history_id_type() ) // will return most recent history if
                                                    // directly call remote API with this
         {
            start = start + 1;
            skip_first_row = true;
         }
      }

      uint32_t default_page_size = 100;
      uint32_t page_limit = skip_first_row ? std::min<uint32_t>( default_page_size, limit + 1 )
                                           : std::min<uint32_t>( default_page_size, limit );

      vector<operation_history_object> current = my->_remote_hist->get_account_history(
            name,
            operation_history_id_type(),
            page_limit,
            start );
      bool first_row = true;
      for( auto& o : current )
      {
         if( first_row )
         {
            first_row = false;
            if( skip_first_row )
            {
               continue;
            }
         }
         std::stringstream ss;
         auto memo = o.op.visit(detail::operation_printer(ss, *my, o));
         result.push_back( operation_detail{ memo, ss.str(), o } );
      }

      if( current.size() < page_limit )
         break;

      limit -= current.size();
      if( skip_first_row )
         ++limit;
   }

   return result;
}

vector<operation_detail> wallet_api::get_relative_account_history(
      const string& name,
      uint32_t stop,
      uint32_t limit,
      uint32_t start )const
{
   vector<operation_detail> result;
   auto account_id = get_account(name).get_id();

   const account_object& account = my->get_account(account_id);
   const account_statistics_object& stats = my->get_object(account.statistics);

   if(start == 0)
       start = stats.total_ops;
   else
      start = std::min<uint32_t>(start, stats.total_ops);

   uint32_t default_page_size = 100;
   while( limit > 0 )
   {
      uint32_t page_size = std::min<uint32_t>(default_page_size, limit);
      vector <operation_history_object> current = my->_remote_hist->get_relative_account_history(
            name,
            stop,
            page_size,
            start);
      for (auto &o : current) {
         std::stringstream ss;
         auto memo = o.op.visit(detail::operation_printer(ss, *my, o));
         result.push_back(operation_detail{memo, ss.str(), o});
      }
      if (current.size() < page_size)
         break;
      limit -= page_size;
      start -= page_size;
      if( start == 0 ) break;
   }
   return result;
}

account_history_operation_detail wallet_api::get_account_history_by_operations(
      const string& name,
      const flat_set<uint16_t>& operation_types,
      uint32_t start,
      uint32_t limit )const
{
    account_history_operation_detail result;

    const auto& account = my->get_account(name);
    const auto& stats = my->get_object(account.statistics);

    // sequence of account_history_object start with 1
    start = start == 0 ? 1 : start;

    if (start <= stats.removed_ops) {
        start = stats.removed_ops;
        result.total_count =stats.removed_ops;
    }

    uint32_t default_page_size = 100;
    while (limit > 0 && start <= stats.total_ops) {
        uint32_t min_limit = std::min(default_page_size, limit);
        auto current = my->_remote_hist->get_account_history_by_operations(name, operation_types, start, min_limit);
        auto his_rend = current.operation_history_objs.rend();
        for( auto it = current.operation_history_objs.rbegin(); it != his_rend; ++it )
        {
            auto& obj = *it;
            std::stringstream ss;
            auto memo = obj.op.visit(detail::operation_printer(ss, *my, obj));

            transaction_id_type transaction_id;
            auto block = get_block(obj.block_num);
            if (block.valid() && obj.trx_in_block < block->transaction_ids.size()) {
                transaction_id = block->transaction_ids[obj.trx_in_block];
            }
            result.details.push_back(operation_detail_ex{memo, ss.str(), obj, transaction_id});
        }
        result.result_count += current.operation_history_objs.size();
        result.total_count += current.total_count;

        start += current.total_count > 0 ? current.total_count : min_limit;
        limit -= current.operation_history_objs.size();
    }

    return result;
}

full_account wallet_api::get_full_account( const string& name_or_id )const
{
    return my->_remote_db->get_full_accounts({name_or_id}, false)[name_or_id];
}

vector<bucket_object> wallet_api::get_market_history(
      const string& symbol1,
      const string& symbol2,
      uint32_t bucket,
      const fc::time_point_sec& start,
      const fc::time_point_sec& end )const
{
   return my->_remote_hist->get_market_history( symbol1, symbol2, bucket, start, end );
}

vector<limit_order_object> wallet_api::get_account_limit_orders(
      const string& name_or_id,
      const string& base,
      const string& quote,
      uint32_t limit,
      const optional<limit_order_id_type>& ostart_id,
      const optional<price>& ostart_price )const
{
   return my->_remote_db->get_account_limit_orders(name_or_id, base, quote, limit, ostart_id, ostart_price);
}

vector<limit_order_object> wallet_api::get_limit_orders( const string& a, const string& b, uint32_t limit )const
{
   return my->_remote_db->get_limit_orders(a, b, limit);
}

vector<call_order_object> wallet_api::get_call_orders( const string& a, uint32_t limit )const
{
   return my->_remote_db->get_call_orders(a, limit);
}

vector<force_settlement_object> wallet_api::get_settle_orders( const string& a, uint32_t limit )const
{
   return my->_remote_db->get_settle_orders(a, limit);
}

vector<collateral_bid_object> wallet_api::get_collateral_bids( const string& a, uint32_t limit, uint32_t start )const
{
   return my->_remote_db->get_collateral_bids(a, limit, start);
}

brain_key_info wallet_api::suggest_brain_key()const
{
   return graphene::wallet::utility::suggest_brain_key();
}

vector<brain_key_info> wallet_api::derive_owner_keys_from_brain_key(
      const string& brain_key,
      uint32_t number_of_desired_keys ) const
{
   return graphene::wallet::utility::derive_owner_keys_from_brain_key(brain_key, number_of_desired_keys);
}

bool wallet_api::is_public_key_registered( const string& public_key ) const
{
   bool is_known = my->_remote_db->is_public_key_registered(public_key);
   return is_known;
}


string wallet_api::serialize_transaction( const signed_transaction& tx )const
{
   return fc::to_hex(fc::raw::pack(tx));
}

variant wallet_api::get_object( const object_id_type& id ) const
{
   return my->_remote_db->get_objects({id}, {});
}

string wallet_api::get_wallet_filename() const
{
   return my->get_wallet_filename();
}

transaction_handle_type wallet_api::begin_builder_transaction()const
{
   return my->begin_builder_transaction();
}

void wallet_api::add_operation_to_builder_transaction(
      transaction_handle_type transaction_handle,
      const operation& op )const
{
   my->add_operation_to_builder_transaction(transaction_handle, op);
}

void wallet_api::replace_operation_in_builder_transaction(
      transaction_handle_type handle,
      uint32_t operation_index,
      const operation& new_op )const
{
   my->replace_operation_in_builder_transaction(handle, operation_index, new_op);
}

asset wallet_api::set_fees_on_builder_transaction( transaction_handle_type handle, const string& fee_asset )const
{
   return my->set_fees_on_builder_transaction(handle, fee_asset);
}

transaction wallet_api::preview_builder_transaction(transaction_handle_type handle)const
{
   return my->preview_builder_transaction(handle);
}

signed_transaction wallet_api::sign_builder_transaction(transaction_handle_type transaction_handle,
                                                        bool broadcast)const
{
   return my->sign_builder_transaction(transaction_handle, broadcast);
}

signed_transaction wallet_api::sign_builder_transaction2(transaction_handle_type transaction_handle,
                                                        const vector<public_key_type>& explicit_keys,
                                                        bool broadcast)const
{
   return my->sign_builder_transaction2(transaction_handle, explicit_keys, broadcast);
}

pair<transaction_id_type,signed_transaction> wallet_api::broadcast_transaction( const signed_transaction& tx )const
{
    return my->broadcast_transaction(tx);
}

signed_transaction wallet_api::propose_builder_transaction(
      transaction_handle_type handle,
      const time_point_sec& expiration,
      uint32_t review_period_seconds,
      bool broadcast )const
{
   return my->propose_builder_transaction(handle, expiration, review_period_seconds, broadcast);
}

signed_transaction wallet_api::propose_builder_transaction2(
      transaction_handle_type handle,
      const string& account_name_or_id,
      const time_point_sec& expiration,
      uint32_t review_period_seconds,
      bool broadcast )const
{
   return my->propose_builder_transaction2(handle, account_name_or_id, expiration, review_period_seconds, broadcast);
}

void wallet_api::remove_builder_transaction(transaction_handle_type handle)const
{
   return my->remove_builder_transaction(handle);
}

account_object wallet_api::get_account( const string& account_name_or_id ) const
{
   return my->get_account(account_name_or_id);
}

extended_asset_object wallet_api::get_asset( const string& asset_name_or_id ) const
{
   auto found_asset = my->find_asset(asset_name_or_id);
   FC_ASSERT( found_asset, "Unable to find asset '${a}'", ("a",asset_name_or_id) );
   return *found_asset;
}

asset_bitasset_data_object wallet_api::get_bitasset_data( const string& asset_name_or_id ) const
{
   auto asset = get_asset(asset_name_or_id);
   FC_ASSERT(asset.is_market_issued() && asset.bitasset_data_id);
   return my->get_object(*asset.bitasset_data_id);
}

account_id_type wallet_api::get_account_id( const string& account_name_or_id ) const
{
   return my->get_account_id(account_name_or_id);
}

asset_id_type wallet_api::get_asset_id( const string& asset_symbol_or_id ) const
{
   return my->get_asset_id(asset_symbol_or_id);
}

bool wallet_api::import_key( const string& account_name_or_id, const string& wif_key )const
{
   FC_ASSERT(!is_locked());
   // backup wallet
   fc::optional<fc::ecc::private_key> optional_private_key = wif_to_key(wif_key);
   if (!optional_private_key)
      FC_THROW("Invalid private key");
   string shorthash = detail::address_to_shorthash(address(optional_private_key->get_public_key()));
   copy_wallet_file( "before-import-key-" + shorthash );

   if( my->import_key(account_name_or_id, wif_key) )
   {
      save_wallet_file();
      copy_wallet_file( "after-import-key-" + shorthash );
      return true;
   }
   return false;
}

map<string, bool, std::less<>> wallet_api::import_accounts( const string& filename, const string& password )const
{
   FC_ASSERT( !is_locked() );
   FC_ASSERT( fc::exists( filename ) );

   const auto imported_keys = fc::json::from_file<exported_keys>( filename );

   const auto password_hash = fc::sha512::hash( password );
   FC_ASSERT( fc::sha512::hash( password_hash ) == imported_keys.password_checksum );

   map<string, bool, std::less<>> result;
   for( const auto& item : imported_keys.account_keys )
   {
       const auto import_this_account = [ & ]() -> bool
       {
           try
           {
               const account_object account = get_account( item.account_name );
               const auto& owner_keys = account.owner.get_keys();
               const auto& active_keys = account.active.get_keys();

               for( const auto& public_key : item.public_keys )
               {
                   if( std::find( owner_keys.begin(), owner_keys.end(), public_key ) != owner_keys.end() )
                       return true;

                   if( std::find( active_keys.begin(), active_keys.end(), public_key ) != active_keys.end() )
                       return true;
               }
           }
           catch( ... )
           {
           }

           return false;
       };

       const auto should_proceed = import_this_account();
       result[ item.account_name ] = should_proceed;

       if( should_proceed )
       {
           uint32_t import_successes = 0;
           uint32_t import_failures = 0;
           // TODO: First check that all private keys match public keys
           for( const auto& encrypted_key : item.encrypted_private_keys )
           {
               try
               {
                  const auto plain_text = fc::aes_decrypt( password_hash, encrypted_key );
                  const auto private_key = fc::raw::unpack<private_key_type>( plain_text );

                  import_key( item.account_name, string( graphene::utilities::key_to_wif( private_key ) ) );
                  ++import_successes;
               }
               catch( const fc::exception& e )
               {
                  elog( "Couldn't import key due to exception ${e}", ("e", e.to_detail_string()) );
                  ++import_failures;
               }
           }
           ilog( "successfully imported ${n} keys for account ${name}",
                 ("n", import_successes)("name", item.account_name) );
           if( import_failures > 0 )
              elog( "failed to import ${n} keys for account ${name}",
                    ("n", import_failures)("name", item.account_name) );
       }
   }

   return result;
}

bool wallet_api::import_account_keys(
      const string& filename,
      const string& password,
      const string& src_account_name,
      const string& dest_account_name )const
{
   FC_ASSERT( !is_locked() );
   FC_ASSERT( fc::exists( filename ) );

   bool is_my_account = false;
   const auto accounts = list_my_accounts();
   for( const auto& account : accounts )
   {
       if( account.name == dest_account_name )
       {
           is_my_account = true;
           break;
       }
   }
   FC_ASSERT( is_my_account );

   const auto imported_keys = fc::json::from_file<exported_keys>( filename );

   const auto password_hash = fc::sha512::hash( password );
   FC_ASSERT( fc::sha512::hash( password_hash ) == imported_keys.password_checksum );

   bool found_account = false;
   for( const auto& item : imported_keys.account_keys )
   {
       if( item.account_name != src_account_name )
           continue;

       found_account = true;

       for( const auto& encrypted_key : item.encrypted_private_keys )
       {
           const auto plain_text = fc::aes_decrypt( password_hash, encrypted_key );
           const auto private_key = fc::raw::unpack<private_key_type>( plain_text );

           my->import_key( dest_account_name, string( graphene::utilities::key_to_wif( private_key ) ) );
       }

       return true;
   }
   save_wallet_file();

   FC_ASSERT( found_account );

   return false;
}

string wallet_api::normalize_brain_key( const string& s ) const
{
   return detail::normalize_brain_key( s );
}

variant wallet_api::info()const
{
   return my->info();
}

variant_object wallet_api::about() const
{
    return my->about();
}

fc::ecc::private_key wallet_api::derive_private_key( const string& prefix_string, uint32_t sequence_number ) const
{
   return detail::derive_private_key( prefix_string, sequence_number );
}

signed_transaction wallet_api::register_account( const string& name,
                                                 const public_key_type& owner_pubkey,
                                                 const public_key_type& active_pubkey,
                                                 const string&  registrar_account,
                                                 const string&  referrer_account,
                                                 uint32_t referrer_percent,
                                                 bool broadcast )const
{
   return my->register_account( name, owner_pubkey, active_pubkey,
                                registrar_account, referrer_account, referrer_percent, broadcast );
}
signed_transaction wallet_api::create_account_with_brain_key( const string& brain_key, const string& account_name,
      const string& registrar_account, const string& referrer_account,
      bool broadcast /* = false */ )const
{
   return my->create_account_with_brain_key(
            brain_key, account_name, registrar_account,
            referrer_account, broadcast
            );
}
signed_transaction wallet_api::issue_asset( const string& to_account, const string& amount, const string& symbol,
                                            const string& memo, bool broadcast )const
{
   return my->issue_asset(to_account, amount, symbol, memo, broadcast);
}

signed_transaction wallet_api::transfer( const string& from, const string& to, const string& amount,
                                         const string& asset_symbol, const string& memo,
                                         bool broadcast /* = false */ )const
{
   return my->transfer(from, to, amount, asset_symbol, memo, broadcast);
}
signed_transaction wallet_api::create_asset( const string& issuer,
                                             const string& symbol,
                                             uint8_t precision,
                                             const asset_options& common,
                                             const optional<bitasset_options>& bitasset_opts,
                                             bool broadcast )const
{
   return my->create_asset(issuer, symbol, precision, common, bitasset_opts, broadcast);
}

signed_transaction wallet_api::update_asset( const string& symbol,
                                             const optional<string>& new_issuer,
                                             const asset_options& new_options,
                                             bool broadcast /* = false */ )const
{
   return my->update_asset(symbol, new_issuer, new_options, broadcast);
}

signed_transaction wallet_api::update_asset_issuer( const string& symbol,
                                                    const string& new_issuer,
                                                    bool broadcast /* = false */ )const
{
   return my->update_asset_issuer(symbol, new_issuer, broadcast);
}

signed_transaction wallet_api::update_bitasset( const string& symbol,
                                                const bitasset_options& new_options,
                                                bool broadcast /* = false */ )const
{
   return my->update_bitasset(symbol, new_options, broadcast);
}

oracle_object wallet_api::get_oracle( const string& name_or_id )const
{
   return my->get_oracle( name_or_id );
}

signed_transaction wallet_api::create_reference_asset( const string& creator, const string& symbol,
                                                       uint8_t precision, const string& description,
                                                       bool broadcast )
{
   return my->create_reference_asset( creator, symbol, precision, description, broadcast );
}

signed_transaction wallet_api::create_oracle( const string& owner, const string& name,
                                              const string& description, const string& base_symbol,
                                              const string& quote_symbol,
                                              const vector<oracle_series>& series,
                                              const oracle_options& options, bool broadcast )
{
   return my->create_oracle( owner, name, description, base_symbol, quote_symbol, series,
                             options, broadcast );
}

signed_transaction wallet_api::update_oracle( const string& owner, const string& name_or_id,
                                              const optional<string>& new_description,
                                              const optional<oracle_options>& new_options,
                                              bool broadcast )
{
   return my->update_oracle( owner, name_or_id, new_description, new_options, broadcast );
}

signed_transaction wallet_api::delete_oracle( const string& owner, const string& name_or_id,
                                              bool broadcast )
{
   return my->delete_oracle( owner, name_or_id, broadcast );
}

signed_transaction wallet_api::publish_oracle_value( const string& producer,
                                                     const string& name_or_id,
                                                     const vector<oracle_value>& values,
                                                     bool broadcast )
{
   return my->publish_oracle_value( producer, name_or_id, values, broadcast );
}

signed_transaction wallet_api::update_asset_feed_producers( const string& symbol,
                                                            const flat_set<string>& new_feed_producers,
                                                            bool broadcast /* = false */ )const
{
   return my->update_asset_feed_producers(symbol, new_feed_producers, broadcast);
}

signed_transaction wallet_api::publish_asset_feed( const string& publishing_account,
                                                   const string& symbol,
                                                   const price_feed& feed,
                                                   bool broadcast /* = false */ )const
{
   return my->publish_asset_feed(publishing_account, symbol, feed, broadcast);
}

signed_transaction wallet_api::fund_asset_fee_pool( const string& from,
                                                    const string& symbol,
                                                    const string& amount,
                                                    bool broadcast /* = false */ )const
{
   return my->fund_asset_fee_pool(from, symbol, amount, broadcast);
}

signed_transaction wallet_api::claim_asset_fee_pool( const string& symbol,
                                                     const string& amount,
                                                     bool broadcast /* = false */ )const
{
   return my->claim_asset_fee_pool(symbol, amount, broadcast);
}

signed_transaction wallet_api::reserve_asset( const string& from,
                                              const string& amount,
                                              const string& symbol,
                                              bool broadcast /* = false */ )const
{
   return my->reserve_asset(from, amount, symbol, broadcast);
}

signed_transaction wallet_api::global_settle_asset( const string& symbol,
                                                    const price& settle_price,
                                                    bool broadcast /* = false */ )const
{
   return my->global_settle_asset(symbol, settle_price, broadcast);
}

signed_transaction wallet_api::settle_asset( const string& account_to_settle,
                                             const string& amount_to_settle,
                                             const string& symbol,
                                             bool broadcast /* = false */ )const
{
   return my->settle_asset(account_to_settle, amount_to_settle, symbol, broadcast);
}

signed_transaction wallet_api::bid_collateral( const string& bidder_name,
                                               const string& debt_amount, const string& debt_symbol,
                                               const string& additional_collateral,
                                               bool broadcast )const
{
   return my->bid_collateral(bidder_name, debt_amount, debt_symbol, additional_collateral, broadcast);
}

signed_transaction wallet_api::whitelist_account( const string& authorizing_account,
                                                  const string& account_to_list,
                                                  account_whitelist_operation::account_listing new_listing_status,
                                                  bool broadcast /* = false */ )const
{
   return my->whitelist_account(authorizing_account, account_to_list, new_listing_status, broadcast);
}

signed_transaction wallet_api::create_committee_member( const string& owner_account, const string& url,
                                                        bool broadcast /* = false */ )const
{
   return my->create_committee_member(owner_account, url, broadcast);
}

map<string, witness_id_type, std::less<>> wallet_api::list_witnesses( const string& lowerbound, uint32_t limit )const
{
   return my->_remote_db->lookup_witness_accounts(lowerbound, limit);
}

map<string,committee_member_id_type, std::less<>> wallet_api::list_committee_members(
      const string& lowerbound, uint32_t limit )const
{
   return my->_remote_db->lookup_committee_member_accounts(lowerbound, limit);
}

witness_object wallet_api::get_witness( const string& owner_account )const
{
   return my->get_witness(owner_account);
}

committee_member_object wallet_api::get_committee_member( const string& owner_account )const
{
   return my->get_committee_member(owner_account);
}

signed_transaction wallet_api::create_witness( const string& owner_account,
                                               const string& url,
                                               bool broadcast /* = false */ )const
{
   return my->create_witness(owner_account, url, broadcast);
}

signed_transaction wallet_api::create_worker(
   const string& owner_account,
   const time_point_sec& work_begin_date,
   const time_point_sec& work_end_date,
   const share_type& daily_pay,
   const string& name,
   const string& url,
   const variant& worker_settings,
   bool broadcast /* = false */ )const
{
   return my->create_worker( owner_account, work_begin_date, work_end_date,
      daily_pay, name, url, worker_settings, broadcast );
}

signed_transaction wallet_api::update_worker_votes(
   const string& owner_account,
   const worker_vote_delta& delta,
   bool broadcast /* = false */ )const
{
   return my->update_worker_votes( owner_account, delta, broadcast );
}

signed_transaction wallet_api::update_witness(
   const string& witness_name,
   const string& url,
   const string& block_signing_key,
   bool broadcast /* = false */ )const
{
   return my->update_witness(witness_name, url, block_signing_key, broadcast);
}

vector< vesting_balance_object_with_info > wallet_api::get_vesting_balances( const string& account_name )const
{
   return my->get_vesting_balances( account_name );
}

signed_transaction wallet_api::withdraw_vesting(
   const string& witness_name,
   const string& amount,
   const string& asset_symbol,
   bool broadcast /* = false */ )const
{
   return my->withdraw_vesting( witness_name, amount, asset_symbol, broadcast );
}

signed_transaction wallet_api::vote_for_committee_member( const string& voting_account,
                                                          const string& witness,
                                                          bool approve,
                                                          bool broadcast /* = false */ )const
{
   return my->vote_for_committee_member(voting_account, witness, approve, broadcast);
}

signed_transaction wallet_api::vote_for_witness( const string& voting_account,
                                                 const string& witness,
                                                 bool approve,
                                                 bool broadcast /* = false */ )const
{
   return my->vote_for_witness(voting_account, witness, approve, broadcast);
}

signed_transaction wallet_api::set_voting_proxy( const string& account_to_modify,
                                                 const optional<string>& voting_account,
                                                 bool broadcast /* = false */ )const
{
   return my->set_voting_proxy(account_to_modify, voting_account, broadcast);
}

signed_transaction wallet_api::set_desired_witness_and_committee_member_count( const string& account_to_modify,
                                                                      uint16_t desired_number_of_witnesses,
                                                                      uint16_t desired_number_of_committee_members,
                                                                      bool broadcast /* = false */ )const
{
   return my->set_desired_witness_and_committee_member_count(account_to_modify, desired_number_of_witnesses,
                                                     desired_number_of_committee_members, broadcast);
}

void wallet_api::set_wallet_filename( const string& wallet_filename )const
{
   my->_wallet_filename = wallet_filename;
}

signed_transaction wallet_api::sign_transaction( const signed_transaction& tx, bool broadcast /* = false */ )const
{ try {
   return my->sign_transaction( tx, broadcast);
} FC_CAPTURE_AND_RETHROW( (tx) ) }

signed_transaction wallet_api::sign_transaction2( const signed_transaction& tx,
                                                  const vector<public_key_type>& signing_keys,
                                                  bool broadcast /* = false */ )const
{ try {
   return my->sign_transaction2( tx, signing_keys, broadcast);
} FC_CAPTURE_AND_RETHROW( (tx) ) }

flat_set<public_key_type> wallet_api::get_transaction_signers( const signed_transaction& tx ) const
{ try {
   return my->get_transaction_signers(tx);
} FC_CAPTURE_AND_RETHROW( (tx) ) }

vector<flat_set<account_id_type>> wallet_api::get_key_references( const vector<public_key_type>& keys ) const
{ try {
   return my->get_key_references(keys);
} FC_CAPTURE_AND_RETHROW( (keys) ) }

operation wallet_api::get_prototype_operation( const string& operation_name )const
{
   return my->get_prototype_operation( operation_name );
}

void wallet_api::dbg_make_uia( const string& creator, const string& symbol )const
{
   FC_ASSERT(!is_locked());
   my->dbg_make_uia(creator, symbol);
}

void wallet_api::dbg_make_mia( const string& creator, const string& symbol )const
{
   FC_ASSERT(!is_locked());
   my->dbg_make_mia(creator, symbol);
}

void wallet_api::dbg_push_blocks( const string& src_filename, uint32_t count )const
{
   my->dbg_push_blocks( src_filename, count );
}

void wallet_api::dbg_generate_blocks( const string& debug_wif_key, uint32_t count )const
{
   my->dbg_generate_blocks( debug_wif_key, count );
}

void wallet_api::dbg_stream_json_objects( const string& filename )const
{
   my->dbg_stream_json_objects( filename );
}

void wallet_api::dbg_update_object( const fc::variant_object& update )const
{
   my->dbg_update_object( update );
}

void wallet_api::network_add_nodes( const vector<string>& nodes )const
{
   my->network_add_nodes( nodes );
}

vector< variant > wallet_api::network_get_connected_peers()const
{
   return my->network_get_connected_peers();
}

void wallet_api::flood_network( const string& prefix, uint32_t number_of_transactions )const
{
   FC_ASSERT(!is_locked());
   my->flood_network(prefix, number_of_transactions);
}

signed_transaction wallet_api::propose_parameter_change(
   const string& proposing_account,
   const fc::time_point_sec& expiration_time,
   const variant_object& changed_values,
   bool broadcast /* = false */
   )const
{
   return my->propose_parameter_change( proposing_account, expiration_time, changed_values, broadcast );
}

signed_transaction wallet_api::propose_fee_change(
   const string& proposing_account,
   const fc::time_point_sec& expiration_time,
   const variant_object& changed_fees,
   bool broadcast /* = false */
   )const
{
   return my->propose_fee_change( proposing_account, expiration_time, changed_fees, broadcast );
}

signed_transaction wallet_api::approve_proposal(
   const string& fee_paying_account,
   const string& proposal_id,
   const approval_delta& delta,
   bool broadcast /* = false */
   )const
{
   return my->approve_proposal( fee_paying_account, proposal_id, delta, broadcast );
}

global_property_object wallet_api::get_global_properties() const
{
   return my->get_global_properties();
}

dynamic_global_property_object wallet_api::get_dynamic_global_properties() const
{
   return my->get_dynamic_global_properties();
}

signed_transaction wallet_api::add_transaction_signature( const signed_transaction& tx,
                                                          bool broadcast )const
{
   return my->add_transaction_signature( tx, broadcast );
}

string wallet_api::help()const
{
   std::vector<string> method_names = my->method_documentation.get_method_names();
   std::stringstream ss;
   for (const string& method_name : method_names)
   {
      try
      {
         ss << my->method_documentation.get_brief_description(method_name);
      }
      catch (const fc::key_not_found_exception&)
      {
         ss << method_name << " (no help available)\n";
      }
   }
   return ss.str();
}

string wallet_api::gethelp( const string& method )const
{
   fc::api<wallet_api> tmp;
   std::stringstream ss;
   ss << "\n";

   string doxygenHelpString = my->method_documentation.get_detailed_description(method);
   if (!doxygenHelpString.empty())
      ss << doxygenHelpString << "\n";

   if( method == "import_key" )
   {
      ss << "usage: import_key ACCOUNT_NAME_OR_ID  WIF_PRIVATE_KEY\n\n";
      ss << "example: import_key \"1.3.11\" 5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3\n";
      ss << "example: import_key \"usera\" 5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3\n";
   }
   else if( method == "transfer" )
   {
      ss << "usage: transfer FROM TO AMOUNT SYMBOL \"memo\" BROADCAST\n\n";
      ss << "example: transfer \"1.3.11\" \"1.3.4\" 1000.03 CORE \"memo\" true\n";
      ss << "example: transfer \"usera\" \"userb\" 1000.123 CORE \"memo\" true\n";
   }
   else if( method == "create_account_with_brain_key" )
   {
      ss << "usage: create_account_with_brain_key BRAIN_KEY ACCOUNT_NAME REGISTRAR REFERRER BROADCAST\n\n";
      ss << "example: create_account_with_brain_key "
         << "\"my really long brain key\" \"newaccount\" \"1.3.11\" \"1.3.11\" true\n";
      ss << "example: create_account_with_brain_key "
         << "\"my really long brain key\" \"newaccount\" \"someaccount\" \"otheraccount\" true\n";
      ss << "\n";
      ss << "This method should be used if you would like the wallet to generate new keys derived from the "
         << "brain key.\n";
      ss << "The BRAIN_KEY will be used as the owner key, and the active key will be derived from the BRAIN_KEY.  "
         << "Use\n";
      ss << "register_account if you already know the keys you know the public keys that you would like to "
         << "register.\n";

   }
   else if( method == "register_account" )
   {
      ss << "usage: register_account ACCOUNT_NAME OWNER_PUBLIC_KEY ACTIVE_PUBLIC_KEY REGISTRAR "
         << "REFERRER REFERRER_PERCENT BROADCAST\n\n";
      ss << "example: register_account \"newaccount\" \"CORE6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV\" "
         << "\"CORE6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV\" \"1.3.11\" \"1.3.11\" 50 true\n";
      ss << "\n";
      ss << "Use this method to register an account for which you do not know the private keys.";
   }
   else if( method == "create_asset" )
   {
      ss << "usage: ISSUER SYMBOL PRECISION_DIGITS OPTIONS BITASSET_OPTIONS BROADCAST\n\n";
      ss << "PRECISION_DIGITS: the number of digits after the decimal point\n\n";
      ss << "Example value of OPTIONS: \n";
      ss << fc::json::to_pretty_string( graphene::chain::asset_options() );
      ss << "\nExample value of BITASSET_OPTIONS: \n";
      ss << fc::json::to_pretty_string( graphene::chain::bitasset_options() );
      ss << "\nBITASSET_OPTIONS may be null\n";
   }
   else if (doxygenHelpString.empty())
      ss << "No help defined for method " << method << "\n";

   return ss.str();
}

bool wallet_api::load_wallet_file( const string& wallet_filename )const
{
   return my->load_wallet_file( wallet_filename );
}

void wallet_api::quit()const
{
   my->quit();
}

void wallet_api::save_wallet_file( const string& wallet_filename )const
{
   my->save_wallet_file( wallet_filename );
}

std::map< string, std::function< string( const fc::variant&, const fc::variants& ) >, std::less<> >
      wallet_api::get_result_formatters() const
{
   return my->get_result_formatters();
}

bool wallet_api::is_locked()const
{
   return my->is_locked();
}
bool wallet_api::is_new()const
{
   return my->_wallet.cipher_keys.size() == 0;
}

void wallet_api::encrypt_keys()const
{
   my->encrypt_keys();
}

void wallet_api::lock()const
{ try {
   FC_ASSERT( !is_locked() );
   encrypt_keys();
   for( auto key : my->_keys )
      key.second = key_to_wif(fc::ecc::private_key());
   my->_keys.clear();
   my->_checksum = fc::sha512();
   my->self.lock_changed(true);
} FC_CAPTURE_AND_RETHROW() }

void wallet_api::unlock( const string& password )const
{ try {
   FC_ASSERT(password.size() > 0);
   auto pw = fc::sha512::hash(password.c_str(), password.size());
   vector<char> decrypted = fc::aes_decrypt(pw, my->_wallet.cipher_keys);
   auto pk = fc::raw::unpack<plain_keys>(decrypted);
   FC_ASSERT(pk.checksum == pw);
   my->_keys = std::move(pk.keys);
   my->_checksum = pk.checksum;
   my->self.lock_changed(false);
} FC_CAPTURE_AND_RETHROW() }

void wallet_api::set_password( const string& password )const
{
   if( !is_new() )
      FC_ASSERT( !is_locked(), "The wallet must be unlocked before the password can be set" );
   my->_checksum = fc::sha512::hash( password.c_str(), password.size() );
   lock();
}

vector< signed_transaction > wallet_api::import_balance(
      const string& name_or_id,
      const vector<string>& wif_keys,
      bool broadcast )const
{
   return my->import_balance( name_or_id, wif_keys, broadcast );
}

map<public_key_type, string> wallet_api::dump_private_keys()const
{
   FC_ASSERT(!is_locked());
   return my->_keys;
}

signed_transaction wallet_api::upgrade_account( const string& name, bool broadcast )const
{
   return my->upgrade_account(name,broadcast);
}

signed_transaction wallet_api::sell_asset( const string& seller_account,
                                           const string& amount_to_sell,
                                           const string& symbol_to_sell,
                                           const string& min_to_receive,
                                           const string& symbol_to_receive,
                                           uint32_t expiration,
                                           bool   fill_or_kill,
                                           bool   broadcast )const
{
   return my->sell_asset(seller_account, amount_to_sell, symbol_to_sell, min_to_receive,
                         symbol_to_receive, expiration, fill_or_kill, broadcast);
}

signed_transaction wallet_api::borrow_asset( const string& seller_name, const string& amount_to_sell,
                                             const string& asset_symbol, const string& amount_of_collateral,
                                             bool broadcast )const
{
   FC_ASSERT(!is_locked());
   return my->borrow_asset_ext( seller_name, amount_to_sell, asset_symbol, amount_of_collateral, {}, broadcast );
}

signed_transaction wallet_api::borrow_asset_ext( const string& seller_name, const string& amount_to_sell,
                                                 const string& asset_symbol, const string& amount_of_collateral,
                                                 const call_order_update_operation::extensions_type& extensions,
                                                 bool broadcast )const
{
   FC_ASSERT(!is_locked());
   return my->borrow_asset_ext(seller_name, amount_to_sell, asset_symbol,
                               amount_of_collateral, extensions, broadcast);
}

signed_transaction wallet_api::cancel_order( const limit_order_id_type& order_id, bool broadcast ) const
{
   FC_ASSERT(!is_locked());
   return my->cancel_order(order_id, broadcast);
}

memo_data wallet_api::sign_memo( const string& from, const string& to, const string& memo )const
{
   FC_ASSERT(!is_locked());
   return my->sign_memo(from, to, memo);
}

string wallet_api::read_memo( const memo_data& memo )const
{
   FC_ASSERT(!is_locked());
   return my->read_memo(memo);
}

signed_message wallet_api::sign_message( const string& signer, const string& message )const
{
   FC_ASSERT(!is_locked());
   return my->sign_message(signer, message);
}

bool wallet_api::verify_message( const string& message, const string& account, int32_t block, const string& msg_time,
                                 const fc::ecc::compact_signature& sig )const
{
   return my->verify_message( message, account, block, msg_time, sig );
}

/** Verify a message signed with sign_message
 *
 * @param message the signed_message structure containing message, meta data and signature
 * @return true if signature matches
 */
bool wallet_api::verify_signed_message( const signed_message& message )const
{
   return my->verify_signed_message( message );
}

/** Verify a message signed with sign_message, in its encapsulated form.
 *
 * @param message the complete encapsulated message string including separators and line feeds
 * @return true if signature matches
 */
bool wallet_api::verify_encapsulated_message( const string& message )const
{
   return my->verify_encapsulated_message( message );
}


string wallet_api::get_key_label( const public_key_type& key )const
{
   auto key_itr   = my->_wallet.labeled_keys.get<by_key>().find(key);
   if( key_itr != my->_wallet.labeled_keys.get<by_key>().end() )
      return key_itr->label;
   return string();
}

string wallet_api::get_private_key( const public_key_type& pubkey )const
{
   return key_to_wif( my->get_private_key( pubkey ) );
}

public_key_type  wallet_api::get_public_key( const string& label )const
{
   try { return fc::variant(label, 1).as<public_key_type>( 1 ); } catch ( ... ){}

   auto key_itr   = my->_wallet.labeled_keys.get<by_label>().find(label);
   if( key_itr != my->_wallet.labeled_keys.get<by_label>().end() )
      return key_itr->key;
   // RP5: dual-key stealth address labels resolve to the view pub (identity).
   for( const auto& r : my->_wallet.stealth_addresses )
      if( r.label == label )
         return r.view_pub;
   return public_key_type();
}

bool               wallet_api::set_key_label( const public_key_type& key, const string& label )const
{
   auto result = my->_wallet.labeled_keys.insert( key_label{label,key} );
   if( result.second  ) return true;

   auto key_itr   = my->_wallet.labeled_keys.get<by_key>().find(key);
   auto label_itr = my->_wallet.labeled_keys.get<by_label>().find(label);
   if( label_itr == my->_wallet.labeled_keys.get<by_label>().end() )
   {
      if( key_itr != my->_wallet.labeled_keys.get<by_key>().end() )
         return my->_wallet.labeled_keys.get<by_key>().modify( key_itr, [&]( key_label& obj ){ obj.label = label; } );
   }
   return false;
}
map<string, public_key_type, std::less<>> wallet_api::get_blind_accounts()const
{
   map<string, public_key_type, std::less<>> result;
   for( const auto& item : my->_wallet.labeled_keys )
      result[item.label] = item.key;
   return result;
}
map<string, public_key_type, std::less<>> wallet_api::get_my_blind_accounts()const
{
   FC_ASSERT( !is_locked() );
   map<string, public_key_type, std::less<>> result;
   for( const auto& item : my->_wallet.labeled_keys )
   {
      if( my->_keys.find(item.key) != my->_keys.end() )
         result[item.label] = item.key;
   }
   return result;
}

public_key_type    wallet_api::create_blind_account( const string& label, const string& p_brain_key  )const
{
   FC_ASSERT( !is_locked() );

   auto label_itr = my->_wallet.labeled_keys.get<by_label>().find(label);
   if( label_itr !=  my->_wallet.labeled_keys.get<by_label>().end() )
      FC_ASSERT( !"Key with label already exists" );
   auto brain_key = fc::trim_and_normalize_spaces( p_brain_key );
   auto secret = fc::sha256::hash( brain_key.c_str(), brain_key.size() );
   auto priv_key = fc::ecc::private_key::regenerate( secret );
   public_key_type pub_key  = priv_key.get_public_key();

   FC_ASSERT( set_key_label( pub_key, label ) );

   my->_keys[pub_key] = graphene::utilities::key_to_wif( priv_key );

   save_wallet_file();
   return pub_key;
}

vector<asset>   wallet_api::get_blind_balances( const string& key_or_label )const
{
   vector<asset> result;
   map<asset_id_type, share_type> balances;

   vector<commitment_type> used;

   auto pub_key = get_public_key( key_or_label );
   auto& to_asset_used_idx = my->_wallet.blind_receipts.get<by_to_asset_used>();
   auto start = to_asset_used_idx.lower_bound( std::make_tuple(pub_key,asset_id_type(0),false)  );
   auto end = to_asset_used_idx.lower_bound( std::make_tuple(pub_key,asset_id_type(uint32_t(0xffffffff)),true)  );
   // G1c decoy-fetch batching (BSIP-2 §1): collect candidate commitments,
   // then one RPC round-trip per chunk — never one per decoy (timing-link
   // defense: per-decoy fetch timing fingerprints the wallet's set).
   vector<commitment_type> candidates;
   flat_set<commitment_type> seen;
   for( auto itr = start; itr != end; ++itr )
      if( !itr->used && seen.insert( itr->commitment() ).second )
         candidates.push_back( itr->commitment() );
   // RP4: AuthKey receipts (to_key = one-time child) are invisible to the
   // indexed range above; match them via the rename-proof address_key link.
   for( const auto& r : my->_wallet.blind_receipts )
      if( !r.used && r.address_key == pub_key && seen.insert( r.commitment() ).second )
         candidates.push_back( r.commitment() );
   uint32_t batch = my->_blind_defaults.decoy_fetch_batch_size;
   if( batch == 0 ) batch = 1;
   flat_set<commitment_type> live;
   const size_t chunks = blind_batch_chunk_count( candidates.size(), batch );
   for( size_t c = 0; c < chunks; ++c )
   {
      const size_t off = c * batch;
      flat_set<commitment_type> chunk;
      for( size_t k = off; k < candidates.size() && k < off + batch; ++k )
         chunk.insert( candidates[k] );
      auto answer = my->_remote_db->get_blinded_balances( chunk );
      for( const auto& bal : answer )
         live.insert( bal.commitment );
   }
   for( const auto& c : candidates )
   {
      auto itr = my->_wallet.blind_receipts.get<by_commitment>().find( c );
      if( itr == my->_wallet.blind_receipts.get<by_commitment>().end() )
         continue;
      if( live.find( c ) != live.end() )
         balances[itr->amount.asset_id] += itr->amount.amount;
      else
         used.push_back( c );
   }
   for( const auto& u : used )
   {
      auto itr = my->_wallet.blind_receipts.get<by_commitment>().find( u );
      my->_wallet.blind_receipts.modify( itr, []( blind_receipt& r ){ r.used = true; } );
   }
   for( auto item : balances )
      result.push_back( asset( item.second, item.first ) );
   return result;
}

blind_confirmation wallet_api::transfer_from_blind( const string& from_blind_account_key_or_label,
                                                    const string& to_account_id_or_name,
                                                    const string& amount_in,
                                                    const string& symbol,
                                                    bool broadcast )const
{ try {
   transfer_from_blind_operation from_blind;


   auto fees  = my->_remote_db->get_global_properties().parameters.get_current_fees();
   fc::optional<asset_object> asset_obj = get_asset(symbol);
   FC_ASSERT(asset_obj.valid(), "Could not find asset matching ${asset}", ("asset", symbol));
   auto amount = asset_obj->amount_from_string(amount_in);

   from_blind.fee  = fees.calculate_fee( from_blind, asset_obj->options.core_exchange_rate );

   auto blind_in = asset_obj->amount_to_string( from_blind.fee + amount );


   auto conf = blind_transfer_help( from_blind_account_key_or_label,
                               from_blind_account_key_or_label,
                               blind_in, symbol, false, true/*to_temp*/ );
   FC_ASSERT( conf.outputs.size() > 0 );

   auto to_account = my->get_account( to_account_id_or_name );
   from_blind.to = to_account.id;
   from_blind.amount = amount;
   from_blind.blinding_factor = conf.outputs.back().decrypted_memo.blinding_factor;
   from_blind.inputs.push_back( {conf.outputs.back().decrypted_memo.commitment, authority() } );
   from_blind.fee  = fees.calculate_fee( from_blind, asset_obj->options.core_exchange_rate );

    // WPC-06: never dump the whole op -- transfer_from_blind_operation
    // carries blinding_factor. Log non-secret routing context only.
    idump( ("from_blind_spend")(from_blind.fee)(from_blind.amount)(from_blind.to) );
   conf.trx.operations.push_back(from_blind);
   ilog( "about to validate" );
   conf.trx.validate();

   ilog( "about to broadcast" );
   maybe_delay_blind_broadcast( broadcast ); // Task 6 choke point (BSIP-2 §1)
   conf.trx = sign_transaction( conf.trx, broadcast );

   if( broadcast && conf.outputs.size() == 2 ) {

       // Save the change
       blind_confirmation::output conf_output;
       blind_confirmation::output change_output = conf.outputs[0];

       // The wallet must have a private key for confirmation.to, this is used to decrypt the memo
       public_key_type from_key = get_public_key(from_blind_account_key_or_label);
       conf_output.confirmation.to = from_key;
       conf_output.confirmation.one_time_key = change_output.confirmation.one_time_key;
       conf_output.confirmation.encrypted_memo = change_output.confirmation.encrypted_memo;
       conf_output.confirmation_receipt = conf_output.confirmation;
       //try {
       receive_blind_transfer( conf_output.confirmation_receipt,
                               from_blind_account_key_or_label,
                               "@"+to_account.name );
       //} catch ( ... ){}
   }

   return conf;
} FC_CAPTURE_AND_RETHROW( (from_blind_account_key_or_label)(to_account_id_or_name)(amount_in)(symbol) ) }

blind_confirmation wallet_api::blind_transfer( const string& from_key_or_label,
                                               const string& to_key_or_label,
                                               const string& amount_in,
                                               const string& symbol,
                                               bool broadcast )const
{
   return blind_transfer_help( from_key_or_label, to_key_or_label, amount_in, symbol, broadcast, false );
}
blind_confirmation wallet_api::blind_transfer_help( const string& from_key_or_label,
                                                    const string& to_key_or_label,
                                                    const string& amount_in,
                                                    const string& symbol,
                                                    bool broadcast,
                                                    bool to_temp )const
{
   blind_confirmation confirm;
   try {

   FC_ASSERT( !is_locked() );
   public_key_type from_key = get_public_key(from_key_or_label);
   public_key_type to_key   = get_public_key(to_key_or_label);

   fc::optional<asset_object> asset_obj = get_asset(symbol);
   FC_ASSERT(asset_obj.valid(), "Could not find asset matching ${asset}", ("asset", symbol));

   blind_transfer_operation blind_tr;
   blind_tr.outputs.resize(2);

   auto fees  = my->_remote_db->get_global_properties().parameters.get_current_fees();

   auto amount = asset_obj->amount_from_string(amount_in);

   asset total_amount = asset_obj->amount(0);

   vector<fc::sha256> blinding_factors;

   //auto from_priv_key = my->get_private_key( from_key );

   blind_tr.fee  = fees.calculate_fee( blind_tr, asset_obj->options.core_exchange_rate );

   vector<commitment_type> used;

   auto& to_asset_used_idx = my->_wallet.blind_receipts.get<by_to_asset_used>();
   auto start = to_asset_used_idx.lower_bound( std::make_tuple(from_key,amount.asset_id,false)  );
   auto end = to_asset_used_idx.lower_bound( std::make_tuple(from_key,amount.asset_id,true)  );
   // Task 6 (BSIP-2 §1): enforce the optional N-block mix hold here, at
   // spend-input selection (consensus never sees wallet receipt age, so the
   // wallet is the only place the hold can live). Head height comes from the
   // node; unknown-age receipts (received_block == 0) are ineligible while
   // any hold is configured. Off (0) by default: no behavior change.
   const uint32_t min_mix = my->_blind_defaults.min_mix_blocks;
   uint32_t head_block = 0;
   if( min_mix > 0 )
      head_block = get_dynamic_global_properties().head_block_number;
   // RP4: merge indexed (to_key) + address_key matches in asset+unused scope.
   // Pointers into multi_index nodes stay valid across the post-loop modify
   // (node-based container; marking happens after selection, as before).
   vector<const blind_receipt*> scope;
   for( auto itr = start; itr != end; ++itr )
      scope.push_back( &*itr );
   for( const auto& r : my->_wallet.blind_receipts )
      if( !r.used && r.amount.asset_id == amount.asset_id && r.address_key == from_key )
      {
         bool dup = false;
         for( auto s : scope ) if( s->commitment() == r.commitment() ) { dup = true; break; }
         if( !dup ) scope.push_back( &r );
      }
   for( auto rp : scope )
   {
      const auto& rec = *rp;
      // RP5: watch-only tallies carry no spend authority — refuse to build a
      // spend from them (fail-closed at build; the tx could never authorize).
      FC_ASSERT( !( rec.control_authority == authority() ),
                 "Cannot spend watch-only receipt (tally only, no spend key)",
                 ("commitment",rec.commitment()) );
      if( !blind_receipt_mix_eligible( rec.received_block, head_block, min_mix ) )
      {
         continue; // too young (or unknown age): never spendable under a hold
      }
      auto result = my->_remote_db->get_blinded_balances( {rec.commitment() } );
      if( result.size() == 0 )
      {
         used.push_back( rec.commitment() );
      }
      else
      {
         blind_tr.inputs.push_back({rec.commitment(), rec.control_authority});
         blinding_factors.push_back( rec.data.blinding_factor );
         total_amount += rec.amount;

         if( total_amount >= amount + blind_tr.fee )
            break;
      }
   }
   for( const auto& u : used )
   {
      auto itr = my->_wallet.blind_receipts.get<by_commitment>().find( u );
      my->_wallet.blind_receipts.modify( itr, []( blind_receipt& r ){ r.used = true; } );
   }

   FC_ASSERT( total_amount >= amount+blind_tr.fee,
              "Insufficient Balance",
              ("available",total_amount)("amount",amount)("fee",blind_tr.fee) );

   // RP5: dual-key resolution — secret under ViewKey, AuthKey from SpendKey.
   // Single-key legs degenerate (same key for both).
   fc::ecc::public_key to_secret_base = to_key, to_auth_base = to_key;
   fc::ecc::public_key from_secret_base = from_key, from_auth_base = from_key;
   for( const auto& r : my->_wallet.stealth_addresses )
   {
      if( r.label == to_key_or_label ) { to_secret_base = r.view_pub; to_auth_base = r.spend_pub; }
      if( r.label == from_key_or_label ) { from_secret_base = r.view_pub; from_auth_base = r.spend_pub; }
   }

   auto one_time_key = fc::ecc::private_key::generate();
   auto secret       = one_time_key.get_shared_secret( to_secret_base );
   auto child        = fc::sha256::hash( secret );
   auto nonce        = fc::sha256::hash( one_time_key.get_secret() );
   auto blind_factor = fc::sha256::hash( child );

   auto from_secret  = one_time_key.get_shared_secret( from_secret_base );
   auto from_child   = fc::sha256::hash( from_secret );
   auto from_nonce   = fc::sha256::hash( nonce );

   auto change = total_amount - amount - blind_tr.fee;
   fc::sha256 change_blind_factor;
   fc::sha256 to_blind_factor;
   if( change.amount > 0 )
   {
       // WPC-06: blind_factor is secret -- log routing context only.
       idump(("to_blind_with_change")(amount)(change) );
      blinding_factors.push_back( blind_factor );
      change_blind_factor = fc::ecc::blind_sum( blinding_factors, blinding_factors.size() - 1 );
       // WPC-06: change_blind_factor is secret -- log amount only.
       wdump(("change_blind_computed")(change) );
   }
   else // change == 0
   {
      blind_tr.outputs.resize(1);
       blind_factor = fc::ecc::blind_sum( blinding_factors, blinding_factors.size() );
       // WPC-06: intermediate blind sum deleted (redundant with the
       // no-change marker below; the scalar itself is never logged).
      blinding_factors.push_back( blind_factor );
       // WPC-06: blind_factor is secret -- log routing context only.
       idump(("to_blind_no_change")(amount) );
   }
   fc::ecc::public_key from_pub_key = from_auth_base;
   fc::ecc::public_key to_pub_key = to_auth_base;

   blind_output to_out;
   to_out.owner       = to_temp ? authority() : authority( 1, public_key_type( to_pub_key.child( child ) ), 1 );
   to_out.commitment  = fc::ecc::blind( blind_factor, amount.amount.value );
    // WPC-06: blind_factor is secret -- the commitment is public
    // (on-chain) and is the only loggable part of this output.
    idump(("to_out.commitment")(to_out.commitment) );


   if( blind_tr.outputs.size() > 1 )
   {
      to_out.range_proof = fc::ecc::range_proof_sign( 0, to_out.commitment, blind_factor, nonce,
                                                      0, RANGE_PROOF_MANTISSA, amount.amount.value );

      blind_output change_out;
      change_out.owner       = authority( 1, public_key_type( from_pub_key.child( from_child ) ), 1 );
      change_out.commitment  = fc::ecc::blind( change_blind_factor, change.amount.value );
      change_out.range_proof = fc::ecc::range_proof_sign( 0, change_out.commitment, change_blind_factor, from_nonce,
                                                          0, RANGE_PROOF_MANTISSA, change.amount.value );
      blind_tr.outputs[1] = change_out;


      blind_confirmation::output conf_output;
      conf_output.label = from_key_or_label;
      conf_output.pub_key = from_key;
      conf_output.decrypted_memo.from = from_key;
      conf_output.decrypted_memo.amount = change;
      conf_output.decrypted_memo.blinding_factor = change_blind_factor;
      conf_output.decrypted_memo.commitment = change_out.commitment;
      conf_output.decrypted_memo.check   = from_secret._hash[0].value();
      conf_output.confirmation.one_time_key = one_time_key.get_public_key();
      conf_output.confirmation.to = public_key_type( from_pub_key.child( from_child ) ); // AuthKey for change too
      conf_output.confirmation.encrypted_memo =
            fc::aes_encrypt( from_secret, fc::raw::pack( conf_output.decrypted_memo ) );
      conf_output.auth = change_out.owner;
      conf_output.confirmation_receipt = conf_output.confirmation;
      change_out.stealth_memo = conf_output.confirmation;

      confirm.outputs.push_back( conf_output );
   }
   blind_tr.outputs[0] = to_out;

   blind_confirmation::output conf_output;
   conf_output.label = to_key_or_label;
   conf_output.pub_key = to_key;
   conf_output.decrypted_memo.from = from_key;
   conf_output.decrypted_memo.amount = amount;
   conf_output.decrypted_memo.blinding_factor = blind_factor;
   conf_output.decrypted_memo.commitment = to_out.commitment;
   conf_output.decrypted_memo.check   = secret._hash[0].value();
   conf_output.confirmation.one_time_key = one_time_key.get_public_key();
   conf_output.confirmation.to = public_key_type( to_pub_key.child( child ) ); // AuthKey, never address key
   conf_output.confirmation.encrypted_memo = fc::aes_encrypt( secret, fc::raw::pack( conf_output.decrypted_memo ) );
   conf_output.auth = to_out.owner;
   conf_output.confirmation_receipt = conf_output.confirmation;
   to_out.stealth_memo = conf_output.confirmation;

   confirm.outputs.push_back( conf_output );

   /** commitments must be in sorted order */
   std::sort( blind_tr.outputs.begin(), blind_tr.outputs.end(),
              [&]( const blind_output& a, const blind_output& b ){ return a.commitment < b.commitment; } );
   std::sort( blind_tr.inputs.begin(), blind_tr.inputs.end(),
              [&]( const blind_input& a, const blind_input& b ){ return a.commitment < b.commitment; } );

   confirm.trx.operations.emplace_back( std::move(blind_tr) );
   ilog( "validate before" );
   confirm.trx.validate();
   maybe_delay_blind_broadcast( broadcast ); // Task 6 choke point (BSIP-2 §1)
   confirm.trx = sign_transaction(confirm.trx, broadcast);

   if( broadcast )
   {
      for( const auto& out : confirm.outputs )
      {
         try { receive_blind_transfer( out.confirmation_receipt, from_key_or_label, "" ); } catch ( ... ){}
      }
   }

   return confirm;
   // WPC-R17-02: (confirm) removed from the capture below —
   // confirm.outputs[].decrypted_memo.blinding_factor holds freshly generated
   // blinds at this point, and fc::exception serializes captured args deep
   // into to_detail_string()/stderr on any later throw (validate/broadcast/sign).
} FC_CAPTURE_AND_RETHROW( (from_key_or_label)(to_key_or_label)(amount_in)(symbol)(broadcast) ) }



/*
 *  Transfers a public balance from @from to one or more blinded balances using a
 *  stealth transfer.
 */
blind_confirmation wallet_api::transfer_to_blind( const string& from_account_id_or_name,
                                                  const string& asset_symbol,
                                                  /* map from key or label to amount */
                                                  const vector<pair<string, string>>& to_amounts,
                                                  bool broadcast )const
{ try {
   FC_ASSERT( !is_locked() );
   idump((to_amounts));

   blind_confirmation confirm;
   account_object from_account = my->get_account(from_account_id_or_name);

   fc::optional<asset_object> asset_obj = get_asset(asset_symbol);
   FC_ASSERT(asset_obj, "Could not find asset matching ${asset}", ("asset", asset_symbol));

   transfer_to_blind_operation bop;
   bop.from   = from_account.id;

   vector<fc::sha256> blinding_factors;

   asset total_amount = asset_obj->amount(0);

    for( auto item : to_amounts )
    {
      auto one_time_key = fc::ecc::private_key::generate();

      // Resolution: existing single-key label/base58 key, else dual-key record.
      public_key_type to_key; // single-key address (degenerate view==spend)
      fc::optional<public_key_type> view_pub, spend_pub;
      {
         auto label_itr = my->_wallet.labeled_keys.get<by_label>().find( item.first );
         if( label_itr != my->_wallet.labeled_keys.get<by_label>().end() )
         {
            to_key = label_itr->key;
         }
         else
         {
            bool found_dual = false;
            for( const auto& r : my->_wallet.stealth_addresses )
            {
               if( r.label == item.first )
               {
                  view_pub  = r.view_pub;
                  spend_pub = r.spend_pub;
                  found_dual = true;
                  break;
               }
            }
            if( !found_dual )
               to_key = get_public_key( item.first ); // base58 fallback (throws if unknown)
         }
      }

      // secret + AuthKey: dual-key encrypts under ViewKey, AuthKey from SpendKey_pub;
      // single-key is the degenerate case (same key material, RP2 helper path).
      // (Copy-init is the proven protocol→ecc conversion in this file; explicit
      // functional casts are ambiguous — do not "simplify" these two lines.)
      public_key_type sb = view_pub.valid() ? *view_pub : to_key;
      public_key_type ab = view_pub.valid() ? *spend_pub : to_key;
      fc::ecc::public_key secret_base = sb;
      fc::ecc::public_key auth_base = ab;
      fc::sha256 child;
      auto secret = one_time_key.get_shared_secret( secret_base );
      child = fc::sha256::hash( secret );
      fc::ecc::public_key auth_pub = auth_base.child( child );
      auto nonce        = fc::sha256::hash( one_time_key.get_secret() );
      auto blind_factor = fc::sha256::hash( child );

      blinding_factors.push_back( blind_factor );

      auto amount = asset_obj->amount_from_string(item.second);
      total_amount += amount;

      blind_output out;
      out.owner       = authority( 1, public_key_type( auth_pub ), 1 );
      out.commitment  = fc::ecc::blind( blind_factor, amount.amount.value );
      if( to_amounts.size() > 1 )
         out.range_proof = fc::ecc::range_proof_sign( 0, out.commitment, blind_factor, nonce,
                                                       0, RANGE_PROOF_MANTISSA, amount.amount.value );

      blind_confirmation::output conf_output;
      conf_output.label = item.first;
      conf_output.pub_key = view_pub.valid() ? *view_pub : to_key;
      conf_output.decrypted_memo.amount = amount;
      conf_output.decrypted_memo.blinding_factor = blind_factor;
      conf_output.decrypted_memo.commitment = out.commitment;
      conf_output.decrypted_memo.check   = secret._hash[0].value();
      conf_output.confirmation.one_time_key = one_time_key.get_public_key();
      conf_output.confirmation.to = public_key_type( auth_pub ); // AuthKey (RP4 + dual-key)
      conf_output.confirmation.encrypted_memo =
            fc::aes_encrypt( secret, fc::raw::pack( conf_output.decrypted_memo ) );
      conf_output.confirmation_receipt = conf_output.confirmation;
      out.stealth_memo = conf_output.confirmation; // op39 wire carrier (RP4)

      confirm.outputs.push_back( conf_output );
      bop.outputs.push_back(out);
    }
   bop.amount          = total_amount;
   bop.blinding_factor = fc::ecc::blind_sum( blinding_factors, blinding_factors.size() );

   /** commitments must be in sorted order */
   std::sort( bop.outputs.begin(), bop.outputs.end(),
              [&]( const blind_output& a, const blind_output& b ){ return a.commitment < b.commitment; } );

   confirm.trx.operations.push_back( bop );
   my->set_operation_fees( confirm.trx, my->_remote_db->get_global_properties().parameters.get_current_fees());
   confirm.trx.validate();
   maybe_delay_blind_broadcast( broadcast ); // Task 6 choke point (BSIP-2 §1)
   confirm.trx = sign_transaction(confirm.trx, broadcast);

   if( broadcast )
   {
      for( const auto& out : confirm.outputs )
      {
         try {
            receive_blind_transfer( out.confirmation_receipt, "@"+from_account.name, "from @"+from_account.name );
         } catch ( ... ){}
      }
   }

   return confirm;
} FC_CAPTURE_AND_RETHROW( (from_account_id_or_name)(asset_symbol)(to_amounts) ) }

blind_receipt wallet_api::receive_blind_transfer( const string& confirmation_receipt,
                                                  const string& opt_from, const string& opt_memo )const
{
   FC_ASSERT( !is_locked() );
   stealth_confirmation conf(confirmation_receipt);
   FC_ASSERT( conf.to );

   blind_receipt result;
   result.conf = conf;

   auto to_priv_key_itr = my->_keys.find( *conf.to );
   fc::optional<fc::ecc::private_key> to_priv_key_opt;
   public_key_type address_key; // wallet address this output was sent to (== to_key for legacy)
   // RP5 dual-key state: when a record matches, auth derives from spend_priv
   // (hot) or is absent (watch-only tally).
   fc::optional<fc::ecc::private_key> dual_auth_opt;
   bool dual_matched = false;
   if( to_priv_key_itr != my->_keys.end() )
   {
      // LEGACY compat (spec §7.2): old receipts name the ADDRESS key in `to`.
      to_priv_key_opt = wif_to_key( to_priv_key_itr->second );
      FC_ASSERT( to_priv_key_opt, "Corrupt key for receiver" );
      address_key = *conf.to;
   }
   else
   {
      // RP5: dual-key records — match under ViewKey, AuthKey from SpendKey.
      // address_key is the view pub (receipt linkage identity).
      for( const auto& r : my->_wallet.stealth_addresses )
      {
         auto v_itr = my->_keys.find( r.view_pub );
         if( v_itr == my->_keys.end() ) continue;
         auto view_priv = wif_to_key( v_itr->second );
         if( !view_priv ) continue;
         fc::optional<fc::ecc::private_key> spend_priv;
         if( !r.watch_only )
         {
            auto s_itr = my->_keys.find( r.spend_pub );
            if( s_itr != my->_keys.end() )
               spend_priv = wif_to_key( s_itr->second );
         }
         stealth_recognition rec;
         rec.one_time_key = conf.one_time_key;
         rec.to = *conf.to;
         rec.encrypted_memo = conf.encrypted_memo;
         auto m = try_recognition( rec, *view_priv, r.spend_pub, spend_priv );
         if( m.valid() && verify_memo_commitment( m->memo ) )
         {
            to_priv_key_opt = view_priv; // secret/child derive from view below
            if( m->has_auth )
               dual_auth_opt = m->auth_priv;
            dual_matched = true;
            address_key = r.view_pub;
            break;
         }
      }
   }
   if( !to_priv_key_opt )
   {
      // FIXED receipts: `to` is the AuthKey = address.child(sha256(shared)).
      // Scan the wallet's address keys; one ECDH + compare per candidate.
      for( const auto& kv : my->_keys )
      {
         auto cand = wif_to_key( kv.second );
         if( !cand ) continue;
         auto s = cand->get_shared_secret( conf.one_time_key );
         auto c = fc::sha256::hash( s );
         fc::ecc::public_key cand_pub = kv.first; // public_key_type → ecc
         if( public_key_type( cand_pub.child( c ) ) == *conf.to )
         {
            to_priv_key_opt = cand;
            address_key = kv.first;
            break;
         }
      }
      FC_ASSERT( to_priv_key_opt, "No private key for receiver (scan miss)", ("conf",conf) );
   }
   auto to_priv_key = *to_priv_key_opt;

   auto secret       = to_priv_key.get_shared_secret( conf.one_time_key );
   auto child        = fc::sha256::hash( secret );

   // RP5: dual-hot receipts authorize via spend-derived auth, not the view key.
   fc::ecc::private_key child_priv_key;
   if( dual_matched )
   {
      FC_ASSERT( dual_auth_opt.valid(),
                 "Watch-only address matched: cannot derive spend authority (tally via scan_stealth_recognitions)" );
      child_priv_key = *dual_auth_opt;
   }
   else
      child_priv_key = to_priv_key.child( child );
   //auto blind_factor = fc::sha256::hash( child );

   auto plain_memo = fc::aes_decrypt( secret, conf.encrypted_memo );
   auto memo = fc::raw::unpack<stealth_confirmation::memo_data>( plain_memo );

   result.to_key   = *conf.to;
   result.to_label = get_key_label( address_key ); // address label, not AuthKey's (RP4 display)
   result.address_key = address_key; // rename-proof linkage for balance/spend/history (RP4)
   if( memo.from )
   {
      result.from_key = *memo.from;
      result.from_label = get_key_label( result.from_key );
      if( result.from_label == string() )
      {
         result.from_label = opt_from;
         set_key_label( result.from_key, result.from_label );
      }
   }
   else
   {
      result.from_label = opt_from;
   }
   result.amount = memo.amount;
   result.memo = opt_memo;

   // confirm the amount matches the commitment (verify the blinding factor)
   auto commitment_test = fc::ecc::blind( memo.blinding_factor, memo.amount.amount.value );
   FC_ASSERT( fc::ecc::verify_sum( {commitment_test}, {memo.commitment}, 0 ) );

   blind_balance bal;
   bal.amount = memo.amount;
   bal.to     = *conf.to;
   if( memo.from ) bal.from   = *memo.from;
   bal.one_time_key = conf.one_time_key;
   bal.blinding_factor = memo.blinding_factor;
   bal.commitment = memo.commitment;
   bal.used = false;

   auto child_pubkey = child_priv_key.get_public_key();
   auto owner = authority(1, public_key_type(child_pubkey), 1);
   result.control_authority = owner;
   result.data = memo;

   auto child_key_itr = owner.key_auths.find( child_pubkey );
   if( child_key_itr != owner.key_auths.end() )
      my->_keys[child_key_itr->first] = key_to_wif( child_priv_key );

   // my->_wallet.blinded_balances[memo.amount.asset_id][bal.to].push_back( bal );

   result.date = fc::time_point::now();
   // Task 6 (BSIP-2 §1): record the chain height with the receipt so
   // min_mix_blocks input selection can enforce an N-block hold. Best
   // effort: 0 (unknown age) when offline or unreachable — and unknown-age
   // receipts are ineligible while any hold is configured (fail-closed).
   try {
      result.received_block = get_dynamic_global_properties().head_block_number;
   } catch( const fc::exception& ) {
      result.received_block = 0;
   }
   my->_wallet.blind_receipts.insert( result );
   my->_keys[child_pubkey] = key_to_wif( child_priv_key );

   save_wallet_file();

   return result;
}

public_key_type wallet_api::create_stealth_address( const string& label,
                                                    const string& brain_key,
                                                    uint32_t index )const
{ try {
   FC_ASSERT( !is_locked() );
   FC_ASSERT( my->_wallet.stealth_addresses.end()
              == std::find_if( my->_wallet.stealth_addresses.begin(), my->_wallet.stealth_addresses.end(),
                               [&]( const stealth_address_record& r ){ return r.label == label; } ),
              "Stealth address label already exists" );
   auto keys = derive_stealth_address_keys( brain_key, index );
   stealth_address_record rec;
   rec.label = label;
   rec.view_pub = public_key_type( keys.view_pub );
   rec.spend_pub = public_key_type( keys.spend_pub );
   rec.watch_only = false;
   my->_wallet.stealth_addresses.push_back( rec );
   // Hot: persist both privkeys in the encrypted _keys map (address-key grade).
   auto vlabel = label + ".view";
   auto slabel = label + ".spend";
   FC_ASSERT( set_key_label( public_key_type( keys.view_pub ), vlabel ) );
   FC_ASSERT( set_key_label( public_key_type( keys.spend_pub ), slabel ) );
   my->_keys[ public_key_type( keys.view_pub ) ]  = graphene::utilities::key_to_wif( keys.view_priv );
   my->_keys[ public_key_type( keys.spend_pub ) ] = graphene::utilities::key_to_wif( keys.spend_priv );
   save_wallet_file();
   return rec.view_pub;
} FC_CAPTURE_AND_RETHROW( (label)(index) ) }

vector<stealth_address_record> wallet_api::import_stealth_view_key(
      const string& label, const string& view_wif,
      const public_key_type& spend_pub )const
{ try {
   FC_ASSERT( !is_locked() );
   auto view_priv = wif_to_key( view_wif );
   FC_ASSERT( view_priv, "Invalid view WIF" );
   stealth_address_record rec;
   rec.label = label;
   rec.view_pub = public_key_type( view_priv->get_public_key() );
   rec.spend_pub = spend_pub;
   rec.watch_only = true;
   my->_wallet.stealth_addresses.push_back( rec );
   auto vlabel = label + ".view";
   FC_ASSERT( set_key_label( rec.view_pub, vlabel ) );
   my->_keys[ rec.view_pub ] = view_wif;
   save_wallet_file();
   return my->_wallet.stealth_addresses;
} FC_CAPTURE_AND_RETHROW( (label) ) }

vector<stealth_address_record> wallet_api::get_stealth_addresses()const
{ return my->_wallet.stealth_addresses; }

vector<blind_receipt> wallet_api::scan_stealth_recognitions(
      uint32_t from_block, uint32_t to_block )const
{ try {
   FC_ASSERT( !is_locked() );
   auto entries = my->_remote_db->get_stealth_recognitions( from_block, to_block );
   const auto& by_cmt = my->_wallet.blind_receipts.get<by_commitment>();
   vector<blind_receipt> fresh;
   for( const auto& e : entries )
   {
      if( by_cmt.find( e.commitment ) != by_cmt.end() )
         continue; // idempotent
      const auto& rec = e.recognition;
      fc::optional<stealth_match_result> m;
      public_key_type matched_address;
      string matched_label;
      // Dual-key records first.
      for( const auto& r : my->_wallet.stealth_addresses )
      {
         auto v_itr = my->_keys.find( r.view_pub );
         if( v_itr == my->_keys.end() ) continue;
         auto view_priv = wif_to_key( v_itr->second );
         if( !view_priv ) continue;
         fc::optional<fc::ecc::private_key> spend_priv;
         auto s_itr = my->_keys.find( r.spend_pub );
         if( !r.watch_only && s_itr != my->_keys.end() )
            spend_priv = wif_to_key( s_itr->second );
         m = try_recognition( rec, *view_priv, r.spend_pub, spend_priv );
         if( m.valid() ) { matched_address = r.view_pub; matched_label = r.label; break; }
      }
      // Degenerate single-key scan over remaining _keys (blind accounts).
      if( !m.valid() )
      {
         for( const auto& kv : my->_keys )
         {
            auto cand = wif_to_key( kv.second );
            if( !cand ) continue;
            m = try_recognition_single_key( rec, *cand );
            if( m.valid() ) { matched_address = kv.first; matched_label = get_key_label( kv.first ); break; }
         }
      }
      if( !m.valid() )
         continue;
      FC_ASSERT( verify_memo_commitment( m->memo ), "Memo failed commitment re-derivation" );
      blind_receipt br;
      br.conf.one_time_key = rec.one_time_key;
      br.conf.to = rec.to;
      br.conf.encrypted_memo = rec.encrypted_memo;
      br.to_key = rec.to;
      br.to_label = matched_label;
      br.address_key = matched_address;
      br.amount = m->memo.amount;
      br.data = m->memo;
      br.control_authority = m->has_auth
            ? authority( 1, public_key_type( m->auth_priv.get_public_key() ), 1 )
            : authority();
      br.date = fc::time_point::now();
      try { br.received_block = get_dynamic_global_properties().head_block_number; }
      catch( const fc::exception& ) { br.received_block = 0; }
      br.used = false;
      // Hot path only: persist auth child key (address-key grade). Watch-only
      // leaves has_auth false — tally receipt, no spend material stored.
      if( m->has_auth )
         my->_keys[ public_key_type( m->auth_priv.get_public_key() ) ] = key_to_wif( m->auth_priv );
      my->_wallet.blind_receipts.insert( br );
      fresh.push_back( br );
   }
   if( !fresh.empty() )
      save_wallet_file();
   return fresh;
} FC_CAPTURE_AND_RETHROW( (from_block)(to_block) ) }

vector<blind_receipt> wallet_api::blind_history( const string& key_or_account )const
{
   vector<blind_receipt> result;
   auto pub_key = get_public_key( key_or_account );

   if( pub_key == public_key_type() )
      return vector<blind_receipt>();

   for( auto& r : my->_wallet.blind_receipts )
   {
      // RP4: match AuthKey receipts via the address_key link as well.
      if( r.from_key == pub_key || r.to_key == pub_key || r.address_key == pub_key )
         result.push_back( r );
   }
   std::sort( result.begin(), result.end(),
              [&]( const blind_receipt& a, const blind_receipt& b ){ return a.date > b.date; } );
   return result;
}

order_book wallet_api::get_order_book( const string& base, const string& quote, uint32_t limit )const
{
   return( my->_remote_db->get_order_book( base, quote, limit ) );
}

// ---------------------------------------------------------------------------
// G1c blind-by-default + network hygiene (BSIP-2 §2).
//
// Behavior contract (binding spec for the browser wallet lives in
// libraries/wallet/BLIND_DEFAULTS_CONTRACT.md):
// - blind_by_default routes transfer_default to the blind leg;
// - decoy-fetch batching: one RPC round-trip per chunk, never per decoy;
// - minimum broadcast delay on blind paths when broadcast=true;
// - fail-closed addressing: blind routing never silently falls back.
// ---------------------------------------------------------------------------

blind_transfer_defaults wallet_api::get_blind_defaults()const
{
   return my->_blind_defaults;
}

void wallet_api::set_blind_by_default( bool blind_by_default )const
{
   my->_blind_defaults.blind_by_default = blind_by_default;
}

void wallet_api::set_blind_defaults( const blind_transfer_defaults& defaults )const
{
   FC_ASSERT( defaults.decoy_fetch_batch_size > 0,
              "decoy fetch batch size must be positive" );
   my->_blind_defaults = defaults;
}

void wallet_api::blind_broadcast_delay()const
{
   uint32_t secs = my->_blind_defaults.min_broadcast_delay_sec;
   if( secs == 0 )
   {
      wlog( "blind broadcast delay disabled by explicit wallet setting" );
      return;
   }
   ilog( "blind broadcast delay: waiting ${s}s before broadcast (timing defense)",
         ("s", secs) );
   // G3-05: injected sleep in tests, real fc::usleep in production.
   if( my->_blind_sleep )
      my->_blind_sleep( secs );
   else
      fc::usleep( fc::seconds( secs ) );
}

void wallet_api::maybe_delay_blind_broadcast( bool broadcast )const
{
   // Task 6 choke point: one call per blind broadcast (including retries —
   // a retry is a new broadcast). broadcast=false paths (build/sign-only)
   // never sleep: there is no propagation timing to defend.
   if( broadcast )
      blind_broadcast_delay();
}

void wallet_api::set_blind_sleep_hook( std::function<void(uint32_t)> hook )const
{
   my->_blind_sleep = std::move( hook );
}

void wallet_api::set_unlocked_for_tests()const
{
   // White-box by design (see header): _checksum is the sole is_locked
   // input. A fixed nonzero sentinel keeps the marker recognizable in
   // dumps; it carries no key material and unlocks no funds.
   my->_checksum = fc::sha512::hash( "g1-unit-test-unlocked", 21 );
}

signed_transaction wallet_api::transfer_default( const string& from,
                                                 const string& to_key_or_account,
                                                 const string& amount,
                                                 const string& asset_symbol,
                                                 const string& memo,
                                                 bool transparent_opt_out,
                                                 bool broadcast )const
{ try {
   FC_ASSERT( !is_locked() );
   if( !transparent_opt_out && my->_blind_defaults.blind_by_default )
   {
      FC_ASSERT( memo.empty(),
                 "blind legs carry no memo: clear the memo or pass transparent_opt_out=true" );
      // Fail closed: a public account name as recipient is never blind-routed
      // (the output would link to a known account key at the sender's sole
      // discretion). Blind routing needs a blind key or label.
      bool is_account = true;
      try { get_account_id( to_key_or_account ); } catch ( ... ) { is_account = false; }
      FC_ASSERT( !is_account,
                 "recipient '${r}' is a public account: blind routing needs a blind key "
                 "or label — pass transparent_opt_out=true for the compliant path",
                 ("r", to_key_or_account) );
      public_key_type to_key = get_public_key( to_key_or_account );
      FC_ASSERT( to_key != public_key_type(),
                 "unknown blind recipient '${r}': register the blind key/label first, "
                 "or pass transparent_opt_out=true", ("r", to_key_or_account) );
       // The blind leg below broadcasts through transfer_to_blind, which
       // invokes the Task-6 delay choke point (maybe_delay_blind_broadcast)
       // when broadcast=true — this path never bypasses the timing defense,
       // and never double-delays (the choke lives in transfer_to_blind only).
       blind_confirmation conf = transfer_to_blind( from, asset_symbol,
                                                    {{ to_key_or_account, amount }},
                                                    broadcast );
       return conf.trx;
    }
    return transfer( from, to_key_or_account, amount, asset_symbol, memo, broadcast );
} FC_CAPTURE_AND_RETHROW( (from)(to_key_or_account)(amount)(asset_symbol)(transparent_opt_out)(broadcast) ) }

signed_transaction wallet_api::stealth_pool_swap(
   const stealth_pool_exchange_operation& op, bool broadcast )const
{ try {
   // Fail-closed shape check BEFORE any timing defense: a malformed op
   // throws here and never reaches the delay choke (nor the network).
   op.validate();
   signed_transaction tx;
   tx.operations = { operation( op ) };
   // Task-6 delay choke point (BSIP-2 §1), now covering op109: sleeps
   // exactly when broadcast=true (a 0 delay setting is an explicit off).
   maybe_delay_blind_broadcast( broadcast );
   // Fee payer is TEMP (threshold-0): no signing key is required for the
   // op itself; sign_transaction envelopes (+ broadcasts) the tx.
   return sign_transaction( tx, broadcast );
} FC_CAPTURE_AND_RETHROW( (op)(broadcast) ) }

// custom operations
signed_transaction wallet_api::account_store_map( const string& account, const string& catalog, bool is_to_remove,
      const flat_map<string, optional<string>>& key_values, bool broadcast )const
{
   return my->account_store_map(account, catalog, is_to_remove, key_values, broadcast);
}

vector<account_storage_object> wallet_api::get_account_storage( const string& account, const string& catalog )const
{ try {
   return my->_custom_operations->get_storage_info(account, catalog);
} FC_CAPTURE_AND_RETHROW( (account)(catalog) ) }

signed_block_with_info::signed_block_with_info( const signed_block& block )
   : signed_block( block ),
     block_id { id() },
     signing_key { signee() }
{
   transaction_ids.reserve( transactions.size() );
   for( const processed_transaction& tx : transactions )
      transaction_ids.push_back( tx.id() );
}

vesting_balance_object_with_info::vesting_balance_object_with_info(
      const vesting_balance_object& vbo,
      const fc::time_point_sec& now )
   : vesting_balance_object( vbo ),
     allowed_withdraw { get_allowed_withdraw( now ) },
     allowed_withdraw_time { now }
{
}

} } // graphene::wallet

namespace fc {
   void to_variant( const account_multi_index_type& accts, variant& vo, uint32_t max_depth )
   {
      to_variant( std::vector<account_object>(accts.begin(), accts.end()), vo, max_depth );
   }

   void from_variant( const variant& var, account_multi_index_type& vo, uint32_t max_depth )
   {
      const std::vector<account_object>& v = var.as<std::vector<account_object>>( max_depth );
      vo = account_multi_index_type(v.begin(), v.end());
   }
}
