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
#include <graphene/chain/types.hpp>
#include <graphene/db/generic_index.hpp>
#include <graphene/protocol/asset_ops.hpp>

#include <boost/multi_index/composite_key.hpp>

/**
 * @defgroup prediction_market Prediction Market
 *
 * A prediction market is a specialized BitAsset such that total debt and total collateral are always equal amounts
 * (although asset IDs differ). No margin calls or force settlements may be performed on a prediction market asset. A
 * prediction market is globally settled by the issuer after the event being predicted resolves, thus a prediction
 * market must always have the @c global_settle permission enabled. The maximum price for global settlement or short
 * sale of a prediction market asset is 1-to-1.
 */

namespace graphene { namespace chain {
   class asset_bitasset_data_object;

   /**
    *  @brief tracks the asset information that changes frequently
    *  @ingroup object
    *  @ingroup implementation
    *
    *  Because the asset_object is very large it doesn't make sense to save an undo state
    *  for all of the parameters that never change.   This object factors out the parameters
    *  of an asset that change in almost every transaction that involves the asset.
    *
    *  This object exists as an implementation detail and its ID should never be referenced by
    *  a blockchain operation.
    */
   class asset_dynamic_data_object : public abstract_object<asset_dynamic_data_object,
                                               implementation_ids, impl_asset_dynamic_data_object_type>
   {
      public:
         /// The number of shares currently in existence
         share_type current_supply;
         share_type confidential_supply; ///< total asset held in confidential balances
         share_type accumulated_fees; ///< fees accumulate to be paid out over time
         share_type accumulated_collateral_fees; ///< accumulated collateral-denominated fees (for bitassets)
         share_type fee_pool;         ///< in core asset
   };

   /**
    *  @brief tracks the parameters of an asset
    *  @ingroup object
    *
    *  All assets have a globally unique symbol name that controls how they are traded and an issuer who
    *  has authority over the parameters of the asset.
    */
   class asset_object : public graphene::db::abstract_object<asset_object, protocol_ids, asset_object_type>
   {
      public:
         /// This function does not check if any registered asset has this symbol or not; it simply checks whether the
         /// symbol would be valid.
         /// @return true if symbol is a valid ticker symbol; false otherwise.
         static bool is_valid_symbol( const string& symbol );

         /// @return true if this is a market-issued asset; false otherwise.
         bool is_market_issued()const { return bitasset_data_id.valid(); }
         /// @return true if this is a share asset of a liquidity pool; false otherwise.
         bool is_liquidity_pool_share_asset()const { return for_liquidity_pool.valid(); }
         /// @return true if users may request force-settlement of this market-issued asset; false otherwise
         bool can_force_settle()const { return (0 == (options.flags & disable_force_settle)); }
         /// @return true if the issuer of this market-issued asset may globally settle the asset; false otherwise
         bool can_global_settle()const { return (0 != (options.issuer_permissions & global_settle)); }
         /// @return true if this asset charges a fee for the issuer on market operations; false otherwise
         bool charges_market_fees()const { return (0 != (options.flags & charge_market_fee)); }
         /// @return true if this asset may only be transferred to/from the issuer or market orders
         bool is_transfer_restricted()const { return (0 != (options.flags & transfer_restricted)); }
         bool can_override()const { return (0 != (options.flags & override_authority)); }
         bool allow_confidential()const
         { return (0 == (options.flags & asset_issuer_permission_flags::disable_confidential)); }
         /// @return true if max supply of the asset can be updated
         bool can_update_max_supply()const { return (0 == (options.flags & lock_max_supply)); }
         /// @return true if can create new supply for the asset
         bool can_create_new_supply()const { return (0 == (options.flags & disable_new_supply)); }
         /// @return true if the asset owner can update MCR directly
         bool can_owner_update_mcr()const { return (0 == (options.issuer_permissions & disable_mcr_update)); }
         /// @return true if the asset owner can update ICR directly
         bool can_owner_update_icr()const { return (0 == (options.issuer_permissions & disable_icr_update)); }
         /// @return true if the asset owner can update MSSR directly
         bool can_owner_update_mssr()const { return (0 == (options.issuer_permissions & disable_mssr_update)); }
         /// @return true if the asset owner can change black swan response method
         bool can_owner_update_bsrm()const { return (0 == (options.issuer_permissions & disable_bsrm_update)); }
         /// @return true if can bid collateral for the asset
         bool can_bid_collateral()const { return (0 == (options.flags & disable_collateral_bidding)); }

         /// Helper function to get an asset object with the given amount in this asset's type
         asset amount(share_type a)const { return asset(a, asset_id_type(id)); }
         /// Convert a string amount (i.e. "123.45") to an asset object with this asset's type
         /// The string may have a decimal and/or a negative sign.
         asset amount_from_string(string amount_string)const;
         /// Convert an asset to a textual representation, i.e. "123.45"
         string amount_to_string(share_type amount)const;
         /// Convert an asset to a textual representation, i.e. "123.45"
         string amount_to_string(const asset& amount)const
         { FC_ASSERT(amount.asset_id == get_id()); return amount_to_string(amount.amount); }
         /// Convert an asset to a textual representation with symbol, i.e. "123.45 USD"
         string amount_to_pretty_string(share_type amount)const
         { return amount_to_string(amount) + " " + symbol; }
         /// Convert an asset to a textual representation with symbol, i.e. "123.45 USD"
         string amount_to_pretty_string(const asset &amount)const
         { FC_ASSERT(amount.asset_id == get_id()); return amount_to_pretty_string(amount.amount); }

         /// Ticker symbol for this asset, i.e. "USD"
         string symbol;
         /// Maximum number of digits after the decimal point (must be <= 12)
         uint8_t precision = 0;
         /// ID of the account which issued this asset.
         account_id_type issuer;

         asset_options options;

         /// Current supply, fee pool, and collected fees are stored in a separate object as they change frequently.
         asset_dynamic_data_id_type  dynamic_asset_data_id;
         /// Extra data associated with BitAssets. This field is non-null if and only if is_market_issued() returns true
         optional<asset_bitasset_data_id_type> bitasset_data_id;

         optional<account_id_type> buyback_account;

         /// The ID of the liquidity pool if the asset is the share asset of a liquidity pool
         optional<liquidity_pool_id_type> for_liquidity_pool;

         /// The block number when the asset object was created
         uint32_t       creation_block_num = 0;
         /// The time when the asset object was created
         time_point_sec creation_time;

         void validate()const
         {
            // UIAs may not be prediction markets, have force settlement, or global settlements
            if( !is_market_issued() )
            {
               FC_ASSERT(0 == (options.flags & disable_force_settle) && 0 == (options.flags & global_settle));
               FC_ASSERT(0 == (options.issuer_permissions & disable_force_settle)
                         && 0 == (options.issuer_permissions & global_settle));
            }
         }

         template<class DB>
         const asset_bitasset_data_object& bitasset_data(const DB& db)const
         {
            FC_ASSERT( bitasset_data_id.valid(),
                       "Asset ${a} (${id}) is not a market issued asset.",
                       ("a",this->symbol)("id",this->id) );
            return db.get( *bitasset_data_id );
         }

         template<class DB>
         const asset_dynamic_data_object& dynamic_data(const DB& db)const
         { return db.get(dynamic_asset_data_id); }

         /**
          *  The total amount of an asset that is reserved for future issuance.
          */
         template<class DB>
         share_type reserved( const DB& db )const
         { return options.max_supply - dynamic_data(db).current_supply; }

         /// @return true if asset can accumulate fees in the given denomination
         template<class DB>
         bool can_accumulate_fee(const DB& db, const asset& fee) const {
            return (( fee.asset_id == get_id() ) ||
                    ( is_market_issued() && fee.asset_id == bitasset_data(db).options.short_backing_asset ));
         }

         /***
          * @brief receive a fee asset to accrue in dynamic_data object
          *
          * Asset owners define various fees (market fees, force-settle fees, etc.) to be
          * collected for the asset owners. These fees are typically denominated in the asset
          * itself, but for bitassets some of the fees are denominated in the collateral
          * asset. This will place the fee in the right container.
          */
         template<class DB>
         void accumulate_fee(DB& db, const asset& fee) const
         {
            if (fee.amount == 0) return;
            FC_ASSERT( fee.amount >= 0, "Fee amount must be non-negative." );
            const auto& dyn_data = dynamic_asset_data_id(db);
            if (fee.asset_id == get_id()) { // fee same as asset
               db.modify( dyn_data, [&fee]( asset_dynamic_data_object& obj ){
                  obj.accumulated_fees += fee.amount;
               });
            } else { // fee different asset; perhaps collateral-denominated fee
               FC_ASSERT( is_market_issued(),
                          "Asset ${a} (${id}) cannot accept fee of asset (${fid}).",
                          ("a",this->symbol)("id",this->id)("fid",fee.asset_id) );
               const auto & bad = bitasset_data(db);
               FC_ASSERT( fee.asset_id == bad.options.short_backing_asset,
                          "Asset ${a} (${id}) cannot accept fee of asset (${fid}).",
                          ("a",this->symbol)("id",this->id)("fid",fee.asset_id) );
               db.modify( dyn_data, [&fee]( asset_dynamic_data_object& obj ){
                  obj.accumulated_collateral_fees += fee.amount;
               });
            }
         }

   };

   /**
    *  @brief defines market parameters for margin positions, extended with an initial_collateral_ratio field
    */
   struct price_feed_with_icr : public price_feed
   {
      /// After BSIP77, when creating a new debt position or updating an existing position,
      /// the position will be checked against this parameter.
      /// Fixed point between 1.000 and 10.000, implied fixed point denominator is GRAPHENE_COLLATERAL_RATIO_DENOM
      uint16_t initial_collateral_ratio = GRAPHENE_DEFAULT_MAINTENANCE_COLLATERAL_RATIO;

      price_feed_with_icr()
      : price_feed(), initial_collateral_ratio( maintenance_collateral_ratio )
      {}

      price_feed_with_icr( const price_feed& pf, const optional<uint16_t>& icr = {} )
      : price_feed( pf ), initial_collateral_ratio( icr.valid() ? *icr : pf.maintenance_collateral_ratio )
      {}

      /// The result will be used to check new debt positions and position updates.
      /// Calculation: ~settlement_price * initial_collateral_ratio / GRAPHENE_COLLATERAL_RATIO_DENOM
      price get_initial_collateralization()const;
   };

   /**
    *  @brief contains properties that only apply to bitassets (market issued assets)
    *
    *  @ingroup object
    *  @ingroup implementation
    */
   class asset_bitasset_data_object : public abstract_object<asset_bitasset_data_object,
                                                implementation_ids, impl_asset_bitasset_data_object_type>
   {
      public:
         /// The asset this object belong to
         asset_id_type asset_id;

         /// The tunable options for BitAssets are stored in this field.
         bitasset_options options;

         /// Feeds published for this asset.
         /// The keys in this map are the feed publishing accounts.
         /// The timestamp on each feed is the time it was published.
         flat_map<account_id_type, pair<time_point_sec,price_feed_with_icr>> feeds;
         /// This is the median of values from the currently active feeds.
         price_feed_with_icr median_feed;
         /// This is the currently active price feed, calculated from @ref median_feed and other parameters.
         price_feed_with_icr current_feed;
         /// This is the publication time of the oldest feed which was factored into current_feed.
         time_point_sec current_feed_publication_time;

         /// @return whether @ref current_feed is different from @ref median_feed
         bool is_current_feed_price_capped()const
         { return ( median_feed.settlement_price != current_feed.settlement_price ); }

         /// Call orders with collateralization (aka collateral/debt) not greater than this value are in margin
         /// call territory.
         /// This value is derived from @ref current_feed for better performance and should be kept consistent.
         price current_maintenance_collateralization;
         /// After BSIP77, when creating a new debt position or updating an existing position, the position
         /// will be checked against the `initial_collateral_ratio` (ICR) parameter in the bitasset options.
         /// This value is derived from @ref current_feed (which includes `ICR`) for better performance and
         /// should be kept consistent.
         price current_initial_collateralization;

         /// True if this asset implements a @ref prediction_market
         bool is_prediction_market = false;

         /// This is the volume of this asset which has been force-settled this maintanence interval
         share_type force_settled_volume;
         /// Calculate the maximum force settlement volume per maintenance interval, given the current share supply
         share_type max_force_settlement_volume(share_type current_supply)const;

         /// @return true if the bitasset has been globally settled, false otherwise
         bool has_settlement()const { return !settlement_price.is_null(); }

         /**
          *  In the event of global settlement, all margin positions
          *  are settled with the siezed collateral being moved into the settlement fund. From this
          *  point on forced settlement occurs immediately when requested, using the settlement price and fund.
          */
         ///@{
         /// Price at which force settlements of a globally settled asset will occur
         price settlement_price;
         /// Amount of collateral which is available for force settlement due to global settlement
         share_type settlement_fund;
         ///@}

         /// The individual settlement pool.
         /// In the event of individual settlements to fund, debt and collateral of the margin positions which got
         /// settled are moved here.
         ///@{
         /// Amount of debt due to individual settlements
         share_type individual_settlement_debt;
         /// Amount of collateral which is available for force settlement due to individual settlements
         share_type individual_settlement_fund;
         ///@}

         /// @return true if the individual settlement pool is not empty, false otherwise
         bool has_individual_settlement()const { return ( individual_settlement_debt != 0 ); }

         /// Get the price of the individual settlement pool
         price get_individual_settlement_price() const
         {
            return asset( individual_settlement_debt, asset_id )
                   / asset( individual_settlement_fund, options.short_backing_asset );
         }

         /// Get the effective black swan response method of this bitasset
         bitasset_options::black_swan_response_type get_black_swan_response_method() const
         {
            return options.get_black_swan_response_method();
         }

         /// Get margin call order price (MCOP) of this bitasset
         price get_margin_call_order_price() const
         {
            return current_feed.margin_call_order_price( options.extensions.value.margin_call_fee_ratio );
         }

         /// Get margin call order ratio (MCOR) of this bitasset
         ratio_type get_margin_call_order_ratio() const
         {
            return current_feed.margin_call_order_ratio( options.extensions.value.margin_call_fee_ratio );
         }

         /// Get margin call pays ratio (MCPR) of this bitasset
         ratio_type get_margin_call_pays_ratio() const
         {
            return current_feed.margin_call_pays_ratio( options.extensions.value.margin_call_fee_ratio );
         }

         /// Track whether core_exchange_rate in corresponding @ref asset_object has updated
         bool asset_cer_updated = false;

         /// Track whether core exchange rate in current feed has updated
         bool feed_cer_updated = false;

         /// Whether need to update core_exchange_rate in @ref asset_object
         bool need_to_update_cer() const
         {
            return ( ( feed_cer_updated || asset_cer_updated ) && !current_feed.core_exchange_rate.is_null() );
         }

         /// The time when @ref current_feed would expire
         time_point_sec feed_expiration_time()const
         {
            uint32_t current_feed_seconds = current_feed_publication_time.sec_since_epoch();
            if( (std::numeric_limits<uint32_t>::max() - current_feed_seconds) <= options.feed_lifetime_sec )
               return time_point_sec::maximum();
            else
               return current_feed_publication_time + options.feed_lifetime_sec;
         }
         /// The old and buggy implementation of @ref feed_is_expired before the No. 615 hardfork.
         /// See https://github.com/cryptonomex/graphene/issues/615
         bool feed_is_expired_before_hf_615(time_point_sec current_time)const
         { return feed_expiration_time() >= current_time; }
         /// @return whether @ref current_feed has expired
         bool feed_is_expired(time_point_sec current_time)const
         { return feed_expiration_time() <= current_time; }

         /******
          * @brief calculate the median feed
          *
          * This calculates the median feed from @ref feeds, feed_lifetime_sec
          * in @ref options, and the given parameters.
          * It may update the @ref median_feed, @ref current_feed_publication_time,
          * @ref current_initial_collateralization and
          * @ref current_maintenance_collateralization member variables.
          *
          * @param current_time the current time to use in the calculations
          * @param next_maintenance_time the next chain maintenance time
          *
          * @note Called by @ref database::update_bitasset_current_feed() which updates @ref current_feed afterwards.
          */
         void update_median_feeds(time_point_sec current_time, time_point_sec next_maintenance_time);
      private:
         /// Derive @ref current_maintenance_collateralization and @ref current_initial_collateralization from
         /// other member variables.
         void refresh_cache();
   };

   /// Key extractor for short backing asset
   struct bitasset_backing_asst_extractor
   {
      using result_type = asset_id_type;
      result_type operator() (const asset_bitasset_data_object& obj) const
      {
         return obj.options.short_backing_asset;
      }
   };

   struct by_short_backing_asset;
   struct by_feed_expiration;
   struct by_cer_update;

   using bitasset_data_multi_index_type = multi_index_container<
      asset_bitasset_data_object,
      indexed_by<
         ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
         ordered_non_unique< tag<by_short_backing_asset>, bitasset_backing_asst_extractor >,
         ordered_unique< tag<by_feed_expiration>,
            composite_key< asset_bitasset_data_object,
               const_mem_fun< asset_bitasset_data_object, time_point_sec,
                              &asset_bitasset_data_object::feed_expiration_time >,
               member< asset_bitasset_data_object, asset_id_type, &asset_bitasset_data_object::asset_id >
            >
         >,
         ordered_non_unique< tag<by_cer_update>,
                             const_mem_fun< asset_bitasset_data_object, bool,
                                            &asset_bitasset_data_object::need_to_update_cer >
         >
      >
   >;
   using asset_bitasset_data_index = generic_index< asset_bitasset_data_object, bitasset_data_multi_index_type >;

   struct by_symbol;
   struct by_type;
   struct by_issuer;
   using asset_object_multi_index_type = multi_index_container<
      asset_object,
      indexed_by<
         ordered_unique< tag<by_id>, member< object, object_id_type, &object::id > >,
         ordered_unique< tag<by_symbol>, member<asset_object, string, &asset_object::symbol> >,
         ordered_unique< tag<by_type>,
            composite_key< asset_object,
                const_mem_fun<asset_object, bool, &asset_object::is_market_issued>,
                member< object, object_id_type, &object::id >
            >
         >,
         ordered_unique< tag<by_issuer>,
            composite_key< asset_object,
                member< asset_object, account_id_type, &asset_object::issuer >,
                member< object, object_id_type, &object::id >
            >
         >
      >
   >;
   using asset_index = generic_index< asset_object, asset_object_multi_index_type >;

} } // graphene::chain

MAP_OBJECT_ID_TO_TYPE(graphene::chain::asset_object)
MAP_OBJECT_ID_TO_TYPE(graphene::chain::asset_dynamic_data_object)
MAP_OBJECT_ID_TO_TYPE(graphene::chain::asset_bitasset_data_object)

FC_REFLECT_DERIVED( graphene::chain::price_feed_with_icr, (graphene::protocol::price_feed),
                    (initial_collateral_ratio) )

// Note: this is left here but not moved to a cpp file due to the extended_asset_object struct in API.
FC_REFLECT_DERIVED( graphene::chain::asset_object, (graphene::db::object),
                    (symbol)
                    (precision)
                    (issuer)
                    (options)
                    (dynamic_asset_data_id)
                    (bitasset_data_id)
                    (buyback_account)
                    (for_liquidity_pool)
                    (creation_block_num)
                    (creation_time)
                  )

FC_REFLECT_TYPENAME( graphene::chain::asset_bitasset_data_object )
FC_REFLECT_TYPENAME( graphene::chain::asset_dynamic_data_object )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::price_feed_with_icr )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::asset_object )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::asset_bitasset_data_object )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::chain::asset_dynamic_data_object )
