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

   /// Upper bound on an oracle's producer set. Bounds the cost of aggregating, which runs
   /// whenever a value is published, and bounds the object's serialized size.
   constexpr uint16_t GRAPHENE_ORACLE_MAX_PRODUCERS = 32;

   /// Upper bound on retained history. State per oracle is fixed at creation rather than
   /// growing with age or publication rate.
   constexpr uint16_t GRAPHENE_ORACLE_MAX_HISTORY = 64;

   /// Upper bound on how many market-issued assets may bind to one oracle. Publishing
   /// refreshes every bound asset's feed, so this bounds the work a single publish can cause.
   constexpr uint16_t GRAPHENE_ORACLE_MAX_SUBSCRIBERS = 64;

   constexpr size_t GRAPHENE_ORACLE_MIN_NAME_LENGTH = 3;
   constexpr size_t GRAPHENE_ORACLE_MAX_NAME_LENGTH = 32;
   constexpr size_t GRAPHENE_ORACLE_MAX_DESCRIPTION_LENGTH = 1000;

   /// Upper bound on the number of series an oracle declares. Bounds per-entry history state
   /// (MAX_HISTORY entries each holding one value per series) and per-publish validation work.
   /// bid/ask/mid/last cover every consumer the design names; more would be schema, not need.
   constexpr uint8_t GRAPHENE_ORACLE_MAX_SERIES = 4;

   /// A producer's weight. Weight is set by the owner, never earned; see ORACLE-DESIGN.md.
   constexpr uint16_t GRAPHENE_ORACLE_MAX_PRODUCER_WEIGHT = 1000;

   constexpr size_t GRAPHENE_REFERENCE_ASSET_MIN_SYMBOL_LENGTH = 2;
   constexpr size_t GRAPHENE_REFERENCE_ASSET_MAX_SYMBOL_LENGTH = 16;
   constexpr size_t GRAPHENE_REFERENCE_ASSET_MAX_DESCRIPTION_LENGTH = 1000;
   /// Kept identical to an asset's precision bound: a reference asset has a smallest unit
   /// exactly like an asset does, so the same range applies.
   constexpr uint8_t GRAPHENE_REFERENCE_ASSET_MAX_PRECISION = 12;

   /**
    * How an oracle turns its producers' submissions into one value.
    *
    * Both methods *select* an observed value rather than computing a new one. That is a
    * consensus requirement, not a stylistic choice: selection cannot round, cannot overflow,
    * and cannot differ between nodes.
    */
   enum class oracle_aggregation_method : uint8_t
   {
      /// Weighted median of the submissions still within value_lifetime_sec. With every
      /// weight equal to 1 this is exactly the behaviour of the legacy price feed median.
      median_of_latest = 0,
      /// Median of the recorded aggregates inside window_sec. Deliberately a windowed median
      /// and not a time-weighted average -- see ORACLE-DESIGN.md for why an exact selection
      /// is preferred over an accumulated mean.
      median_over_window = 1
   };

   /// What one published value in an oracle's series list is. Suggested in review: each
   /// consumer reads the series whose meaning and rounding suit it.
   enum class oracle_series_kind : uint8_t
   {
      mid  = 0,
      last = 1,
      bid  = 2,
      ask  = 3
   };

   /// How the value in a series was rounded by its producer. A consumer that reads a series
   /// rounded against borrowers keeps that property through conversion (see
   /// convert_oracle_value_to_price).
   enum class oracle_series_rounding : uint8_t
   {
      unspecified = 0,
      down        = 1,
      up          = 2
   };

   /// One entry of an oracle's declared series list. The list is fixed at creation in
   /// creation order; every publish carries exactly one value per entry, in order.
   struct oracle_series
   {
      /**
       * Kind and rounding, held as the underlying integers of @ref oracle_series_kind and
       * @ref oracle_series_rounding, for the same reason the aggregation method travels as
       * a plain integer: an unknown value must fail in validate(), not in deserialisation.
       */
      uint8_t kind     = static_cast<uint8_t>( oracle_series_kind::mid );
      uint8_t rounding = static_cast<uint8_t>( oracle_series_rounding::unspecified );

      oracle_series() = default;
      oracle_series( oracle_series_kind k, oracle_series_rounding r )
         : kind( static_cast<uint8_t>( k ) ), rounding( static_cast<uint8_t>( r ) ) {}

      oracle_series_kind get_kind()const
      { return static_cast<oracle_series_kind>( kind ); }
      oracle_series_rounding get_rounding()const
      { return static_cast<oracle_series_rounding>( rounding ); }

      void validate()const;
   };

   /**
    * One published value: that many smallest units of the oracle's base reference asset
    * equal that many smallest units of its quote. Both are positive int64. Comparing two
    * values stays exact, by 128-bit cross-multiplication.
    */
   struct oracle_value
   {
      share_type base_amount;
      share_type quote_amount;

      oracle_value() = default;
      oracle_value( int64_t base_amount_, int64_t quote_amount_ )
         : base_amount( base_amount_ ), quote_amount( quote_amount_ ) {}

      void validate()const;
   };

   bool operator <  ( const oracle_value& a, const oracle_value& b );
   bool operator == ( const oracle_value& a, const oracle_value& b );
   inline bool operator >  ( const oracle_value& a, const oracle_value& b ) { return (b < a); }
   inline bool operator <= ( const oracle_value& a, const oracle_value& b ) { return !(b < a); }
   inline bool operator >= ( const oracle_value& a, const oracle_value& b ) { return !(a < b); }
   inline bool operator != ( const oracle_value& a, const oracle_value& b ) { return !(a == b); }

   /**
    * One producer's entry in an oracle's producer set. A struct, not a bare weight, so that
    * an economic layer (bonds, reward shares) can be added later without a new operation.
    * The extensions field is wire space only in this stage: no bond logic reads it.
    * See ORACLE-DESIGN.md "What the first stage does to keep this possible".
    */
   struct oracle_producer_entry
   {
      uint16_t weight = 0;
      extensions_type extensions;

      oracle_producer_entry() = default;
      explicit oracle_producer_entry( uint16_t w ) : weight( w ) {}
   };

   /// Shared by create and update. Every field is policy the owner controls.
   struct oracle_options
   {
      /// Producers permitted to publish, and their entries. Empty means nobody can publish,
      /// which is legal: it parks an oracle without deleting it.
      flat_map<account_id_type, oracle_producer_entry> producers;

      /// Fewer live submissions than this and the oracle reports no value at all, rather than
      /// reporting a value derived from too few sources.
      uint16_t minimum_producers = 1;

      /// A submission older than this stops counting toward the aggregate.
      uint32_t value_lifetime_sec = 86400;

      /**
       * Aggregation method, held as the underlying integer of @ref oracle_aggregation_method.
       *
       * Protocol data, so not the enum type itself: fc reflects an enum as a signed 64-bit
       * value, which both wastes space in every signed transaction and moves the rejection of
       * an unknown method into deserialisation instead of validate(). The existing protocol
       * does the same with black_swan_response_method. Read it through get_aggregation().
       */
      uint8_t aggregation = static_cast<uint8_t>( oracle_aggregation_method::median_of_latest );

      /// Window for median_over_window. Ignored by median_of_latest.
      uint32_t window_sec = 3600;

      /**
       * How far a submission may sit from the current aggregate before it is treated as an
       * outlier, in parts per million. Zero disables the check.
       *
       * Outliers are excluded only while enough non-outliers remain to satisfy
       * minimum_producers. If excluding them would break quorum, nothing is excluded and the
       * aggregate moves -- otherwise a real crash, where every honest producer moves at once,
       * would freeze the oracle at the moment it most needs to update.
       */
      uint32_t max_deviation_ppm = 0;

      extensions_type extensions;

      /// @return the aggregation method; only valid after validate() has accepted the value
      oracle_aggregation_method get_aggregation()const
      { return static_cast<oracle_aggregation_method>( aggregation ); }

      void validate()const;
   };

   /**
    * An on-chain asset's declaration that it tracks a reference asset, at a ratio, both in
    * smallest units, both positive. Declared by the asset's issuer in the asset's options;
    * nobody else may say what the issuer's token tracks. Examples: HONEST.USD (precision 4)
    * maps 1:1 to USD (precision 4); a 6-precision USDT maps 100:1; a 7-precision one 1000:1.
    */
   struct reference_mapping
   {
      reference_asset_id_type reference;
      share_type asset_amount;
      share_type reference_amount;

      void validate()const;
   };

   /**
    * @brief Creates a unit a price can be quoted in: a symbol and a precision nobody holds.
    * @ingroup operations
    *
    * Reference assets live in their own namespace: a reference asset "USD" and the smartcoin
    * "USD" are different things, and the smartcoin maps to the reference asset. Symbol and
    * precision are immutable -- every value ever published against a reference asset is
    * counted in its smallest unit, so rescaling would silently reinterpret all of them.
    * There is no update operation; what is stored at creation is final.
    */
   struct reference_asset_create_operation : public base_operation
   {
      struct fee_params_t {
         uint64_t fee = 500 * GRAPHENE_BLOCKCHAIN_PRECISION;
         uint32_t price_per_kbyte = GRAPHENE_BLOCKCHAIN_PRECISION;
      };

      asset           fee;
      account_id_type creator;     ///< Pays the fee; gated by the chain parameter (committee-only first)
      string          symbol;      ///< Unique among reference assets, e.g. "USD"
      uint8_t         precision = 0;
      string          description;

      extensions_type extensions;

      account_id_type fee_payer()const { return creator; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Creates a named price series that consumers can reference by id.
    * @ingroup operations
    */
   struct oracle_create_operation : public base_operation
   {
      struct fee_params_t {
         uint64_t fee = 500 * GRAPHENE_BLOCKCHAIN_PRECISION;
         uint32_t price_per_kbyte = GRAPHENE_BLOCKCHAIN_PRECISION;
      };

      asset           fee;
      account_id_type owner;         ///< Creator and administrator; pays the fee

      /// Unique, e.g. "BTC.USD". Uppercase letters, digits, '.' and '-'.
      string          name;
      string          description;

      /// What a published price means, as reference assets rather than on-chain asset ids,
      /// so that several consumers can share one oracle. Immutable once created.
      reference_asset_id_type base;
      reference_asset_id_type quote;

      /// The ordered series list, fixed at creation. Every publish carries exactly one
      /// value per entry, in order. Carried on the wire from day one so that adding
      /// series later needs no new operation.
      vector<oracle_series> series;

      oracle_options  options;

      extensions_type extensions;

      account_id_type fee_payer()const { return owner; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Changes an oracle's policy.
    * @ingroup operations
    *
    * Deliberately cannot change base, quote, series or name: consumers reference an
    * oracle by id and would have no way to notice that what it measures had changed
    * underneath them.
    */
   struct oracle_update_operation : public base_operation
   {
      struct fee_params_t {
         uint64_t fee = 50 * GRAPHENE_BLOCKCHAIN_PRECISION;
         uint32_t price_per_kbyte = GRAPHENE_BLOCKCHAIN_PRECISION;
      };

      asset            fee;
      account_id_type  owner;
      oracle_id_type   oracle_id;

      optional<string>         new_description;
      optional<oracle_options> new_options;

      extensions_type  extensions;

      account_id_type fee_payer()const { return owner; }
      void            validate()const;
      share_type      calculate_fee( const fee_params_t& k )const;
   };

   /**
    * @brief Removes an oracle.
    * @ingroup operations
    *
    * Refused while anything on chain still references it.
    */
   struct oracle_delete_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 0; };

      asset            fee;
      account_id_type  owner;
      oracle_id_type   oracle_id;

      extensions_type  extensions;

      account_id_type fee_payer()const { return owner; }
      void            validate()const;
   };

   /**
    * @brief Submits one value per declared series to an oracle.
    * @ingroup operations
    *
    * The narrowest operation in the set on purpose. A producer supplies prices and nothing
    * else: it cannot alter policy, add producers, or affect any oracle it is not a producer
    * of.
    */
   struct oracle_publish_operation : public base_operation
   {
      /// Published often by design, so the fee is low. Spam is bounded by the producer set
      /// being an allow-list the owner controls, not by the fee.
      struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION / 10; };

      asset            fee;
      account_id_type  producer;
      oracle_id_type   oracle_id;

      /// Exactly one value per series the oracle declared, in order. The evaluator enforces
      /// the relations a single submission must satisfy: bid <= ask, and a series rounded
      /// down <= the same kind rounded up.
      vector<oracle_value> values;

      extensions_type  extensions;

      account_id_type fee_payer()const { return producer; }
      void            validate()const;
   };

   /// @return whether @p name is acceptable as an oracle name
   bool is_valid_oracle_name( const string& name );

   /// @return whether @p symbol is acceptable as a reference asset symbol
   bool is_valid_reference_asset_symbol( const string& symbol );

   /**
    * Converts one oracle value into the settlement price between two mapped assets.
    *
    * Take the oracle value (b, q), the debt asset's mapping (s_a, s_r) and the backing
    * asset's mapping (c_a, c_r). The settlement price is
    *
    *   (s_a . b . c_r) debt units = (s_r . q . c_a) backing units
    *
    * When both mappings are 1:1 in smallest units this IS the oracle value and involves no
    * arithmetic at all. Otherwise each side is a product of three int64 values, computed
    * exactly (boost::multiprecision, no floats anywhere) and reduced by the sides' greatest
    * common divisor. If a side still exceeds GRAPHENE_MAX_SHARE_SUPPLY, both sides are
    * scaled down by one common factor, rounding the way @p rounding declares (unspecified
    * behaves as down); a scaled side that would vanish is kept at 1. Deterministic by
    * construction: exact integer arithmetic with a declared rounding direction cannot
    * differ between nodes.
    */
   price convert_oracle_value_to_price(
      const oracle_value& v,
      const reference_mapping& debt_mapping, asset_id_type debt_asset,
      const reference_mapping& backing_mapping, asset_id_type backing_asset,
      oracle_series_rounding rounding );

} } // graphene::protocol

FC_REFLECT_ENUM( graphene::protocol::oracle_aggregation_method,
                 (median_of_latest)(median_over_window) )
FC_REFLECT_ENUM( graphene::protocol::oracle_series_kind,
                 (mid)(last)(bid)(ask) )
FC_REFLECT_ENUM( graphene::protocol::oracle_series_rounding,
                 (unspecified)(down)(up) )

FC_REFLECT( graphene::protocol::oracle_series,
            (kind)(rounding) )

FC_REFLECT( graphene::protocol::oracle_value,
            (base_amount)(quote_amount) )

FC_REFLECT( graphene::protocol::oracle_producer_entry,
            (weight)(extensions) )

FC_REFLECT( graphene::protocol::reference_mapping,
            (reference)(asset_amount)(reference_amount) )

FC_REFLECT( graphene::protocol::oracle_options,
            (producers)(minimum_producers)(value_lifetime_sec)(aggregation)(window_sec)
            (max_deviation_ppm)(extensions) )

FC_REFLECT( graphene::protocol::reference_asset_create_operation::fee_params_t, (fee)(price_per_kbyte) )
FC_REFLECT( graphene::protocol::oracle_create_operation::fee_params_t, (fee)(price_per_kbyte) )
FC_REFLECT( graphene::protocol::oracle_update_operation::fee_params_t, (fee)(price_per_kbyte) )
FC_REFLECT( graphene::protocol::oracle_delete_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::oracle_publish_operation::fee_params_t, (fee) )

FC_REFLECT( graphene::protocol::reference_asset_create_operation,
            (fee)(creator)(symbol)(precision)(description)(extensions) )
FC_REFLECT( graphene::protocol::oracle_create_operation,
            (fee)(owner)(name)(description)(base)(quote)(series)(options)(extensions) )
FC_REFLECT( graphene::protocol::oracle_update_operation,
            (fee)(owner)(oracle_id)(new_description)(new_options)(extensions) )
FC_REFLECT( graphene::protocol::oracle_delete_operation,
            (fee)(owner)(oracle_id)(extensions) )
FC_REFLECT( graphene::protocol::oracle_publish_operation,
            (fee)(producer)(oracle_id)(values)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_series )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_value )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_producer_entry )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reference_mapping )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_options )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reference_asset_create_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_create_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_update_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_delete_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_publish_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reference_asset_create_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_create_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_update_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_delete_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_publish_operation )
