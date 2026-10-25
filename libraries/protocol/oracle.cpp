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
#include <graphene/protocol/oracle.hpp>

#include <fc/io/raw.hpp>
#include <fc/uint128.hpp>

#include <boost/multiprecision/cpp_int.hpp>

namespace graphene { namespace protocol {

namespace {
   /// Charset shared by oracle names and reference asset symbols: humans tell series apart
   /// by these strings, so lookalikes built from mixed case or unicode would be a way to
   /// get a consumer to reference the wrong value.
   bool is_valid_oracle_word( const string& name, size_t min_len, size_t max_len )
   {
      if( name.size() < min_len || name.size() > max_len )
         return false;

      char previous = 0;
      for( size_t i = 0; i < name.size(); ++i )
      {
         const char c = name[i];
         const bool is_alnum = ( c >= 'A' && c <= 'Z' ) || ( c >= '0' && c <= '9' );
         const bool is_sep   = ( '.' == c || '-' == c );
         if( !is_alnum && !is_sep )
            return false;
         // no leading, trailing or repeated separator
         if( is_sep && ( 0 == i || i + 1 == name.size() || '.' == previous || '-' == previous ) )
            return false;
         previous = c;
      }
      return true;
   }
} // namespace

bool is_valid_oracle_name( const string& name )
{
   return is_valid_oracle_word( name,
      GRAPHENE_ORACLE_MIN_NAME_LENGTH, GRAPHENE_ORACLE_MAX_NAME_LENGTH );
}

bool is_valid_reference_asset_symbol( const string& symbol )
{
   return is_valid_oracle_word( symbol,
      GRAPHENE_REFERENCE_ASSET_MIN_SYMBOL_LENGTH, GRAPHENE_REFERENCE_ASSET_MAX_SYMBOL_LENGTH );
}

void oracle_series::validate()const
{
   FC_ASSERT( kind <= static_cast<uint8_t>( oracle_series_kind::ask ),
              "Unknown series kind ${k}", ("k", kind) );
   FC_ASSERT( rounding <= static_cast<uint8_t>( oracle_series_rounding::up ),
              "Unknown series rounding ${r}", ("r", rounding) );
}

void oracle_value::validate()const
{
   // A null or non-positive value would otherwise be carried into the aggregate, where a
   // zero reads as "free" to every consumer downstream.
   FC_ASSERT( base_amount > 0, "Published base amount should be positive" );
   FC_ASSERT( quote_amount > 0, "Published quote amount should be positive" );
   // Bounded so the consumer conversion's three-way products fit the exact integer
   // arithmetic it is computed in (each factor below 2^50 keeps the product below 2^150).
   FC_ASSERT( base_amount <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Published base amount exceeds maximum share supply" );
   FC_ASSERT( quote_amount <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Published quote amount exceeds maximum share supply" );
}

bool operator < ( const oracle_value& a, const oracle_value& b )
{
   // Ratio-order determinism fix: the order must be TOTAL over the
   // struct so the weighted-median representative is a function of the value
   // set, never of std::sort stability. Ratio-equal, raw-different values
   // ((1,1) vs (3,3)) are otherwise equivalent elements whose permutation is
   // implementation-defined -- two honest nodes on different standard
   // libraries (exactly what a hardfork binary switch brings) would emit
   // different current_feed base/quote scales. operator== stays ratio-based
   // on purpose: H2 change detection (h2_economics.cpp:619) and
   // deviates_too_far compare by ratio and must keep doing so.
   const fc::uint128_t left  = fc::uint128_t( a.base_amount.value )
                             * b.quote_amount.value;
   const fc::uint128_t right = fc::uint128_t( b.base_amount.value )
                             * a.quote_amount.value;
   if( left != right )
      return left < right;
   if( a.base_amount != b.base_amount )
      return a.base_amount < b.base_amount;
   return a.quote_amount < b.quote_amount;
}

bool operator == ( const oracle_value& a, const oracle_value& b )
{
   const fc::uint128_t left  = fc::uint128_t( a.base_amount.value )
                             * b.quote_amount.value;
   const fc::uint128_t right = fc::uint128_t( b.base_amount.value )
                             * a.quote_amount.value;
   return left == right;
}

void reference_mapping::validate()const
{
   FC_ASSERT( asset_amount > 0, "Mapping asset amount should be positive" );
   FC_ASSERT( reference_amount > 0, "Mapping reference amount should be positive" );
   FC_ASSERT( asset_amount <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Mapping asset amount exceeds maximum share supply" );
   FC_ASSERT( reference_amount <= GRAPHENE_MAX_SHARE_SUPPLY,
              "Mapping reference amount exceeds maximum share supply" );
}

bool operator==( const reference_mapping& a, const reference_mapping& b )
{
   return a.reference == b.reference
          && a.asset_amount == b.asset_amount
          && a.reference_amount == b.reference_amount;
}

void price_oracle::validate()const
{
   // The range against the oracle's ACTUAL series list is chain state, so it is checked
   // in the evaluator; here the index must at least fit the largest list any oracle may
   // declare, or a binding could name a series no oracle could ever have.
   FC_ASSERT( series < GRAPHENE_ORACLE_MAX_SERIES,
              "Bound series ${s} exceeds the maximum an oracle may declare (${m})",
              ("s", series)("m", GRAPHENE_ORACLE_MAX_SERIES) );
   // Expiry is mandatory: a binding without an expiry height (zero, the struct default)
   // is refused here, before any chain-state check. The strictly-future rule needs the
   // head block number, so it lives in the asset_update_bitasset evaluator, not here.
   FC_ASSERT( expiry_height > 0,
              "A price_oracle_binding must carry a consensus expiry height" );
}

void oracle_options::validate()const
{
   FC_ASSERT( producers.size() <= GRAPHENE_ORACLE_MAX_PRODUCERS,
              "An oracle may have at most ${m} producers", ("m", GRAPHENE_ORACLE_MAX_PRODUCERS) );

   uint32_t total_weight = 0;
   for( const auto& p : producers )
   {
      FC_ASSERT( p.second.weight > 0,
                 "Producer ${a} has weight zero; remove the producer instead", ("a", p.first) );
      FC_ASSERT( p.second.weight <= GRAPHENE_ORACLE_MAX_PRODUCER_WEIGHT,
                 "Producer weight should not exceed ${m}",
                 ("m", GRAPHENE_ORACLE_MAX_PRODUCER_WEIGHT) );
      total_weight += p.second.weight;
   }
   // Bounded above by MAX_PRODUCERS * MAX_PRODUCER_WEIGHT, so the weighted median's running
   // total cannot overflow the uint32 it is accumulated in.
   FC_ASSERT( total_weight <= uint32_t( GRAPHENE_ORACLE_MAX_PRODUCERS )
                              * GRAPHENE_ORACLE_MAX_PRODUCER_WEIGHT,
              "Total producer weight is too large" );

   FC_ASSERT( minimum_producers > 0,
              "minimum_producers should be positive: an oracle with no quorum would report a "
              "value derived from nothing" );
   FC_ASSERT( minimum_producers <= GRAPHENE_ORACLE_MAX_PRODUCERS,
              "minimum_producers should not exceed ${m}", ("m", GRAPHENE_ORACLE_MAX_PRODUCERS) );
   // An unreachable quorum is almost certainly a mistake, and it would leave the oracle
   // permanently valueless while looking configured.
   FC_ASSERT( producers.empty() || minimum_producers <= producers.size(),
              "minimum_producers (${q}) exceeds the number of producers (${n}), so the oracle "
              "could never report a value",
              ("q", minimum_producers)("n", producers.size()) );

   FC_ASSERT( value_lifetime_sec > 0, "value_lifetime_sec should be positive" );

   // With the method held as a plain integer, an unknown value no longer fails at
   // deserialisation, so it has to fail here -- otherwise nodes would have to agree on how to
   // aggregate using a method none of them knows.
   FC_ASSERT( aggregation <= static_cast<uint8_t>( oracle_aggregation_method::median_over_window ),
              "Unknown aggregation method ${a}", ("a", aggregation) );

   if( oracle_aggregation_method::median_over_window == get_aggregation() )
      FC_ASSERT( window_sec > 0,
                 "window_sec should be positive when aggregating over a window" );

   FC_ASSERT( max_deviation_ppm <= GRAPHENE_100_PERCENT * 100,
              "max_deviation_ppm is out of range" );
}

void reference_asset_create_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( is_valid_reference_asset_symbol( symbol ),
              "Reference asset symbol '${s}' is not valid: ${min}-${max} characters, uppercase "
              "letters, digits, '.' and '-', with no leading, trailing or repeated separator",
              ("s", symbol)("min", GRAPHENE_REFERENCE_ASSET_MIN_SYMBOL_LENGTH)
              ("max", GRAPHENE_REFERENCE_ASSET_MAX_SYMBOL_LENGTH) );
   FC_ASSERT( precision <= GRAPHENE_REFERENCE_ASSET_MAX_PRECISION,
              "Reference asset precision should not exceed ${m}",
              ("m", GRAPHENE_REFERENCE_ASSET_MAX_PRECISION) );
   // The core asset maps 1:1 to "BTS" by protocol rule, and the core asset's precision is
   // GRAPHENE_REFERENCE_ASSET_BTS_PRECISION: any other precision here would silently
   // mis-scale every core-quoted conversion, so creation is refused outright.
   if( symbol == "BTS" )
      FC_ASSERT( precision == GRAPHENE_REFERENCE_ASSET_BTS_PRECISION,
                 "The BTS reference asset must have precision ${p}, matching the core asset",
                 ("p", GRAPHENE_REFERENCE_ASSET_BTS_PRECISION) );
   FC_ASSERT( description.size() <= GRAPHENE_REFERENCE_ASSET_MAX_DESCRIPTION_LENGTH,
              "Description should not exceed ${m} characters",
              ("m", GRAPHENE_REFERENCE_ASSET_MAX_DESCRIPTION_LENGTH) );
}

share_type reference_asset_create_operation::calculate_fee( const fee_params_t& schedule )const
{
   share_type core_fee_required = schedule.fee;
   core_fee_required += calculate_data_fee( fc::raw::pack_size(*this), schedule.price_per_kbyte );
   return core_fee_required;
}

void oracle_create_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( is_valid_oracle_name( name ),
              "Oracle name '${n}' is not valid: ${min}-${max} characters, uppercase letters, "
              "digits, '.' and '-', with no leading, trailing or repeated separator",
              ("n", name)("min", GRAPHENE_ORACLE_MIN_NAME_LENGTH)
              ("max", GRAPHENE_ORACLE_MAX_NAME_LENGTH) );
   FC_ASSERT( description.size() <= GRAPHENE_ORACLE_MAX_DESCRIPTION_LENGTH,
              "Description should not exceed ${m} characters",
              ("m", GRAPHENE_ORACLE_MAX_DESCRIPTION_LENGTH) );
   FC_ASSERT( base != quote,
              "Base and quote reference asset should be different" );
   FC_ASSERT( !series.empty(), "An oracle should declare at least one series" );
   FC_ASSERT( series.size() <= size_t( GRAPHENE_ORACLE_MAX_SERIES ),
              "An oracle may declare at most ${m} series", ("m", GRAPHENE_ORACLE_MAX_SERIES) );
   for( const auto& s : series )
      s.validate();
   options.validate();
}

share_type oracle_create_operation::calculate_fee( const fee_params_t& schedule )const
{
   share_type core_fee_required = schedule.fee;
   core_fee_required += calculate_data_fee( fc::raw::pack_size(*this), schedule.price_per_kbyte );
   return core_fee_required;
}

void oracle_update_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( new_description.valid() || new_options.valid(),
              "Should change something" );
   if( new_description.valid() )
      FC_ASSERT( new_description->size() <= GRAPHENE_ORACLE_MAX_DESCRIPTION_LENGTH,
                 "Description should not exceed ${m} characters",
                 ("m", GRAPHENE_ORACLE_MAX_DESCRIPTION_LENGTH) );
   if( new_options.valid() )
      new_options->validate();
}

share_type oracle_update_operation::calculate_fee( const fee_params_t& schedule )const
{
   share_type core_fee_required = schedule.fee;
   core_fee_required += calculate_data_fee( fc::raw::pack_size(*this), schedule.price_per_kbyte );
   return core_fee_required;
}

void oracle_delete_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
}

void oracle_unfreeze_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
}

void oracle_publish_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( !values.empty(), "Published values should not be empty" );
   FC_ASSERT( values.size() <= size_t( GRAPHENE_ORACLE_MAX_SERIES ),
              "Published values exceed the maximum series count" );
   // Whether the count matches the oracle's declared series is chain state, so it is
   // checked in the evaluator; here each carried value must stand on its own.
   for( const auto& v : values )
      v.validate();
}

price convert_oracle_value_to_price(
   const oracle_value& v,
   const reference_mapping& debt_mapping, asset_id_type debt_asset,
   const reference_mapping& backing_mapping, asset_id_type backing_asset,
   oracle_series_rounding rounding )
{
   // The common case (HONEST.USD -> USD, BTS -> BTS): the oracle value already IS the
   // price, and no arithmetic runs at all. Rationals confine rounding to the places
   // where two scales genuinely differ.
   if( debt_mapping.asset_amount == debt_mapping.reference_amount
       && backing_mapping.asset_amount == backing_mapping.reference_amount )
      return price( asset( v.base_amount, debt_asset ), asset( v.quote_amount, backing_asset ) );

   // Exact integer arithmetic throughout: boost::multiprecision::cpp_int is software
   // integers with no rounding and no platform-dependent behaviour, so two nodes
   // computing from identical inputs agree bit for bit. (Precedent: int256_t in
   // market_object.cpp.) Each side is a product of three int64 values, each bounded by
   // GRAPHENE_MAX_SHARE_SUPPLY, so well within any precision concern.
   using boost::multiprecision::cpp_int;
   const cpp_int N = cpp_int( debt_mapping.asset_amount.value )
                   * v.base_amount.value
                   * backing_mapping.reference_amount.value;
   const cpp_int D = cpp_int( debt_mapping.reference_amount.value )
                   * v.quote_amount.value
                   * backing_mapping.asset_amount.value;

   // Reduce by the greatest common divisor before anything else: most real mappings
   // cancel here and never reach the scaling below.
   cpp_int a = N > 0 ? N : -N;
   cpp_int b = D > 0 ? D : -D;
   while( b != 0 )
   {
      const cpp_int r = a % b;
      a = b;
      b = r;
   }
   const cpp_int num = N / a;
   const cpp_int den = D / a;

   // The one place rounding happens: a side past GRAPHENE_MAX_SHARE_SUPPLY cannot be a
   // price amount, so both sides come down by one common factor, in the direction the
   // chosen series declares. An unspecified series behaves as down.
   const cpp_int cap = GRAPHENE_MAX_SHARE_SUPPLY;
   const cpp_int mx = num > den ? num : den;
   cpp_int out_num = num;
   cpp_int out_den = den;
   if( mx > cap )
   {
      const cpp_int scale = ( mx + cap - 1 ) / cap;
      if( oracle_series_rounding::up == rounding )
      {
         out_num = ( num + scale - 1 ) / scale;
         out_den = ( den + scale - 1 ) / scale;
      }
      else
      {
         out_num = num / scale;
         out_den = den / scale;
         // A floor that vanishes would be a null amount downstream; keep it at 1. Only
         // reachable when one side is smaller than the scale, i.e. a ratio more extreme
         // than the supply cap -- economically absurd, but consensus must still agree.
         if( out_num <= 0 ) out_num = 1;
         if( out_den <= 0 ) out_den = 1;
      }
   }

   return price( asset( out_num.convert_to<int64_t>(), debt_asset ),
                 asset( out_den.convert_to<int64_t>(), backing_asset ) );
}

void oracle_foreign_publish_operation::validate()const
{
   FC_ASSERT( fee.amount >= 0, "Fee should not be negative" );
   FC_ASSERT( value.amount > 0,
              "A published foreign transaction record must carry a positive amount" );
   bool nonzero = false;
   for( const uint8_t b : value.tx_id.hash )
      if( b != 0 )
         nonzero = true;
   FC_ASSERT( nonzero, "A published foreign transaction record must carry a transaction id" );
   value.validate();
}

} } // graphene::protocol

GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_series )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_value )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_producer_entry )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_producer_reputation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::price_oracle )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reference_mapping )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_options )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reference_asset_create_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_create_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_update_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_delete_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_publish_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::reference_asset_create_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_create_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_update_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_unfreeze_operation::fee_params_t )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_unfreeze_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_delete_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_publish_operation )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::foreign_tx_id )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::foreign_tx_value )
GRAPHENE_IMPLEMENT_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_foreign_publish_operation )
