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
#include <array>

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

   /**
    * Track A guard: the most the guarded (consumed) value may move in one promotion,
    * in parts per million. Proposal value: 5%. A spike beyond the bound holds the
    * last-good value and raises the rate_limited flag; it never jumps. Exact integer
    * ratio comparison, like the deviation filter -- no floats anywhere.
    */
   constexpr uint32_t GRAPHENE_ORACLE_GUARD_MAX_MOVE_PPM = 50000;

   /**
    * Track A guard: OSM-style delay proposal default (1h). How long a computed median
    * waits before it becomes consumable for margin/settlement. Lives as the
    * oracle_guard_delay_sec chain parameter so the committee owns it; this constant is
    * the default while the parameter is absent.
    */
   constexpr uint32_t GRAPHENE_ORACLE_GUARD_DEFAULT_DELAY_SEC = 3600;

   /// Upper bound on the committee-set guard delay (1 day). Bounds the pending queue's
   /// time span; enforced in chain_parameters::validate().
   constexpr uint32_t GRAPHENE_ORACLE_GUARD_MAX_DELAY_SEC = 86400;
   /// H1-FINAL-06 + R17G: coded floor on the committee-set OSM
   /// delay. Sub-minute values are refused at validate (the unset default is
   /// the floor), and the whole-hour stall classes are covered by the R17G
   /// bucket repair plus the t8b2 regression.
   constexpr uint32_t GRAPHENE_ORACLE_GUARD_MIN_DELAY_SEC
      = GRAPHENE_ORACLE_GUARD_DEFAULT_DELAY_SEC;

   /// Upper bound on an oracle's guarded pending queue. Samples are bucketed so a full
   /// queue always spans the configured delay whatever the publish rate.
   constexpr uint32_t GRAPHENE_ORACLE_GUARD_MAX_PENDING = 16;

   /**
    * GOV-R9-02 consensus time-lock: a challenge-set freeze costs a 2/3
    * supermajority of the deciding set, while `oracle_unfreeze` costs one
    * seated member and one op fee. The op therefore may not apply until this
    * many seconds after the oracle's `open_disputes` last reached 0 (the
    * clear anchor is recorded then; never recorded = never cleared = never
    * unfrozen through this op). Integer seconds against head-block time
    * only: no wall-clock, no floats.
    */
   constexpr uint32_t GRAPHENE_ORACLE_UNFREEZE_DELAY_SEC = 14 * 24 * 60 * 60;

    constexpr size_t GRAPHENE_REFERENCE_ASSET_MIN_SYMBOL_LENGTH = 2;
    constexpr size_t GRAPHENE_REFERENCE_ASSET_MAX_SYMBOL_LENGTH = 16;
    constexpr size_t GRAPHENE_REFERENCE_ASSET_MAX_DESCRIPTION_LENGTH = 1000;
    /// Kept identical to an asset's precision bound: a reference asset has a smallest unit
    /// exactly like an asset does, so the same range applies.
    constexpr uint8_t GRAPHENE_REFERENCE_ASSET_MAX_PRECISION = 12;

    /**
     * The precision a reference asset named "BTS" must be created with. The core asset
     * (1.3.0) maps 1:1 to the BTS reference by protocol rule, and the core asset's own
     * precision is 5 (GRAPHENE_BLOCKCHAIN_PRECISION = 10^5): any other precision on the
     * reference side would silently mis-scale every core-quoted conversion. Enforced at
     * creation, in the operation's validate() and again in its evaluator.
     */
    constexpr uint8_t GRAPHENE_REFERENCE_ASSET_BTS_PRECISION = 5;

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
      ask        = 3,
      foreign_tx = 4
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

    /// Foreign chain identifiers (H3). Appended enum, never inserted.
    enum class foreign_chain_id : uint8_t
    {
       bitcoin  = 0,
       ethereum = 1,
       solana   = 2
    };

    /// Fixed-size foreign transaction id (32 bytes, all chains).
    struct foreign_tx_id
    {
       std::array<uint8_t, 32> hash{};

       foreign_tx_id() = default;
       explicit foreign_tx_id( const std::array<uint8_t, 32>& h ) : hash( h ) {}

       bool operator==( const foreign_tx_id& o ) const { return hash == o.hash; }
       bool operator!=( const foreign_tx_id& o ) const { return hash != o.hash; }
       bool operator<( const foreign_tx_id& o ) const { return hash < o.hash; }
    };

    /// Event kind reported by a foreign chain transaction oracle.
    enum class foreign_tx_kind : uint8_t
    {
       lock   = 0,
       unlock = 1,
       refund = 2
    };

    /// Value reported by a foreign chain transaction oracle (an event, not a ratio).
    struct foreign_tx_value
    {
       foreign_chain_id  chain = foreign_chain_id::bitcoin;
       foreign_tx_id     tx_id;
       foreign_tx_kind   kind = foreign_tx_kind::lock;
       int64_t           amount = 0;
       uint8_t           foreign_asset_id = 0;
       uint64_t          confirmation_height = 0;

       foreign_tx_value() = default;

       void validate() const
       {
          FC_ASSERT( amount >= 0, "Foreign tx amount must be non-negative" );
       }
    };

    bool operator==( const foreign_tx_value& a, const foreign_tx_value& b );
    inline bool operator!=( const foreign_tx_value& a, const foreign_tx_value& b )
    { return !( a == b ); }

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

   /**
    * Track A guard: one producer's liveness/deviation history, accrued on-chain.
    *
    * Counts only -- deliberately no weights, no rewards, no slashing (H2 economics are
    * out of scope). publish_count counts publish operations; live_count counts rounds
    * the producer's submission was live toward the aggregate; outlier_count counts
    * rounds the quorum-aware filter excluded it. Queryable through the existing oracle
    * read API, which returns the whole object.
    */
   struct oracle_producer_reputation
   {
      uint32_t publish_count = 0;
      uint32_t live_count = 0;
      uint32_t outlier_count = 0;
      time_point_sec last_publish_time;
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

      /**
       * Track A guard: emergency freeze. While set, the oracle still aggregates (raw
       * values stay transparent) but nothing is promoted to the consumed value and
       * bound consumers read no price, so margin actions fail closed. Set and cleared
       * by the owner through oracle_update; clearing through a proposal vote is the
       * supported Track A unfreeze path. R-02: challenge-set freezes
       * (sustain/expiry with terminal dispute history, or any open dispute)
       * are NOT clearable by the owner (refused in consensus) and clear only
       * through the committee oracle_unfreeze op. Appended AFTER extensions,
       * never inserted before them, so every pre-existing field keeps its wire
       * position.
       */
      bool frozen = false;

      /**
       * Track A guards, new-pairs-only opt-in. Both default OFF, in which case the
       * guarded (consumed) value tracks the raw aggregate immediately with no band:
       * an oracle that never opts in behaves exactly as before guards existed
       * (existing oracle-bound pairs are byte-identical). A NEW pair opts in at
       * creation (or later via update):
       * - guard_rate_limit: bound the consumed value's movement per maintenance
       *   interval to GRAPHENE_ORACLE_GUARD_MAX_MOVE_PPM; spikes beyond it hold the
       *   last-good value and raise the flag, never jump.
       * - guard_delay: hold the raw aggregate in the delay queue until the
       *   committee-owned guard delay (chain parameter, 1h proposal) has passed
       *   (OSM-style: computed at N, consumable at N + delay).
       * Appended after frozen, never inserted: wire positions are append-only.
       */
      bool guard_rate_limit = false;
      bool guard_delay = false;

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

    bool operator==( const reference_mapping& a, const reference_mapping& b );
    inline bool operator!=( const reference_mapping& a, const reference_mapping& b )
    { return !( a == b ); }

    /**
     * @brief A smartcoin's binding to an oracle: WHICH oracle and WHICH of its series.
     *
     * The legacy price_oracle_id binding names an oracle but no series (it reads series 0
     * and is refused against multi-series oracles). This struct names both, so several
     * consumers can read different series of one oracle and no consumer silently reads a
     * series it did not choose. Appended as bitasset_options::ext::price_oracle_binding; the two
     * fields are mutually exclusive on one asset.
     *
     * Every explicit binding carries a consensus expiry height (a head block number, never
     * a timestamp: no wall-clock, no time conversion anywhere on this path). Past expiry
     * the binding yields no price -- the read path fails closed exactly as on mapping
     * drift -- which blocks new debt through the existing null-settlement-price rule
     * while leaving legacy pairs untouched. The field is appended LAST in this struct
     * (never inserted): wire-tag stability for the struct's own encoding is pinned by
     * price_oracle_expiry_round_trips. A binding with expiry_height == 0 never validates
     * (see price_oracle::validate): expiry is mandatory, never defaulted.
     */
    struct price_oracle
    {
       oracle_id_type oracle_id;
       /// Index into the oracle's declared series list. Range-checked against the oracle
       /// at bind time; the read path re-checks (fail closed on drift).
       uint16_t series = 0;
       /// Head block number past which this binding yields no price. Must be strictly
       /// in the future at bind time and can never be extended while bound (the bind
       /// evaluator refuses any change to a live binding; unbinding is allowed). There
       /// is no committee extend path by construction: no operation and no chain
       /// parameter touches this field after binding.
       uint32_t expiry_height = 0;

       void validate()const;
    };

    inline bool operator==( const price_oracle& a, const price_oracle& b )
    { return a.oracle_id == b.oracle_id && a.series == b.series && a.expiry_height == b.expiry_height; }
    inline bool operator!=( const price_oracle& a, const price_oracle& b )
    { return !( a == b ); }

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
    * @brief Committee unfreeze for challenge-set oracle freezes (R-02).
    * @ingroup operations
    *
    * Owner `oracle_update` MUST NOT clear `frozen` while the oracle carries
    * open disputes or a sustain/expiry freeze (challenge-set): that path is
    * refused in consensus and must come here instead. Only a seated
    * committee member may unfreeze, and only when no dispute is open
    * (clearing after resolution, never mid-vote). Slash stays flag-only in
    * this task (slash-to-seizure is a follow-on phase): this op clears the
    * freeze flag only, never seizes bonds. Price-leg gated (touches the H2
    * debt tap), tag 97, extensions appended-last.
    */
   struct oracle_unfreeze_operation : public base_operation
   {
      struct fee_params_t { uint64_t fee = 5 * GRAPHENE_BLOCKCHAIN_PRECISION; };

      asset           fee;
      account_id_type unfreezer; ///< Must be a seated committee member; pays the fee
      oracle_id_type  oracle;    ///< Must be frozen with zero open disputes

      extensions_type extensions; ///< Appended-last rule

      account_id_type fee_payer()const { return unfreezer; }
      void            validate()const;
   };

   /**
    * @brief Removes an oracle.
    * @ingroup operations
    *
    * Refused while anything on chain still references it.
    */
    struct oracle_delete_operation : public base_operation
    {
       // Zero by design (R7C-H2 fee-floor review): owner-only cleanup, refused
       // while anything references the oracle, and each deletable oracle cost
       // 500 BTS to create -- delete-spam is bounded by creation (1k deletes
       // cost 500k BTS in creations), so a fee would only tax hygiene. Matches
       // the chain-wide delete/cancel precedent (pool/fund/permission/offer
       // deletes, order cancels are all zero-fee). No rate-limit: the creation
       // cost dominates any flood the free delete could carry.
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
                 (mid)(last)(bid)(ask)(foreign_tx) )
FC_REFLECT_ENUM( graphene::protocol::foreign_chain_id,
                  (bitcoin)(ethereum)(solana) )
FC_REFLECT_ENUM( graphene::protocol::foreign_tx_kind,
                  (lock)(unlock)(refund) )
FC_REFLECT_ENUM( graphene::protocol::oracle_series_rounding,
                 (unspecified)(down)(up) )

FC_REFLECT( graphene::protocol::oracle_series,
            (kind)(rounding) )

FC_REFLECT( graphene::protocol::oracle_value,
            (base_amount)(quote_amount) )

FC_REFLECT( graphene::protocol::foreign_tx_id,
            (hash) )

FC_REFLECT( graphene::protocol::foreign_tx_value,
            (chain)(tx_id)(kind)(amount)(foreign_asset_id)(confirmation_height) )

FC_REFLECT( graphene::protocol::oracle_producer_entry,
             (weight)(extensions) )

FC_REFLECT( graphene::protocol::oracle_producer_reputation,
             (publish_count)(live_count)(outlier_count)(last_publish_time) )

FC_REFLECT( graphene::protocol::price_oracle,
             (oracle_id)(series)(expiry_height) )

FC_REFLECT( graphene::protocol::reference_mapping,
            (reference)(asset_amount)(reference_amount) )

FC_REFLECT( graphene::protocol::oracle_options,
            (producers)(minimum_producers)(value_lifetime_sec)(aggregation)(window_sec)
            (max_deviation_ppm)(extensions)(frozen)(guard_rate_limit)(guard_delay) )

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
FC_REFLECT( graphene::protocol::oracle_unfreeze_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::oracle_unfreeze_operation,
            (fee)(unfreezer)(oracle)(extensions) )
FC_REFLECT( graphene::protocol::oracle_delete_operation,
            (fee)(owner)(oracle_id)(extensions) )
FC_REFLECT( graphene::protocol::oracle_publish_operation,
            (fee)(producer)(oracle_id)(values)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_series )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_value )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::foreign_tx_id )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::foreign_tx_value )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_producer_entry )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_producer_reputation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::price_oracle )
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
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_unfreeze_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_unfreeze_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_delete_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::oracle_publish_operation )
