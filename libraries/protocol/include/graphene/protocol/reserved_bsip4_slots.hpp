// SPDX-License-Identifier: MIT
#pragma once
#include <graphene/protocol/base.hpp>
#include <graphene/protocol/asset.hpp>

namespace graphene { namespace protocol {

// Reserved slots 78-117 for the H/G/F tracks in combined builds.
// In this standalone BSIP-4 branch these are disabled stubs so that
// reciprocity operations occupy tags 118-123 (P4-01).

struct reserved_bsip4_slot_78_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_79_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_80_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_81_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_82_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_83_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_84_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_85_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_86_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_87_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_88_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_89_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_90_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_91_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_92_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_93_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_94_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_95_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_96_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_97_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_98_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_99_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_100_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_101_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_102_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_103_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_104_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_105_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_106_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_107_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_108_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_109_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_110_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_111_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_112_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_113_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_114_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_115_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_116_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

struct reserved_bsip4_slot_117_operation : public base_operation
{
   struct fee_params_t { uint64_t fee = GRAPHENE_BLOCKCHAIN_PRECISION; };
   asset fee;
   account_id_type fee_payer() const { return account_id_type(); }
   void validate() const {}
   extensions_type extensions;
};

} } // graphene::protocol

FC_REFLECT( graphene::protocol::reserved_bsip4_slot_78_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_79_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_80_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_81_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_82_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_83_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_84_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_85_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_86_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_87_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_88_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_89_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_90_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_91_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_92_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_93_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_94_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_95_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_96_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_97_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_98_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_99_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_100_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_101_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_102_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_103_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_104_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_105_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_106_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_107_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_108_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_109_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_110_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_111_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_112_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_113_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_114_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_115_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_116_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_117_operation::fee_params_t, (fee) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_78_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_79_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_80_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_81_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_82_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_83_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_84_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_85_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_86_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_87_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_88_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_89_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_90_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_91_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_92_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_93_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_94_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_95_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_96_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_97_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_98_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_99_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_100_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_101_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_102_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_103_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_104_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_105_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_106_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_107_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_108_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_109_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_110_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_111_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_112_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_113_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_114_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_115_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_116_operation, (fee)(extensions) )
FC_REFLECT( graphene::protocol::reserved_bsip4_slot_117_operation, (fee)(extensions) )

GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_78_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_79_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_80_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_81_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_82_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_83_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_84_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_85_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_86_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_87_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_88_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_89_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_90_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_91_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_92_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_93_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_94_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_95_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_96_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_97_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_98_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_99_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_100_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_101_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_102_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_103_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_104_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_105_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_106_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_107_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_108_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_109_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_110_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_111_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_112_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_113_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_114_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_115_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_116_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_117_operation::fee_params_t )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_78_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_79_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_80_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_81_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_82_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_83_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_84_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_85_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_86_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_87_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_88_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_89_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_90_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_91_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_92_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_93_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_94_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_95_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_96_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_97_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_98_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_99_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_100_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_101_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_102_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_103_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_104_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_105_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_106_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_107_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_108_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_109_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_110_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_111_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_112_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_113_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_114_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_115_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_116_operation )
GRAPHENE_DECLARE_EXTERNAL_SERIALIZATION( graphene::protocol::reserved_bsip4_slot_117_operation )
