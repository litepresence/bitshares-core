# G1 vendored proof lineage — provenance + build rule

NEW consensus code lives in `../` (`stealth_proof.{hpp,cpp}`, evaluators).
The files below are REFERENCE ONLY: they are never compiled into
`witness_node` / `chain_test`. The build performs no network fetch; the exact
G1a-pinned sources are vendored here so the secp256k1 port in `../` can be
audited line-by-line against its lineage without trusting a remote.

## Pins (G1a report `/workspace/build/task-g1a-report.md`, all verified by build)

- S1 monero-project/monero master commit
  `e4fbca88b15f3cb2b6aa2d0e98639649f7da3d21` (2026-09-26)
  URL: https://github.com/monero-project/monero
  Files: `src/ringct/rctSigs.{cpp,h}` (CLSAG prove/verify),
  `bulletproofs_plus.{cc,h}` (BP+ prove/verify),
  `bulletproofs.{cc,h}` (original BP, size/baseline reference),
  `rctOps.cpp`, `rctOps.h`, `rctTypes.h` (key images, H/NUMS constant,
  hash-to-point lineage).
- S2 mimblewimble/secp256k1-zkp commit
  `b247e1ec8ed62b9abf123dc83189d253e17d488d` (2023-05-16, "Merge PR #67")
  URL: https://github.com/mimblewimble/secp256k1-zkp
  Files: `src/modules/{commitment,generator,rangeproof,bulletproofs}/`
  (Pedersen + Borromean + original-BP lineage on secp256k1, C).

Reference only (NOT vendored, API-design signal):
BlockstreamResearch/secp256k1-zkp @ `8e1f96c20e16bf960be6caec7f3c94acb360cdf2`.

## Why reference-only, not compiled

1. S1 is ed25519/Curve25519; graphene blind keys are secp256k1. Compiling S1
   would link a second curve backend into consensus for code that cannot verify
   our wire format. The port lineage is the CLSAG construction (Goodell et al.
   2019-654, curve-generic) and the BP+ protocol (2020-735), re-instantiated
   over secp256k1 in `../stealth_proof.cpp` (NEW code, pre-G1 audit gate).
2. S2 is autotools C with its own build; consensus links OpenSSL + fc's
   secp256k1 already. Re-implementing the needed EC ops on the linked backend
   keeps one audited toolchain (C++17, g++ 11.4) per consensus law.
3. fc's vendored secp256k1-zkp (@bd06794, Borromean-era, no `src/modules/`)
   is SUPERSEDED for the new proof path by `../stealth_proof.cpp`; the legacy
   blind path (ops 39-41, V1 proofs) keeps using fc's `verify_range` untouched.

## S-02: the `fc @ bd067945` snapshot is legacy-blind-only

The secp256k1-zkp snapshot vendored inside `libraries/fc` (commit
`bd067945`, Borromean era) predates the upstream `src/modules/`
rangeproof/bulletproofs work (S2 above, 2023). Its consensus role is
narrow and frozen: it verifies legacy V1 Borromean proofs for ops 39-41
(`transfer_to_blind`, `blind_transfer`, `transfer_from_blind`) via fc's
`verify_range`/`range_proof_sign`, and NOTHING else. It is never a
dependency of the new G1 path: `../stealth_proof.cpp` (rings, BP+,
conservation kernel) links OpenSSL + fc's secp256k1 EC primitives only,
and the CMake guard in `libraries/chain/CMakeLists.txt` (S-02) fails the
configure if any `stealth/vendor/` file ever enters a consensus target.
Any future proof upgrade vendors its lineage here with fresh pins — the
`fc` snapshot is not upgraded in place for G1 purposes.

## SHA256 of vendored files (measured at vendor time)

monero-ringct/:
- bulletproofs.cc      fe61080cfbe7710847a97ea49e8463928cc4ae83eab439e623eda070b9dd17b0
- bulletproofs.h       e36c28a84778076d333fcf6011fb986058f75d8238855fa0d0aa796923c6e2bd
- bulletproofs_plus.cc 3b77634f01a1d5e7f007c5fcf8b6bad0eab0689ad277a18a825f17fee4a43d20
- bulletproofs_plus.h  64d3dc95fe1da6fd48c29ff14664a10f1148b4101e48efadda1922e14a92745d
- rctOps.cpp           0cd3cbb185c4053e8b17b3a6279d02bfe18b6f48a61e0e334f7baa3a2cd46d77
- rctOps.h             dc34e9a64653c2f16a479228e4c0e3df907ecfacade80fce17b4808458a1dc10
- rctSigs.cpp          44288c9f166206a329747a9bcd0b879b996e9c62f12ea452bc0fc1d4f694d38d
- rctSigs.h            60dd8268f5c8c9c2ba00e59db1f2f819e37530ad00aedb09719728dd8c10a9f3
- rctTypes.h           b7ae21c0b4119d5c0431f85fb9b0850591213f88096e89cd7cec01a117534b33

secp256k1-zkp-modules/:
- bulletproofs/inner_product_impl.h  b93fc6eed017b570f20464164cec33cd4ad15dfb8f50e00404eefb40d1a6584f
- bulletproofs/main_impl.h           3d24d0ac45f14d1cd8e356df6801035c999c163216843248ec5f836a9834f750
- bulletproofs/rangeproof_impl.h     88935a658d6912f660e4ee85cfe446f36175f0129093a69872ca1a533047f83a
- bulletproofs/tests_impl.h          7ca263171b33f99c4671a221dc6deee7ab8796c19f5db6bcd27ab62ff3a23e13
- bulletproofs/util.h                2c5c67cbacab267f5d68334d81d764b8a901ec43be9c5f7beb851fbef4604510
- commitment/main_impl.h             2e4faf2d66601e459cc37ab6d1465ea2b4fd6d6a660a39c09468801f1f24dc16
- commitment/pedersen_impl.h         2abcb1bed49d470c4bdab2658fbd3f610984fceccc268f7379d6faec46b6ac16
- commitment/tests_impl.h            6f1a4a1ccdca77dd5bf1513802b8808432e868720ef1327121670a54df59439a
- generator/main_impl.h              065152e9409692d302023decc6ea2fe6c03a6af462435150f73be9ce8246f9f8
- generator/tests_impl.h             6ec8063c932e3343792058e4cb4c39ed4973ddf89e7a2bab677e0d5834ee950b0
- rangeproof/borromean.h             668ad333886c5a7db3f518cdc9acf88fc78eaad04e6d280fcb0ee58a571b94ee
- rangeproof/borromean_impl.h        83b3fb20ae6782f754252333273a7f55a222b1d5670afad02a6885936f06d2ab
- rangeproof/main_impl.h             be0404a7dba6ac56dc8dfb269c66dc9498e0fe4c76c49747028e155095f045ee
- rangeproof/rangeproof.h            f136150e8e7347ff0bfac863581d9d0506bf1d4f528bf29750a7db4d2d4a8b54
- rangeproof/rangeproof_impl.h       2d15388aa11b34718d2e3528ba1354e3872890afa4d82f1d222d89ea7b70c8e8
- rangeproof/tests_impl.h            5668f69a04ef1a150d0c67cf3330790f6b7a7778bd4e0da0d319d190fcb9c2af

Vendored build files (recorded G1b-2 P7; reference-only, never compiled):
- bulletproofs/Makefile.am.include  78b28bbc4012439b2c7d532e5d7a8dbd0b6dd06a5838f00c42f17ca51d441d14
- commitment/Makefile.am.include    5d85f3cd4461b2ca81add2413f010c0f620f7b503bfbb9725f18cef3fa5cdc4a
- generator/Makefile.am.include     93399ccf579c755b8ef1f9fe338cd987d33ea3c1b3ac203dc6f3462950ec723f
- rangeproof/Makefile.am.include    df5decc9948ae34c5e2c9cc569b4a6145d110af94db56d1b1b718bed44f7aa14

Re-verify with: `sha256sum <file>` against the list above.

## Parameter provenance (reproducible, no trusted setup)

- CLSAG: transparent Schnorr setup, nothing to trapdoor. S1 NUMS second
  generator `rct::H` (`rctTypes.h`, `= toPoint(cn_fast_hash(G))` per
  `rctOps.cpp`): ed25519 point, NOT reused. G1 secp256k1 `H_G1` is derived in
  `../stealth_proof.cpp` by try-and-increment over
  `sha256("BitShares-G1-H-secp256k1-v1" || G_compressed)` with a consensus test
  vector pinning the resulting compressed point. Any change of H_G1 is a
  wire-breaking change gated like an op.
- BP+ generators Gi/Hi: derived at verify time from source per proof (S1:
  `hash_to_p3(cn_fast_hash(H || "bulletproof_plus" || varint(i)))`,
  `bulletproofs_plus.cc:108-114`). G1 port derives over secp256k1 from the
  fixed consensus seed `"BitShares-G1-BP-secp256k1-v1"` + domain separators;
  the seed string is embedded in consensus code with a generator test vector.
- NOT vendored / out of scope: Monero's Rust FCMP++ component, wallet code,
  P2P code, `contrib/guix` tree.
