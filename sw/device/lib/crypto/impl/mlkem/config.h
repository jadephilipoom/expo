// Copyright The mlkem-native project authors
// Copyright zeroRISC Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_LIB_CRYPTO_IMPL_MLKEM_CONFIG_H_
#define OPENTITAN_SW_DEVICE_LIB_CRYPTO_IMPL_MLKEM_CONFIG_H_

/******************************************************************************
 * Name:        MLK_CONFIG_NAMESPACE_PREFIX
 *
 * Description: The prefix to use to namespace global symbols from mlkem/.
 *
 *              In a multi-level build (that is, if either
 *              - MLK_CONFIG_MULTILEVEL_WITH_SHARED, or
 *              - MLK_CONFIG_MULTILEVEL_NO_SHARED,
 *              are set, level-dependent symbols will additionally be prefixed
 *              with the parameter set (512/768/1024).
 *
 *              This can also be set using CFLAGS.
 *
 *****************************************************************************/
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem

/******************************************************************************
 * Name:        MLK_CONFIG_NO_RANDOMIZED_API
 *
 * Description: If this option is set, mlkem-native will be built without the
 *              randomized API functions (crypto_kem_keypair and
 *              crypto_kem_enc).
 *.             This allows users to build mlkem-native without providing a
 *              randombytes() implementation if they only need the
 *              deterministic API
 *              (crypto_kem_keypair_derand, crypto_kem_enc_derand,
 *              crypto_kem_dec).
 *
 *              NOTE: This option is incompatible with MLK_CONFIG_KEYGEN_PCT
 *              as the current PCT implementation requires crypto_kem_enc().
 *
 *****************************************************************************/
#define MLK_CONFIG_NO_RANDOMIZED_API

/******************************************************************************
 * Name:        MLK_CONFIG_INTERNAL_API_QUALIFIER
 *
 * Description: If set, this option provides an additional function
 *              qualifier to be added to declarations of internal API.
 *
 *              The primary use case for this option are single-CU builds,
 *              in which case this option can be set to `static`.
 *
 *****************************************************************************/
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static

/******************************************************************************
 * Name:        MLK_CONFIG_FIPS202_CUSTOM_HEADER
 *
 * Description: Custom header to use for FIPS-202
 *
 *              This should only be set if you intend to use a custom
 *              FIPS-202 implementation, different from the one shipped
 *              with mlkem-native.
 *
 *              If set, it must be the name of a file serving as the
 *              replacement for mlkem/fips202/fips202.h, and exposing
 *              the same API (see FIPS202.md).
 *
 *****************************************************************************/
#define MLK_CONFIG_FIPS202_CUSTOM_HEADER "fips202_glue.h"

/******************************************************************************
 * Name:        MLK_CONFIG_FIPS202X4_CUSTOM_HEADER
 *
 * Description: Custom header to use for FIPS-202-X4
 *
 *              This should only be set if you intend to use a custom
 *              FIPS-202 implementation, different from the one shipped
 *              with mlkem-native.
 *
 *              If set, it must be the name of a file serving as the
 *              replacement for mlkem/fips202/fips202x4.h, and exposing
 *              the same API (see FIPS202.md).
 *
 *****************************************************************************/
#define MLK_CONFIG_FIPS202X4_CUSTOM_HEADER "fips202x4_glue.h"

/******************************************************************************
 * Name:        MLK_CONFIG_SERIAL_FIPS202_ONLY
 *
 * Description: If this option is set, batched Keccak operations will be
 *              disabled for rejection sampling during matrix generation.
 *              Instead, matrix entries will be generated one at a time.
 *
 *              This allows offloading Keccak computations to a hardware
 *              accelerator that holds only a single Keccak state locally,
 *              rather than requiring support for batched (4x) Keccak states.
 *
 *              NOTE: Depending on the target CPU, disabling batched Keccak
 *              may reduce performance when using software FIPS202
 *              implementations. Only enable this when you have to.
 *
 *****************************************************************************/
#define MLK_CONFIG_SERIAL_FIPS202_ONLY

#endif  // OPENTITAN_SW_DEVICE_LIB_CRYPTO_IMPL_MLKEM_CONFIG_H_
