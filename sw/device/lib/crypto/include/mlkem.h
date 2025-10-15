// Copyright The mlkem-native project authors
// Copyright zeroRISC Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_LIB_CRYPTO_INCLUDE_MLKEM_H_
#define OPENTITAN_SW_DEVICE_LIB_CRYPTO_INCLUDE_MLKEM_H_

#include "datatypes.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

enum {
  kOtcryptoMlkem512PublicKeyBytes = 800,
  kOtcryptoMlkem512SecretKeyBytes = 1632,
  kOtcryptoMlkem512CiphertextBytes = 768,
  kOtcryptoMlkem512SharedSecretBytes = 32,
  kOtcryptoMlkem512KeygenSeedBytes = 64,

  kOtcryptoMlkem768PublicKeyBytes = 1184,
  kOtcryptoMlkem768SecretKeyBytes = 2400,
  kOtcryptoMlkem768CiphertextBytes = 1088,
  kOtcryptoMlkem768SharedSecretBytes = 32,
  kOtcryptoMlkem768KeygenSeedBytes = 64,

  kOtcryptoMlkem1024PublicKeyBytes = 1568,
  kOtcryptoMlkem1024SecretKeyBytes = 3168,
  kOtcryptoMlkem1024CiphertextBytes = 1568,
  kOtcryptoMlkem1024SharedSecretBytes = 32,
  kOtcryptoMlkem1024KeygenSeedBytes = 64,
};

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem512_keygen(otcrypto_byte_buf_t public_key,
                                           otcrypto_byte_buf_t secret_key);

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem512_keygen_derand(
    otcrypto_const_byte_buf_t randomness, otcrypto_byte_buf_t public_key,
    otcrypto_byte_buf_t secret_key);

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem512_encapsulate(
    otcrypto_const_byte_buf_t public_key, otcrypto_byte_buf_t ciphertext,
    otcrypto_byte_buf_t shared_secret);

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem512_encapsulate_derand(
    otcrypto_const_byte_buf_t public_key, otcrypto_const_byte_buf_t randomness,
    otcrypto_byte_buf_t ciphertext, otcrypto_byte_buf_t shared_secret);

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem512_decapsulate(
    otcrypto_const_byte_buf_t secret_key, otcrypto_const_byte_buf_t ciphertext,
    otcrypto_byte_buf_t shared_secret);

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem768_keygen(otcrypto_byte_buf_t public_key,
                                           otcrypto_byte_buf_t secret_key);

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem768_keygen_derand(
    otcrypto_const_byte_buf_t randomness, otcrypto_byte_buf_t public_key,
    otcrypto_byte_buf_t secret_key);

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem768_encapsulate(
    otcrypto_const_byte_buf_t public_key, otcrypto_byte_buf_t ciphertext,
    otcrypto_byte_buf_t shared_secret);

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem768_encapsulate_derand(
    otcrypto_const_byte_buf_t public_key, otcrypto_const_byte_buf_t randomness,
    otcrypto_byte_buf_t ciphertext, otcrypto_byte_buf_t shared_secret);

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem768_decapsulate(
    otcrypto_const_byte_buf_t secret_key, otcrypto_const_byte_buf_t ciphertext,
    otcrypto_byte_buf_t shared_secret);

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem1024_keygen(otcrypto_byte_buf_t public_key,
                                            otcrypto_byte_buf_t secret_key);

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem1024_keygen_derand(
    otcrypto_const_byte_buf_t randomness, otcrypto_byte_buf_t public_key,
    otcrypto_byte_buf_t secret_key);

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem1024_encapsulate(
    otcrypto_const_byte_buf_t public_key, otcrypto_byte_buf_t ciphertext,
    otcrypto_byte_buf_t shared_secret);

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem1024_encapsulate_derand(
    otcrypto_const_byte_buf_t public_key, otcrypto_const_byte_buf_t randomness,
    otcrypto_byte_buf_t ciphertext, otcrypto_byte_buf_t shared_secret);

OT_WARN_UNUSED_RESULT
otcrypto_status_t otcrypto_mlkem1024_decapsulate(
    otcrypto_const_byte_buf_t secret_key, otcrypto_const_byte_buf_t ciphertext,
    otcrypto_byte_buf_t shared_secret);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // OPENTITAN_SW_DEVICE_LIB_CRYPTO_INCLUDE_MLKEM_H_
