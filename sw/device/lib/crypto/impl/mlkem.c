// Copyright The mlkem-native project authors
// Copyright zeroRISC Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/crypto/include/mlkem.h"

#include "sw/device/lib/base/math.h"
#include "sw/device/lib/crypto/drivers/entropy.h"
#include "sw/device/lib/crypto/impl/integrity.h"
#include "sw/device/lib/crypto/impl/keyblob.h"
#include "sw/device/lib/crypto/impl/mlkem/mlkem_native_monobuild.h"
#include "sw/device/lib/crypto/impl/status.h"

// Module ID for status codes.
#define MODULE_ID MAKE_MODULE_ID('m', 'l', 'k')

// ML-KEM-512 functions

otcrypto_status_t otcrypto_mlkem512_keygen_derand(
    otcrypto_const_byte_buf_t randomness, otcrypto_unblinded_key_t *public_key,
    otcrypto_blinded_key_t *secret_key) {
  if (randomness.len != 2 * MLKEM512_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (public_key->key_length != MLKEM512_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.key_length != MLKEM512_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.key_mode != kOtcryptoKeyModeMlkem512) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.security_level == kOtcryptoKeySecurityLevelHigh) {
    // Reject high-security keys; the underlying implementation is not masked
    // against power side channels.
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.hw_backed != kHardenedBoolFalse) {
    return OTCRYPTO_NOT_IMPLEMENTED;
  }

  // Destination buffer for the unmasked key.
  uint32_t sk[ceil_div(MLKEM512_SECRETKEYBYTES, sizeof(uint32_t))];

  int result = mlkem512_keypair_derand((unsigned char *)public_key->key,
                                       (unsigned char *)sk, randomness.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  // Write the unmasked secret key into the two shares of the keyblob.
  uint32_t *share0;
  uint32_t *share1;
  HARDENED_TRY(keyblob_to_shares(secret_key, &share0, &share1));
  memcpy(share0, sk, sizeof(sk));
  memset(share1, 0, sizeof(sk));

  public_key->checksum = integrity_unblinded_checksum(public_key);
  secret_key->checksum = integrity_blinded_checksum(secret_key);

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem512_encapsulate_derand(
    const otcrypto_unblinded_key_t *public_key,
    otcrypto_const_byte_buf_t randomness, otcrypto_byte_buf_t ciphertext,
    otcrypto_blinded_key_t *shared_secret) {
  if (public_key->key_length != MLKEM512_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (public_key->key_mode != kOtcryptoKeyModeMlkem512) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (randomness.len != MLKEM512_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (ciphertext.len != MLKEM512_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.key_length != MLKEM512_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.hw_backed != kHardenedBoolFalse) {
    // Shared secret cannot be a hardware-backed key.
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.security_level == kOtcryptoKeySecurityLevelHigh) {
    // Reject high-security keys; the underlying implementation is not masked
    // against power side channels.
    return OTCRYPTO_BAD_ARGS;
  }
  if (integrity_unblinded_key_check(public_key) != kHardenedBoolTrue) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (integrity_blinded_key_check(shared_secret) != kHardenedBoolTrue) {
    return OTCRYPTO_BAD_ARGS;
  }

  // Destination buffer for the shared secret.
  uint32_t ss[ceil_div(MLKEM512_BYTES, sizeof(uint32_t))];

  int result =
      mlkem512_enc_derand(ciphertext.data, (unsigned char *)ss,
                          (unsigned char *)public_key->key, randomness.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  // Write the unmasked secret key into the two shares of the keyblob.
  uint32_t *share0;
  uint32_t *share1;
  HARDENED_TRY(keyblob_to_shares(shared_secret, &share0, &share1));
  memcpy(share0, ss, sizeof(ss));
  memset(share1, 0, sizeof(ss));

  shared_secret->checksum = integrity_blinded_checksum(shared_secret);

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem512_keygen(otcrypto_unblinded_key_t *public_key,
                                           otcrypto_blinded_key_t *secret_key) {
  HARDENED_TRY(entropy_complex_check());

  uint32_t randomness[ceil_div(2 * MLKEM512_BYTES, sizeof(uint32_t))];
  HARDENED_TRY(entropy_csrng_instantiate(
      /*disable_trng_input=*/kHardenedBoolFalse, &kEntropyEmptySeed));
  HARDENED_TRY(entropy_csrng_generate(&kEntropyEmptySeed, randomness,
                                      ARRAYSIZE(randomness),
                                      /*fips_check=*/kHardenedBoolTrue));
  HARDENED_TRY(entropy_csrng_uninstantiate());

  otcrypto_const_byte_buf_t randomness_buf = {
      .data = (unsigned char *)randomness, .len = sizeof(randomness)};
  return otcrypto_mlkem512_keygen_derand(randomness_buf, public_key,
                                         secret_key);
}

otcrypto_status_t otcrypto_mlkem512_encapsulate(
    const otcrypto_unblinded_key_t *public_key, otcrypto_byte_buf_t ciphertext,
    otcrypto_blinded_key_t *shared_secret) {
  HARDENED_TRY(entropy_complex_check());

  uint32_t randomness[ceil_div(MLKEM512_BYTES, sizeof(uint32_t))];
  HARDENED_TRY(entropy_csrng_instantiate(
      /*disable_trng_input=*/kHardenedBoolFalse, &kEntropyEmptySeed));
  HARDENED_TRY(entropy_csrng_generate(&kEntropyEmptySeed, randomness,
                                      ARRAYSIZE(randomness),
                                      /*fips_check=*/kHardenedBoolTrue));
  HARDENED_TRY(entropy_csrng_uninstantiate());

  otcrypto_const_byte_buf_t randomness_buf = {
      .data = (unsigned char *)randomness, .len = sizeof(randomness)};
  return otcrypto_mlkem512_encapsulate_derand(public_key, randomness_buf,
                                              ciphertext, shared_secret);
}

otcrypto_status_t otcrypto_mlkem512_decapsulate(
    const otcrypto_blinded_key_t *secret_key,
    otcrypto_const_byte_buf_t ciphertext,
    otcrypto_blinded_key_t *shared_secret) {
  if (secret_key->config.key_length != MLKEM512_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.key_mode != kOtcryptoKeyModeMlkem512) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.security_level == kOtcryptoKeySecurityLevelHigh) {
    // Reject high-security keys; the underlying implementation is not masked
    // against power side channels.
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.hw_backed != kHardenedBoolFalse) {
    return OTCRYPTO_NOT_IMPLEMENTED;
  }
  if (ciphertext.len != MLKEM512_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.key_length != MLKEM512_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.hw_backed != kHardenedBoolFalse) {
    // Shared secret cannot be a hardware-backed key.
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.security_level == kOtcryptoKeySecurityLevelHigh) {
    // Reject high-security keys; the underlying implementation is not masked
    // against power side channels.
    return OTCRYPTO_BAD_ARGS;
  }
  if (integrity_blinded_key_check(secret_key) != kHardenedBoolTrue) {
    return OTCRYPTO_BAD_ARGS;
  }

  // Unmask the key for the underlying implementation.
  uint32_t sk[ceil_div(MLKEM512_SECRETKEYBYTES, sizeof(uint32_t))];
  HARDENED_TRY(keyblob_key_unmask(secret_key, ARRAYSIZE(sk), sk));

  memset(shared_secret->keyblob, 0, shared_secret->keyblob_length);
  int result = mlkem512_dec((unsigned char *)shared_secret->keyblob,
                            ciphertext.data, (unsigned char *)sk);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

// ML-KEM-768 functions

otcrypto_status_t otcrypto_mlkem768_keygen_derand(
    otcrypto_const_byte_buf_t randomness, otcrypto_unblinded_key_t *public_key,
    otcrypto_blinded_key_t *secret_key) {
  if (randomness.len != 2 * MLKEM768_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (public_key->key_length != MLKEM768_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.key_length != MLKEM768_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.key_mode != kOtcryptoKeyModeMlkem768) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.security_level == kOtcryptoKeySecurityLevelHigh) {
    // Reject high-security keys; the underlying implementation is not masked
    // against power side channels.
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.hw_backed != kHardenedBoolFalse) {
    return OTCRYPTO_NOT_IMPLEMENTED;
  }

  // Destination buffer for the unmasked key.
  uint32_t sk[ceil_div(MLKEM768_SECRETKEYBYTES, sizeof(uint32_t))];

  int result = mlkem768_keypair_derand((unsigned char *)public_key->key,
                                       (unsigned char *)sk, randomness.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  // Write the unmasked secret key into the two shares of the keyblob.
  uint32_t *share0;
  uint32_t *share1;
  HARDENED_TRY(keyblob_to_shares(secret_key, &share0, &share1));
  memcpy(share0, sk, sizeof(sk));
  memset(share1, 0, sizeof(sk));

  public_key->checksum = integrity_unblinded_checksum(public_key);
  secret_key->checksum = integrity_blinded_checksum(secret_key);

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem768_encapsulate_derand(
    const otcrypto_unblinded_key_t *public_key,
    otcrypto_const_byte_buf_t randomness, otcrypto_byte_buf_t ciphertext,
    otcrypto_blinded_key_t *shared_secret) {
  if (public_key->key_length != MLKEM768_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (public_key->key_mode != kOtcryptoKeyModeMlkem768) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (randomness.len != MLKEM768_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (ciphertext.len != MLKEM768_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.key_length != MLKEM768_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.hw_backed != kHardenedBoolFalse) {
    // Shared secret cannot be a hardware-backed key.
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.security_level == kOtcryptoKeySecurityLevelHigh) {
    // Reject high-security keys; the underlying implementation is not masked
    // against power side channels.
    return OTCRYPTO_BAD_ARGS;
  }
  if (integrity_unblinded_key_check(public_key) != kHardenedBoolTrue) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (integrity_blinded_key_check(shared_secret) != kHardenedBoolTrue) {
    return OTCRYPTO_BAD_ARGS;
  }

  // Destination buffer for the shared secret.
  uint32_t ss[ceil_div(MLKEM768_BYTES, sizeof(uint32_t))];

  int result =
      mlkem768_enc_derand(ciphertext.data, (unsigned char *)ss,
                          (unsigned char *)public_key->key, randomness.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  // Write the unmasked secret key into the two shares of the keyblob.
  uint32_t *share0;
  uint32_t *share1;
  HARDENED_TRY(keyblob_to_shares(shared_secret, &share0, &share1));
  memcpy(share0, ss, sizeof(ss));
  memset(share1, 0, sizeof(ss));

  shared_secret->checksum = integrity_blinded_checksum(shared_secret);

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem768_keygen(otcrypto_unblinded_key_t *public_key,
                                           otcrypto_blinded_key_t *secret_key) {
  HARDENED_TRY(entropy_complex_check());

  uint32_t randomness[ceil_div(2 * MLKEM768_BYTES, sizeof(uint32_t))];
  HARDENED_TRY(entropy_csrng_instantiate(
      /*disable_trng_input=*/kHardenedBoolFalse, &kEntropyEmptySeed));
  HARDENED_TRY(entropy_csrng_generate(&kEntropyEmptySeed, randomness,
                                      ARRAYSIZE(randomness),
                                      /*fips_check=*/kHardenedBoolTrue));
  HARDENED_TRY(entropy_csrng_uninstantiate());

  otcrypto_const_byte_buf_t randomness_buf = {
      .data = (unsigned char *)randomness, .len = sizeof(randomness)};
  return otcrypto_mlkem768_keygen_derand(randomness_buf, public_key,
                                         secret_key);
}

otcrypto_status_t otcrypto_mlkem768_encapsulate(
    const otcrypto_unblinded_key_t *public_key, otcrypto_byte_buf_t ciphertext,
    otcrypto_blinded_key_t *shared_secret) {
  HARDENED_TRY(entropy_complex_check());

  uint32_t randomness[ceil_div(MLKEM768_BYTES, sizeof(uint32_t))];
  HARDENED_TRY(entropy_csrng_instantiate(
      /*disable_trng_input=*/kHardenedBoolFalse, &kEntropyEmptySeed));
  HARDENED_TRY(entropy_csrng_generate(&kEntropyEmptySeed, randomness,
                                      ARRAYSIZE(randomness),
                                      /*fips_check=*/kHardenedBoolTrue));
  HARDENED_TRY(entropy_csrng_uninstantiate());

  otcrypto_const_byte_buf_t randomness_buf = {
      .data = (unsigned char *)randomness, .len = sizeof(randomness)};
  return otcrypto_mlkem768_encapsulate_derand(public_key, randomness_buf,
                                              ciphertext, shared_secret);
}

otcrypto_status_t otcrypto_mlkem768_decapsulate(
    const otcrypto_blinded_key_t *secret_key,
    otcrypto_const_byte_buf_t ciphertext,
    otcrypto_blinded_key_t *shared_secret) {
  if (secret_key->config.key_length != MLKEM768_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.key_mode != kOtcryptoKeyModeMlkem768) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.security_level == kOtcryptoKeySecurityLevelHigh) {
    // Reject high-security keys; the underlying implementation is not masked
    // against power side channels.
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.hw_backed != kHardenedBoolFalse) {
    return OTCRYPTO_NOT_IMPLEMENTED;
  }
  if (ciphertext.len != MLKEM768_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.key_length != MLKEM768_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.hw_backed != kHardenedBoolFalse) {
    // Shared secret cannot be a hardware-backed key.
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.security_level == kOtcryptoKeySecurityLevelHigh) {
    // Reject high-security keys; the underlying implementation is not masked
    // against power side channels.
    return OTCRYPTO_BAD_ARGS;
  }
  if (integrity_blinded_key_check(secret_key) != kHardenedBoolTrue) {
    return OTCRYPTO_BAD_ARGS;
  }

  // Unmask the key for the underlying implementation.
  uint32_t sk[ceil_div(MLKEM768_SECRETKEYBYTES, sizeof(uint32_t))];
  HARDENED_TRY(keyblob_key_unmask(secret_key, ARRAYSIZE(sk), sk));

  memset(shared_secret->keyblob, 0, shared_secret->keyblob_length);
  int result = mlkem768_dec((unsigned char *)shared_secret->keyblob,
                            ciphertext.data, (unsigned char *)sk);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

// ML-KEM-1024 functions

otcrypto_status_t otcrypto_mlkem1024_keygen_derand(
    otcrypto_const_byte_buf_t randomness, otcrypto_unblinded_key_t *public_key,
    otcrypto_blinded_key_t *secret_key) {
  if (randomness.len != 2 * MLKEM1024_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (public_key->key_length != MLKEM1024_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.key_length != MLKEM1024_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.key_mode != kOtcryptoKeyModeMlkem1024) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.security_level == kOtcryptoKeySecurityLevelHigh) {
    // Reject high-security keys; the underlying implementation is not masked
    // against power side channels.
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.hw_backed != kHardenedBoolFalse) {
    return OTCRYPTO_NOT_IMPLEMENTED;
  }

  // Destination buffer for the unmasked key.
  uint32_t sk[ceil_div(MLKEM1024_SECRETKEYBYTES, sizeof(uint32_t))];

  int result = mlkem1024_keypair_derand((unsigned char *)public_key->key,
                                        (unsigned char *)sk, randomness.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  // Write the unmasked secret key into the two shares of the keyblob.
  uint32_t *share0;
  uint32_t *share1;
  HARDENED_TRY(keyblob_to_shares(secret_key, &share0, &share1));
  memcpy(share0, sk, sizeof(sk));
  memset(share1, 0, sizeof(sk));

  public_key->checksum = integrity_unblinded_checksum(public_key);
  secret_key->checksum = integrity_blinded_checksum(secret_key);

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem1024_encapsulate_derand(
    const otcrypto_unblinded_key_t *public_key,
    otcrypto_const_byte_buf_t randomness, otcrypto_byte_buf_t ciphertext,
    otcrypto_blinded_key_t *shared_secret) {
  if (public_key->key_length != MLKEM1024_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (public_key->key_mode != kOtcryptoKeyModeMlkem1024) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (randomness.len != MLKEM1024_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (ciphertext.len != MLKEM1024_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.key_length != MLKEM1024_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.hw_backed != kHardenedBoolFalse) {
    // Shared secret cannot be a hardware-backed key.
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.security_level == kOtcryptoKeySecurityLevelHigh) {
    // Reject high-security keys; the underlying implementation is not masked
    // against power side channels.
    return OTCRYPTO_BAD_ARGS;
  }
  if (integrity_unblinded_key_check(public_key) != kHardenedBoolTrue) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (integrity_blinded_key_check(shared_secret) != kHardenedBoolTrue) {
    return OTCRYPTO_BAD_ARGS;
  }

  // Destination buffer for the shared secret.
  uint32_t ss[ceil_div(MLKEM1024_BYTES, sizeof(uint32_t))];

  int result =
      mlkem1024_enc_derand(ciphertext.data, (unsigned char *)ss,
                           (unsigned char *)public_key->key, randomness.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  // Write the unmasked secret key into the two shares of the keyblob.
  uint32_t *share0;
  uint32_t *share1;
  HARDENED_TRY(keyblob_to_shares(shared_secret, &share0, &share1));
  memcpy(share0, ss, sizeof(ss));
  memset(share1, 0, sizeof(ss));

  shared_secret->checksum = integrity_blinded_checksum(shared_secret);

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem1024_keygen(
    otcrypto_unblinded_key_t *public_key, otcrypto_blinded_key_t *secret_key) {
  HARDENED_TRY(entropy_complex_check());

  uint32_t randomness[ceil_div(2 * MLKEM1024_BYTES, sizeof(uint32_t))];
  HARDENED_TRY(entropy_csrng_instantiate(
      /*disable_trng_input=*/kHardenedBoolFalse, &kEntropyEmptySeed));
  HARDENED_TRY(entropy_csrng_generate(&kEntropyEmptySeed, randomness,
                                      ARRAYSIZE(randomness),
                                      /*fips_check=*/kHardenedBoolTrue));
  HARDENED_TRY(entropy_csrng_uninstantiate());

  otcrypto_const_byte_buf_t randomness_buf = {
      .data = (unsigned char *)randomness, .len = sizeof(randomness)};
  return otcrypto_mlkem1024_keygen_derand(randomness_buf, public_key,
                                          secret_key);
}

otcrypto_status_t otcrypto_mlkem1024_encapsulate(
    const otcrypto_unblinded_key_t *public_key, otcrypto_byte_buf_t ciphertext,
    otcrypto_blinded_key_t *shared_secret) {
  HARDENED_TRY(entropy_complex_check());

  uint32_t randomness[ceil_div(MLKEM1024_BYTES, sizeof(uint32_t))];
  HARDENED_TRY(entropy_csrng_instantiate(
      /*disable_trng_input=*/kHardenedBoolFalse, &kEntropyEmptySeed));
  HARDENED_TRY(entropy_csrng_generate(&kEntropyEmptySeed, randomness,
                                      ARRAYSIZE(randomness),
                                      /*fips_check=*/kHardenedBoolTrue));
  HARDENED_TRY(entropy_csrng_uninstantiate());

  otcrypto_const_byte_buf_t randomness_buf = {
      .data = (unsigned char *)randomness, .len = sizeof(randomness)};
  return otcrypto_mlkem1024_encapsulate_derand(public_key, randomness_buf,
                                               ciphertext, shared_secret);
}

otcrypto_status_t otcrypto_mlkem1024_decapsulate(
    const otcrypto_blinded_key_t *secret_key,
    otcrypto_const_byte_buf_t ciphertext,
    otcrypto_blinded_key_t *shared_secret) {
  if (secret_key->config.key_length != MLKEM1024_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.key_mode != kOtcryptoKeyModeMlkem1024) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.security_level == kOtcryptoKeySecurityLevelHigh) {
    // Reject high-security keys; the underlying implementation is not masked
    // against power side channels.
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key->config.hw_backed != kHardenedBoolFalse) {
    return OTCRYPTO_NOT_IMPLEMENTED;
  }
  if (ciphertext.len != MLKEM1024_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.key_length != MLKEM1024_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.hw_backed != kHardenedBoolFalse) {
    // Shared secret cannot be a hardware-backed key.
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret->config.security_level == kOtcryptoKeySecurityLevelHigh) {
    // Reject high-security keys; the underlying implementation is not masked
    // against power side channels.
    return OTCRYPTO_BAD_ARGS;
  }
  if (integrity_blinded_key_check(secret_key) != kHardenedBoolTrue) {
    return OTCRYPTO_BAD_ARGS;
  }

  // Unmask the key for the underlying implementation.
  uint32_t sk[ceil_div(MLKEM1024_SECRETKEYBYTES, sizeof(uint32_t))];
  HARDENED_TRY(keyblob_key_unmask(secret_key, ARRAYSIZE(sk), sk));

  memset(shared_secret->keyblob, 0, shared_secret->keyblob_length);
  int result = mlkem1024_dec((unsigned char *)shared_secret->keyblob,
                             ciphertext.data, (unsigned char *)sk);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}
