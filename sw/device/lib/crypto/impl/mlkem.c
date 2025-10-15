// Copyright The mlkem-native project authors
// Copyright zeroRISC Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/crypto/include/mlkem.h"

#include "sw/device/lib/crypto/drivers/entropy.h"
#include "sw/device/lib/crypto/impl/mlkem/mlkem_native_monobuild.h"
#include "sw/device/lib/crypto/impl/status.h"

// ML-KEM-512 functions

otcrypto_status_t otcrypto_mlkem512_keygen_derand(
    otcrypto_const_byte_buf_t randomness, otcrypto_byte_buf_t public_key,
    otcrypto_byte_buf_t secret_key) {
  if (randomness.len != 2 * MLKEM512_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (public_key.len != MLKEM512_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key.len != MLKEM512_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  int result = mlkem512_keypair_derand(public_key.data, secret_key.data,
                                       randomness.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem512_encapsulate_derand(
    otcrypto_const_byte_buf_t public_key, otcrypto_const_byte_buf_t randomness,
    otcrypto_byte_buf_t ciphertext, otcrypto_byte_buf_t shared_secret) {
  if (public_key.len != MLKEM512_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (randomness.len != MLKEM512_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (ciphertext.len != MLKEM512_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret.len != MLKEM512_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  int result = mlkem512_enc_derand(ciphertext.data, shared_secret.data,
                                   public_key.data, randomness.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem512_keygen(otcrypto_byte_buf_t public_key,
                                           otcrypto_byte_buf_t secret_key) {
  if (public_key.len != MLKEM512_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key.len != MLKEM512_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  uint8_t randomness[2 * MLKEM512_BYTES];
  HARDENED_TRY(entropy_complex_check());
  HARDENED_TRY(entropy_csrng_instantiate(
      /*disable_trng_input=*/kHardenedBoolFalse, &kEntropyEmptySeed));
  HARDENED_TRY(entropy_csrng_generate(
      &kEntropyEmptySeed, (uint32_t *)randomness, sizeof(randomness) / 4,
      /*fips_check=*/kHardenedBoolTrue));
  HARDENED_TRY(entropy_csrng_uninstantiate());

  int result =
      mlkem512_keypair_derand(public_key.data, secret_key.data, randomness);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem512_encapsulate(
    otcrypto_const_byte_buf_t public_key, otcrypto_byte_buf_t ciphertext,
    otcrypto_byte_buf_t shared_secret) {
  if (public_key.len != MLKEM512_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (ciphertext.len != MLKEM512_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret.len != MLKEM512_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  uint8_t randomness[MLKEM512_BYTES];
  HARDENED_TRY(entropy_complex_check());
  HARDENED_TRY(entropy_csrng_instantiate(
      /*disable_trng_input=*/kHardenedBoolFalse, &kEntropyEmptySeed));
  HARDENED_TRY(entropy_csrng_generate(
      &kEntropyEmptySeed, (uint32_t *)randomness, sizeof(randomness) / 4,
      /*fips_check=*/kHardenedBoolTrue));
  HARDENED_TRY(entropy_csrng_uninstantiate());

  int result = mlkem512_enc_derand(ciphertext.data, shared_secret.data,
                                   public_key.data, randomness);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem512_decapsulate(
    otcrypto_const_byte_buf_t secret_key, otcrypto_const_byte_buf_t ciphertext,
    otcrypto_byte_buf_t shared_secret) {
  if (secret_key.len != MLKEM512_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (ciphertext.len != MLKEM512_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret.len != MLKEM512_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  int result =
      mlkem512_dec(shared_secret.data, ciphertext.data, secret_key.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

// ML-KEM-768 functions

otcrypto_status_t otcrypto_mlkem768_keygen_derand(
    otcrypto_const_byte_buf_t randomness, otcrypto_byte_buf_t public_key,
    otcrypto_byte_buf_t secret_key) {
  if (randomness.len != 2 * MLKEM768_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (public_key.len != MLKEM768_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key.len != MLKEM768_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  int result = mlkem768_keypair_derand(public_key.data, secret_key.data,
                                       randomness.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem768_encapsulate_derand(
    otcrypto_const_byte_buf_t public_key, otcrypto_const_byte_buf_t randomness,
    otcrypto_byte_buf_t ciphertext, otcrypto_byte_buf_t shared_secret) {
  if (public_key.len != MLKEM768_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (randomness.len != MLKEM768_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (ciphertext.len != MLKEM768_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret.len != MLKEM768_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  int result = mlkem768_enc_derand(ciphertext.data, shared_secret.data,
                                   public_key.data, randomness.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem768_keygen(otcrypto_byte_buf_t public_key,
                                           otcrypto_byte_buf_t secret_key) {
  if (public_key.len != MLKEM768_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key.len != MLKEM768_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  uint8_t randomness[2 * MLKEM768_BYTES];
  HARDENED_TRY(entropy_complex_check());
  HARDENED_TRY(entropy_csrng_instantiate(
      /*disable_trng_input=*/kHardenedBoolFalse, &kEntropyEmptySeed));
  HARDENED_TRY(entropy_csrng_generate(
      &kEntropyEmptySeed, (uint32_t *)randomness, sizeof(randomness) / 4,
      /*fips_check=*/kHardenedBoolTrue));
  HARDENED_TRY(entropy_csrng_uninstantiate());

  int result =
      mlkem768_keypair_derand(public_key.data, secret_key.data, randomness);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem768_encapsulate(
    otcrypto_const_byte_buf_t public_key, otcrypto_byte_buf_t ciphertext,
    otcrypto_byte_buf_t shared_secret) {
  if (public_key.len != MLKEM768_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (ciphertext.len != MLKEM768_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret.len != MLKEM768_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  uint8_t randomness[MLKEM768_BYTES];
  HARDENED_TRY(entropy_complex_check());
  HARDENED_TRY(entropy_csrng_instantiate(
      /*disable_trng_input=*/kHardenedBoolFalse, &kEntropyEmptySeed));
  HARDENED_TRY(entropy_csrng_generate(
      &kEntropyEmptySeed, (uint32_t *)randomness, sizeof(randomness) / 4,
      /*fips_check=*/kHardenedBoolTrue));
  HARDENED_TRY(entropy_csrng_uninstantiate());

  int result = mlkem768_enc_derand(ciphertext.data, shared_secret.data,
                                   public_key.data, randomness);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem768_decapsulate(
    otcrypto_const_byte_buf_t secret_key, otcrypto_const_byte_buf_t ciphertext,
    otcrypto_byte_buf_t shared_secret) {
  if (secret_key.len != MLKEM768_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (ciphertext.len != MLKEM768_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret.len != MLKEM768_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  int result =
      mlkem768_dec(shared_secret.data, ciphertext.data, secret_key.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

// ML-KEM-1024 functions

otcrypto_status_t otcrypto_mlkem1024_keygen_derand(
    otcrypto_const_byte_buf_t randomness, otcrypto_byte_buf_t public_key,
    otcrypto_byte_buf_t secret_key) {
  if (randomness.len != 2 * MLKEM1024_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (public_key.len != MLKEM1024_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key.len != MLKEM1024_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  int result = mlkem1024_keypair_derand(public_key.data, secret_key.data,
                                        randomness.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem1024_encapsulate_derand(
    otcrypto_const_byte_buf_t public_key, otcrypto_const_byte_buf_t randomness,
    otcrypto_byte_buf_t ciphertext, otcrypto_byte_buf_t shared_secret) {
  if (public_key.len != MLKEM1024_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (randomness.len != MLKEM1024_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (ciphertext.len != MLKEM1024_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret.len != MLKEM1024_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  int result = mlkem1024_enc_derand(ciphertext.data, shared_secret.data,
                                    public_key.data, randomness.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem1024_keygen(otcrypto_byte_buf_t public_key,
                                            otcrypto_byte_buf_t secret_key) {
  if (public_key.len != MLKEM1024_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (secret_key.len != MLKEM1024_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  uint8_t randomness[2 * MLKEM1024_BYTES];
  HARDENED_TRY(entropy_complex_check());
  HARDENED_TRY(entropy_csrng_instantiate(
      /*disable_trng_input=*/kHardenedBoolFalse, &kEntropyEmptySeed));
  HARDENED_TRY(entropy_csrng_generate(
      &kEntropyEmptySeed, (uint32_t *)randomness, sizeof(randomness) / 4,
      /*fips_check=*/kHardenedBoolTrue));
  HARDENED_TRY(entropy_csrng_uninstantiate());

  int result =
      mlkem1024_keypair_derand(public_key.data, secret_key.data, randomness);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem1024_encapsulate(
    otcrypto_const_byte_buf_t public_key, otcrypto_byte_buf_t ciphertext,
    otcrypto_byte_buf_t shared_secret) {
  if (public_key.len != MLKEM1024_PUBLICKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (ciphertext.len != MLKEM1024_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret.len != MLKEM1024_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  uint8_t randomness[MLKEM1024_BYTES];
  HARDENED_TRY(entropy_complex_check());
  HARDENED_TRY(entropy_csrng_instantiate(
      /*disable_trng_input=*/kHardenedBoolFalse, &kEntropyEmptySeed));
  HARDENED_TRY(entropy_csrng_generate(
      &kEntropyEmptySeed, (uint32_t *)randomness, sizeof(randomness) / 4,
      /*fips_check=*/kHardenedBoolTrue));
  HARDENED_TRY(entropy_csrng_uninstantiate());

  int result = mlkem1024_enc_derand(ciphertext.data, shared_secret.data,
                                    public_key.data, randomness);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}

otcrypto_status_t otcrypto_mlkem1024_decapsulate(
    otcrypto_const_byte_buf_t secret_key, otcrypto_const_byte_buf_t ciphertext,
    otcrypto_byte_buf_t shared_secret) {
  if (secret_key.len != MLKEM1024_SECRETKEYBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (ciphertext.len != MLKEM1024_CIPHERTEXTBYTES) {
    return OTCRYPTO_BAD_ARGS;
  }
  if (shared_secret.len != MLKEM1024_BYTES) {
    return OTCRYPTO_BAD_ARGS;
  }

  int result =
      mlkem1024_dec(shared_secret.data, ciphertext.data, secret_key.data);
  if (result != 0) {
    return OTCRYPTO_FATAL_ERR;
  }

  return OTCRYPTO_OK;
}
