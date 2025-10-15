// Copyright The mlkem-native project authors
// Copyright zeroRISC Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/lib/crypto/include/mlkem.h"
#include "sw/device/lib/dif/dif_otbn.h"
#include "sw/device/lib/runtime/ibex.h"
#include "sw/device/lib/runtime/log.h"
#include "sw/device/lib/testing/entropy_testutils.h"
#include "sw/device/lib/testing/otbn_testutils.h"
#include "sw/device/lib/testing/profile.h"
#include "sw/device/lib/testing/test_framework/check.h"
#include "sw/device/lib/testing/test_framework/ottf_main.h"

#include "hw/top_earlgrey/sw/autogen/top_earlgrey.h"

OTTF_DEFINE_TEST_CONFIG();

static void test_mlkem512_derand(void) {
  uint64_t t0;
  uint8_t pk[kOtcryptoMlkem512PublicKeyBytes];
  uint8_t sk[kOtcryptoMlkem512SecretKeyBytes];
  uint8_t ct[kOtcryptoMlkem512CiphertextBytes];
  uint8_t key_a[kOtcryptoMlkem512SharedSecretBytes];
  uint8_t key_b[kOtcryptoMlkem512SharedSecretBytes];

  uint8_t coins[kOtcryptoMlkem512KeygenSeedBytes] = {0};
  uint8_t coinsE[kOtcryptoMlkem512SharedSecretBytes] = {1};

  const uint8_t expected_key[] = {
      0x5f, 0x5f, 0x8c, 0xf5, 0x7c, 0x34, 0xd4, 0x68, 0x06, 0xa2, 0xe9,
      0xc9, 0x28, 0xba, 0x10, 0x5a, 0x46, 0xf2, 0x67, 0x1a, 0xc7, 0x81,
      0xdf, 0xf1, 0x4a, 0xbb, 0x27, 0xea, 0x46, 0x06, 0x46, 0x3c};

  otcrypto_const_byte_buf_t coins_buf = {.data = coins, .len = sizeof(coins)};
  otcrypto_byte_buf_t pk_buf = {.data = pk, .len = sizeof(pk)};
  otcrypto_byte_buf_t sk_buf = {.data = sk, .len = sizeof(sk)};
  t0 = profile_start();
  CHECK_STATUS_OK(otcrypto_mlkem512_keygen_derand(coins_buf, pk_buf, sk_buf));
  profile_end_and_print(t0, "otcrypto_mlkem512_keygen_derand");

  otcrypto_const_byte_buf_t pk_const_buf = {.data = pk, .len = sizeof(pk)};
  otcrypto_const_byte_buf_t coinsE_buf = {.data = coinsE,
                                          .len = sizeof(coinsE)};
  otcrypto_byte_buf_t ct_buf = {.data = ct, .len = sizeof(ct)};
  otcrypto_byte_buf_t key_b_buf = {.data = key_b, .len = sizeof(key_b)};
  t0 = profile_start();
  CHECK_STATUS_OK(otcrypto_mlkem512_encapsulate_derand(pk_const_buf, coinsE_buf,
                                                       ct_buf, key_b_buf));
  profile_end_and_print(t0, "otcrypto_mlkem512_encapsulate_derand");

  otcrypto_const_byte_buf_t sk_const_buf = {.data = sk, .len = sizeof(sk)};
  otcrypto_const_byte_buf_t ct_const_buf = {.data = ct, .len = sizeof(ct)};
  otcrypto_byte_buf_t key_a_buf = {.data = key_a, .len = sizeof(key_a)};
  t0 = profile_start();
  CHECK_STATUS_OK(
      otcrypto_mlkem512_decapsulate(sk_const_buf, ct_const_buf, key_a_buf));
  profile_end_and_print(t0, "otcrypto_mlkem512_decapsulate");

  CHECK_ARRAYS_EQ(key_a, key_b, kOtcryptoMlkem512SharedSecretBytes);
  CHECK_ARRAYS_EQ(key_a, expected_key, kOtcryptoMlkem512SharedSecretBytes);
}

static void test_mlkem768_derand(void) {
  uint64_t t0;
  uint8_t pk[kOtcryptoMlkem768PublicKeyBytes];
  uint8_t sk[kOtcryptoMlkem768SecretKeyBytes];
  uint8_t ct[kOtcryptoMlkem768CiphertextBytes];
  uint8_t key_a[kOtcryptoMlkem768SharedSecretBytes];
  uint8_t key_b[kOtcryptoMlkem768SharedSecretBytes];

  uint8_t coins[kOtcryptoMlkem768KeygenSeedBytes] = {0};
  uint8_t coinsE[kOtcryptoMlkem768SharedSecretBytes] = {1};

  const uint8_t expected_key[] = {
      0x85, 0x21, 0xab, 0xc8, 0x14, 0xc7, 0x67, 0x70, 0x4f, 0xa6, 0x25,
      0xd9, 0x35, 0x95, 0xd0, 0x03, 0x79, 0xa8, 0xb3, 0x70, 0x35, 0x2c,
      0xa4, 0xba, 0xb3, 0xa6, 0x82, 0x46, 0x63, 0x0d, 0xb0, 0x8b};

  otcrypto_const_byte_buf_t coins_buf = {.data = coins, .len = sizeof(coins)};
  otcrypto_byte_buf_t pk_buf = {.data = pk, .len = sizeof(pk)};
  otcrypto_byte_buf_t sk_buf = {.data = sk, .len = sizeof(sk)};
  t0 = profile_start();
  CHECK_STATUS_OK(otcrypto_mlkem768_keygen_derand(coins_buf, pk_buf, sk_buf));
  profile_end_and_print(t0, "otcrypto_mlkem768_keygen_derand");

  otcrypto_const_byte_buf_t pk_const_buf = {.data = pk, .len = sizeof(pk)};
  otcrypto_const_byte_buf_t coinsE_buf = {.data = coinsE,
                                          .len = sizeof(coinsE)};
  otcrypto_byte_buf_t ct_buf = {.data = ct, .len = sizeof(ct)};
  otcrypto_byte_buf_t key_b_buf = {.data = key_b, .len = sizeof(key_b)};
  t0 = profile_start();
  CHECK_STATUS_OK(otcrypto_mlkem768_encapsulate_derand(pk_const_buf, coinsE_buf,
                                                       ct_buf, key_b_buf));
  profile_end_and_print(t0, "otcrypto_mlkem768_encapsulate_derand");

  otcrypto_const_byte_buf_t sk_const_buf = {.data = sk, .len = sizeof(sk)};
  otcrypto_const_byte_buf_t ct_const_buf = {.data = ct, .len = sizeof(ct)};
  otcrypto_byte_buf_t key_a_buf = {.data = key_a, .len = sizeof(key_a)};
  t0 = profile_start();
  CHECK_STATUS_OK(
      otcrypto_mlkem768_decapsulate(sk_const_buf, ct_const_buf, key_a_buf));
  profile_end_and_print(t0, "otcrypto_mlkem768_decapsulate");

  CHECK_ARRAYS_EQ(key_a, key_b, kOtcryptoMlkem768SharedSecretBytes);
  CHECK_ARRAYS_EQ(key_a, expected_key, kOtcryptoMlkem768SharedSecretBytes);
}

static void test_mlkem1024_derand(void) {
  uint64_t t0;
  uint8_t pk[kOtcryptoMlkem1024PublicKeyBytes];
  uint8_t sk[kOtcryptoMlkem1024SecretKeyBytes];
  uint8_t ct[kOtcryptoMlkem1024CiphertextBytes];
  uint8_t key_a[kOtcryptoMlkem1024SharedSecretBytes];
  uint8_t key_b[kOtcryptoMlkem1024SharedSecretBytes];

  uint8_t coins[kOtcryptoMlkem1024KeygenSeedBytes] = {0};
  uint8_t coinsE[kOtcryptoMlkem1024SharedSecretBytes] = {1};

  const uint8_t expected_key[] = {
      0x30, 0x4d, 0xbe, 0x54, 0xd6, 0x6f, 0x80, 0x66, 0xc6, 0xa8, 0x1c,
      0x6b, 0x36, 0xc4, 0x48, 0x9b, 0xf9, 0xe6, 0x05, 0x79, 0x83, 0x3c,
      0x4e, 0xdc, 0x8a, 0xc7, 0x92, 0xe5, 0x73, 0x0d, 0xdd, 0x85};

  otcrypto_const_byte_buf_t coins_buf = {.data = coins, .len = sizeof(coins)};
  otcrypto_byte_buf_t pk_buf = {.data = pk, .len = sizeof(pk)};
  otcrypto_byte_buf_t sk_buf = {.data = sk, .len = sizeof(sk)};
  t0 = profile_start();
  CHECK_STATUS_OK(otcrypto_mlkem1024_keygen_derand(coins_buf, pk_buf, sk_buf));
  profile_end_and_print(t0, "otcrypto_mlkem1024_keygen_derand");

  otcrypto_const_byte_buf_t pk_const_buf = {.data = pk, .len = sizeof(pk)};
  otcrypto_const_byte_buf_t coinsE_buf = {.data = coinsE,
                                          .len = sizeof(coinsE)};
  otcrypto_byte_buf_t ct_buf = {.data = ct, .len = sizeof(ct)};
  otcrypto_byte_buf_t key_b_buf = {.data = key_b, .len = sizeof(key_b)};
  t0 = profile_start();
  CHECK_STATUS_OK(otcrypto_mlkem1024_encapsulate_derand(
      pk_const_buf, coinsE_buf, ct_buf, key_b_buf));
  profile_end_and_print(t0, "otcrypto_mlkem1024_encapsulate_derand");

  otcrypto_const_byte_buf_t sk_const_buf = {.data = sk, .len = sizeof(sk)};
  otcrypto_const_byte_buf_t ct_const_buf = {.data = ct, .len = sizeof(ct)};
  otcrypto_byte_buf_t key_a_buf = {.data = key_a, .len = sizeof(key_a)};
  t0 = profile_start();
  CHECK_STATUS_OK(
      otcrypto_mlkem1024_decapsulate(sk_const_buf, ct_const_buf, key_a_buf));
  profile_end_and_print(t0, "otcrypto_mlkem1024_decapsulate");

  CHECK_ARRAYS_EQ(key_a, key_b, kOtcryptoMlkem1024SharedSecretBytes);
  CHECK_ARRAYS_EQ(key_a, expected_key, kOtcryptoMlkem1024SharedSecretBytes);
}

static void test_mlkem512_randomized(void) {
  uint64_t t0;
  uint8_t pk[kOtcryptoMlkem512PublicKeyBytes];
  uint8_t sk[kOtcryptoMlkem512SecretKeyBytes];
  uint8_t ct[kOtcryptoMlkem512CiphertextBytes];
  uint8_t key_a[kOtcryptoMlkem512SharedSecretBytes];
  uint8_t key_b[kOtcryptoMlkem512SharedSecretBytes];

  otcrypto_byte_buf_t pk_buf = {.data = pk, .len = sizeof(pk)};
  otcrypto_byte_buf_t sk_buf = {.data = sk, .len = sizeof(sk)};
  t0 = profile_start();
  CHECK_STATUS_OK(otcrypto_mlkem512_keygen(pk_buf, sk_buf));
  profile_end_and_print(t0, "otcrypto_mlkem512_keygen");

  otcrypto_const_byte_buf_t pk_const_buf = {.data = pk, .len = sizeof(pk)};
  otcrypto_byte_buf_t ct_buf = {.data = ct, .len = sizeof(ct)};
  otcrypto_byte_buf_t key_b_buf = {.data = key_b, .len = sizeof(key_b)};
  t0 = profile_start();
  CHECK_STATUS_OK(
      otcrypto_mlkem512_encapsulate(pk_const_buf, ct_buf, key_b_buf));
  profile_end_and_print(t0, "otcrypto_mlkem512_encapsulate");

  otcrypto_const_byte_buf_t sk_const_buf = {.data = sk, .len = sizeof(sk)};
  otcrypto_const_byte_buf_t ct_const_buf = {.data = ct, .len = sizeof(ct)};
  otcrypto_byte_buf_t key_a_buf = {.data = key_a, .len = sizeof(key_a)};
  t0 = profile_start();
  CHECK_STATUS_OK(
      otcrypto_mlkem512_decapsulate(sk_const_buf, ct_const_buf, key_a_buf));
  profile_end_and_print(t0, "otcrypto_mlkem512_decapsulate");

  CHECK_ARRAYS_EQ(key_a, key_b, kOtcryptoMlkem512SharedSecretBytes);
}

static void test_mlkem768_randomized(void) {
  uint64_t t0;
  uint8_t pk[kOtcryptoMlkem768PublicKeyBytes];
  uint8_t sk[kOtcryptoMlkem768SecretKeyBytes];
  uint8_t ct[kOtcryptoMlkem768CiphertextBytes];
  uint8_t key_a[kOtcryptoMlkem768SharedSecretBytes];
  uint8_t key_b[kOtcryptoMlkem768SharedSecretBytes];

  otcrypto_byte_buf_t pk_buf = {.data = pk, .len = sizeof(pk)};
  otcrypto_byte_buf_t sk_buf = {.data = sk, .len = sizeof(sk)};
  t0 = profile_start();
  CHECK_STATUS_OK(otcrypto_mlkem768_keygen(pk_buf, sk_buf));
  profile_end_and_print(t0, "otcrypto_mlkem768_keygen");

  otcrypto_const_byte_buf_t pk_const_buf = {.data = pk, .len = sizeof(pk)};
  otcrypto_byte_buf_t ct_buf = {.data = ct, .len = sizeof(ct)};
  otcrypto_byte_buf_t key_b_buf = {.data = key_b, .len = sizeof(key_b)};
  t0 = profile_start();
  CHECK_STATUS_OK(
      otcrypto_mlkem768_encapsulate(pk_const_buf, ct_buf, key_b_buf));
  profile_end_and_print(t0, "otcrypto_mlkem768_encapsulate");

  otcrypto_const_byte_buf_t sk_const_buf = {.data = sk, .len = sizeof(sk)};
  otcrypto_const_byte_buf_t ct_const_buf = {.data = ct, .len = sizeof(ct)};
  otcrypto_byte_buf_t key_a_buf = {.data = key_a, .len = sizeof(key_a)};
  t0 = profile_start();
  CHECK_STATUS_OK(
      otcrypto_mlkem768_decapsulate(sk_const_buf, ct_const_buf, key_a_buf));
  profile_end_and_print(t0, "otcrypto_mlkem768_decapsulate");

  CHECK_ARRAYS_EQ(key_a, key_b, kOtcryptoMlkem768SharedSecretBytes);
}

static void test_mlkem1024_randomized(void) {
  uint64_t t0;
  uint8_t pk[kOtcryptoMlkem1024PublicKeyBytes];
  uint8_t sk[kOtcryptoMlkem1024SecretKeyBytes];
  uint8_t ct[kOtcryptoMlkem1024CiphertextBytes];
  uint8_t key_a[kOtcryptoMlkem1024SharedSecretBytes];
  uint8_t key_b[kOtcryptoMlkem1024SharedSecretBytes];

  otcrypto_byte_buf_t pk_buf = {.data = pk, .len = sizeof(pk)};
  otcrypto_byte_buf_t sk_buf = {.data = sk, .len = sizeof(sk)};
  t0 = profile_start();
  CHECK_STATUS_OK(otcrypto_mlkem1024_keygen(pk_buf, sk_buf));
  profile_end_and_print(t0, "otcrypto_mlkem1024_keygen");

  otcrypto_const_byte_buf_t pk_const_buf = {.data = pk, .len = sizeof(pk)};
  otcrypto_byte_buf_t ct_buf = {.data = ct, .len = sizeof(ct)};
  otcrypto_byte_buf_t key_b_buf = {.data = key_b, .len = sizeof(key_b)};
  t0 = profile_start();
  CHECK_STATUS_OK(
      otcrypto_mlkem1024_encapsulate(pk_const_buf, ct_buf, key_b_buf));
  profile_end_and_print(t0, "otcrypto_mlkem1024_encapsulate");

  otcrypto_const_byte_buf_t sk_const_buf = {.data = sk, .len = sizeof(sk)};
  otcrypto_const_byte_buf_t ct_const_buf = {.data = ct, .len = sizeof(ct)};
  otcrypto_byte_buf_t key_a_buf = {.data = key_a, .len = sizeof(key_a)};
  t0 = profile_start();
  CHECK_STATUS_OK(
      otcrypto_mlkem1024_decapsulate(sk_const_buf, ct_const_buf, key_a_buf));
  profile_end_and_print(t0, "otcrypto_mlkem1024_decapsulate");

  CHECK_ARRAYS_EQ(key_a, key_b, kOtcryptoMlkem1024SharedSecretBytes);
}

bool test_main(void) {
  CHECK_STATUS_OK(entropy_testutils_auto_mode_init());

  // Run deterministic tests
  test_mlkem512_derand();
  test_mlkem768_derand();
  test_mlkem1024_derand();

  // Run randomized tests
  test_mlkem512_randomized();
  test_mlkem768_randomized();
  test_mlkem1024_randomized();

  return true;
}
