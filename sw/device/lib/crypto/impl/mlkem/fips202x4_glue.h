/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLK_FIPS202_FIPS202X4_H
#define MLK_FIPS202_FIPS202X4_H

#include "fips202_glue.h"
#include "mlkem/src/common.h"

static MLK_INLINE void mlk_shake256x4(uint8_t *out0, uint8_t *out1,
                                      uint8_t *out2, uint8_t *out3,
                                      size_t outlen, uint8_t *in0, uint8_t *in1,
                                      uint8_t *in2, uint8_t *in3,
                                      size_t inlen) {
  mlk_shake256(out0, outlen, in0, inlen);
  mlk_shake256(out1, outlen, in1, inlen);
  mlk_shake256(out2, outlen, in2, inlen);
  mlk_shake256(out3, outlen, in3, inlen);
}

#endif /* MLK_FIPS202_FIPS202X4_H */