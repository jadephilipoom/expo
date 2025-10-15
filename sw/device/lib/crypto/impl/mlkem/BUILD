# Copyright The mlkem-native project authors
# Copyright zeroRISC Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "mlkem_native",
    srcs = ["mlkem_native_monobuild.c"],
    hdrs = [
        "config.h",
        "fips202_glue.h",
        "fips202x4_glue.h",
        "mlkem_native_monobuild.h",
    ],
    copts = [
        '-DMLK_CONFIG_FILE=\\"config.h\\"',
    ],
    includes = ["."],
    deps = [
        "//sw/device/lib/crypto/impl:sha3",
        "@mlkem_native//:mlkem_native_sources",
    ],
)
