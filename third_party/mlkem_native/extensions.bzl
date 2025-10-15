# Copyright The mlkem-native project authors
# Copyright zeroRISC Inc.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

mlkem_native = module_extension(
    implementation = lambda _: _mlkem_native_repos(),
)

def _mlkem_native_repos():
    http_archive(
        name = "mlkem_native",
        build_file = Label("//third_party/mlkem_native:BUILD.mlkem_native.bazel"),
        sha256 = "2b1cb3891435452d8f09b047276970cc5bedee4acc1447ec499f2e4beef8e592",
        strip_prefix = "mlkem-native-206f8edbec21bc25a2e222be19cfc89f847422f5",
        urls = [
            "https://github.com/pq-code-package/mlkem-native/archive/206f8edbec21bc25a2e222be19cfc89f847422f5.tar.gz",
        ],
    )
