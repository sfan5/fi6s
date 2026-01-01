#!/bin/bash -e
d=..
export AFL_LLVM_LAF_ALL=1
make -C $d clean all CC=afl-clang-fast FUZZ=banner BUILD_TYPE=release
mv -v $d/fi6s ./fi6s-fuzz
make -C $d clean all FUZZ=banner
mv -v $d/fi6s ./fi6s-test
make -C $d clean
