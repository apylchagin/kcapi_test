#!/bin/bash

CURR=$(pwd)

git submodule update --init --recursive

pushd kcapi/code
autoreconf -i
#./configure --enable-shared
./configure
make -j8
popd

mkdir build
pushd build
cmake -G "Unix Makefiles" -S $CURR -B .
cmake --build . -- -j8

./kcapi_test

