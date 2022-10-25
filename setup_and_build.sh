#!/bin/bash

CURR=$(pwd)

git submodule update --init --recursive

if [ -z "$(which autoreconf)" ]; then
    echo " plz, install 'sudo apt install autoconf'"
    exit 1
fi

echo "make sure the autoconf and libtool are installed"

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

