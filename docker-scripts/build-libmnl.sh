#!/bin/sh

set -e

VER=1.0.5

wget -O libmnl-$VER.tar.bz2 "https://www.netfilter.org/pub/libmnl/libmnl-$VER.tar.bz2"
tar xf libmnl-$VER.tar.bz2 && cd libmnl-$VER
mkdir build && cd build
../configure --prefix=/usr/local --enable-static --disable-shared
make install
