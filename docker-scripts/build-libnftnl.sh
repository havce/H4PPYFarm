#!/bin/sh

set -e

VER=1.2.6

wget -O libnftnl-$VER.tar.xz "https://www.netfilter.org/pub/libnftnl/libnftnl-$VER.tar.xz"
tar xf libnftnl-$VER.tar.xz && cd libnftnl-$VER
mkdir build && cd build
../configure --prefix=/usr/local --enable-static --disable-shared
make install
