#!/usr/bin/env bash
if [ ! -e configure ]; then
    ./autogen.sh
fi
export CFLAGS="--sysroot=/opt/sysroot"
export LIBXML_LIBS="-L/opt/sysroot/lib -L/opt/sysroot/usr/lib -lxml2 -lz -lm -ldl" 
./configure \
    --host=arm-linux-gnueabihf \
    --prefix="$(pwd)/install" \
    --with-openssl=/opt/sysroot/usr \
    --with-libxml=/opt/sysroot/usr \
    --disable-crypto-dl \
    --disable-apps-crypto-dl \
    --disable-static \
    --enable-debugging
make -j8