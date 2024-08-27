#!/usr/bin/env bash
./configure --host=arm-linux-gnueabihf \
    --with-sysroot=/opt/sysroot \ 
    --with-openssl=/opt/sysroot/usr \
    --with-libxml=/opt/sysroot/usr \
    --without-libltdl --disable-crypto-dl \
    --enable-debugging \
    --disable-apps-crypto-dl \
    --disable-static \
    --with-libxml=/opt/sysroot/usr
make