#!/bin/sh

sudo apt install \
  autoconf build-essential libtool    \
  libtool libtool-bin libgcrypt-dev   \
  bison flex libpcap-dev

git clone http://github.com/cuishark/wireshark
cd wireshark
./autogen.sh
./configure  \
  --enable-wireshark=false  \
	--enable-editcap=false    \
	--enable-mergecap=false   \
	--enable-text2cap=false   \
	--enable-sharkd=false     \
	--enable-captype=false    \
	--enable-reordercap=false \
	--enable-dftest=false     \
	--enable-randpkt=false    \
	--enable-rawshark=false   \
	--enable-tfshark=false    \
	--enable-fuzzshark=false  \
	--enable-androiddump=no   \
	--enable-shared=yes       \
	--enable-static=yes       \
	--disable-guides
make && sudo make install

