# !/bin/sh

./configure \
	CC=arm-linux-gnueabihf-gcc \
	--prefix=/home/linux/usr \
	--host=arm-linux-gnueabihf 

make 

make install

