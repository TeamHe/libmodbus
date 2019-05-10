# !/bin/sh

./configure  									\
	--prefix=/home/linux/wkdir/board 			\
	--host=arm-linux-gnueabihf 					\
	CC=arm-linux-gnueabihf-gcc 	

	
make

make install

#echo "make test-glib"
#gcc -g -o0  						\
#	tests/test-glib.c 				\
#	src/.libs/libmodbus.a 			\
#	-o test-glib  					\
#	-lglib-2.0 -lgio-2.0 
