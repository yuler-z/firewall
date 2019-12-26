#!/bin/sh

make clean
make
gcc user_test.c -lpthread -o user_test
gcc user.c -lpthread -o user