#!/bin/sh

make clean
make
gcc user.c -lpthread -o user