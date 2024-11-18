#!/bin/sh
LD_PRELOAD=./init_dso.exe ./test.pie a b c 1 2 3
