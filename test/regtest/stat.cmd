#!/bin/sh
trap 'rm -f FILE.txt' EXIT HUP INT TERM
echo XXX > FILE.txt
chmod 0640 FILE.txt
./stat.exe
