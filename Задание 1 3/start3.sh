#!/bin/bash

xfce4-terminal -e "/bin/bash -c \"netcat -u -l -p 11111\""
xfce4-terminal -e "/bin/bash -c \"netcat -u -l -p 10000\""
LD_PRELOAD=./libcall-intercepter.so netcat -u localhost 11111
