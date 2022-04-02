#!/bin/bash


# Запустить в отдельной консоли
#netcat -u -l -p 10000
echo "ftp://admin:1234@91.122.30.115 21"

LD_PRELOAD=./libcall-intercepter.so ftpcopy -u admin -p 1234 ftp://91.122.30.115:21 .