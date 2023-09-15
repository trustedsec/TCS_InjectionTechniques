#!/usr/bin/env sh
x86_64-w64-mingw32-gcc sc_mapsection.c -w -fpermissive -static  -lws2_32 -lntdll -o ../bin/sc_mapSection.exe
